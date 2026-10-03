"""Fixed GitHub environment storage; credentials enter gh only through stdin.

Provider-native approval evidence is required before exchange and again before
storage. A code-check success or a local approval flag cannot open this gate.
"""
import json
import re
import subprocess
from pathlib import Path
from connect_clickup_oauth import ConnectionRefused

REPO = 'dallanlee/idyll-cloud-source-synthetic-qualification'
ENVIRONMENT = 'qualification-source'
ENVIRONMENT_ID = 23353662059
REVIEWER_ID = 13070764
BRANCH = 'codex/qualification'
SECRET_NAME = 'QUAL_CLICKUP_OAUTH_TOKEN'
PROBE_PATH = '.github/workflows/environment-approval-probe.yml'


class StorageRefused(ConnectionRefused):
    pass


def verify_environment(environment, branches):
    rules = environment.get('protection_rules', [])
    reviewers = [rule for rule in rules if rule.get('type') == 'required_reviewers']
    if (environment.get('id') != ENVIRONMENT_ID
            or environment.get('name') != ENVIRONMENT
            or environment.get('can_admins_bypass') is not False
            or len(reviewers) != 1 or reviewers[0].get('prevent_self_review') is not True
            or [(item.get('type'), item.get('reviewer', {}).get('id'))
                for item in reviewers[0].get('reviewers', [])] != [('User', REVIEWER_ID)]
            or environment.get('deployment_branch_policy') != {
                'protected_branches': False, 'custom_branch_policies': True}
            or branches.get('total_count') != 1
            or [(item.get('name'), item.get('type')) for item in branches.get('branch_policies', [])]
                != [(BRANCH, 'branch')]):
        raise StorageRefused('Protected environment identity or controls changed')


def verify_approval_runs(negative, positive, pending, approvals, sha):
    for run in (negative, positive):
        if (run.get('head_sha') != sha or run.get('head_branch') != BRANCH
                or run.get('event') != 'workflow_dispatch' or run.get('run_attempt') != 1
                or run.get('path') != PROBE_PATH):
            raise StorageRefused('Approval run is not the exact accepted probe')
    if (negative.get('actor', {}).get('id') != REVIEWER_ID
            or negative.get('status') != 'waiting' or negative.get('conclusion') is not None
            or positive.get('actor', {}).get('id') != 41898282
            or positive.get('actor', {}).get('login') != 'github-actions[bot]'
            or positive.get('actor', {}).get('type') != 'Bot'
            or positive.get('status') != 'completed' or positive.get('conclusion') != 'success'
            or len(pending) != 1
            or pending[0].get('environment', {}).get('id') != ENVIRONMENT_ID
            or pending[0].get('current_user_can_approve') is not False):
        raise StorageRefused('Distinct dispatcher or self-review refusal not verified')
    if (len(approvals) != 1 or approvals[0].get('state') != 'approved'
            or approvals[0].get('user', {}).get('id') != REVIEWER_ID
            or [(item.get('id'), item.get('name')) for item in approvals[0].get('environments', [])]
                != [(ENVIRONMENT_ID, ENVIRONMENT)]):
        raise StorageRefused('Native human approval receipt not verified')


class GitHubStorage:
    def __init__(self, sha, negative_run, positive_run, *, root=None):
        if not re.fullmatch(r'[0-9a-f]{40}', sha):
            raise StorageRefused('Invalid accepted code SHA')
        if any(not re.fullmatch(r'[0-9]{1,20}', str(run)) for run in (negative_run, positive_run)):
            raise StorageRefused('Invalid approval run identity')
        if str(negative_run) == str(positive_run):
            raise StorageRefused('Approval runs must be distinct')
        self.sha, self.negative_run, self.positive_run = sha, str(negative_run), str(positive_run)
        self.root = Path(root) if root else Path(__file__).resolve().parents[1]
        self.stored = False

    def command(self, argv, *, input=None):
        try:
            result = subprocess.run(argv, cwd=self.root, input=input, text=True,
                                    capture_output=True, timeout=20, check=False)
            if result.returncode != 0:
                raise StorageRefused('GitHub operation failed or outcome uncertain; inspect before retry')
            return result.stdout
        except StorageRefused:
            raise
        except Exception:
            raise StorageRefused('GitHub operation failed or outcome uncertain; inspect before retry') from None

    def api(self, path):
        try:
            return json.loads(self.command(['gh', 'api', 'repos/' + REPO + '/' + path]))
        except StorageRefused:
            raise
        except Exception:
            raise StorageRefused('GitHub response refused') from None

    def ready(self):
        if self.stored:
            raise StorageRefused('Source credential already stored; reconcile before another attempt')
        try:
            principal = json.loads(self.command(['gh', 'api', 'user']))
        except Exception:
            raise StorageRefused('Owning GitHub principal not verified') from None
        if principal.get('id') != REVIEWER_ID:
            raise StorageRefused('Owning GitHub principal not verified')
        if (self.command(['git', 'rev-parse', 'HEAD']).strip() != self.sha
                or self.command(['git', 'status', '--porcelain', '--untracked-files=all']).strip()
                or self.api('branches/codex%2Fqualification').get('commit', {}).get('sha') != self.sha):
            raise StorageRefused('Accepted clean local and remote code binding not verified')
        environment_path = 'environments/' + ENVIRONMENT
        verify_environment(self.api(environment_path), self.api(environment_path + '/deployment-branch-policies'))
        inventory = self.api(environment_path + '/secrets')
        if inventory.get('total_count') != 0 or inventory.get('secrets') != []:
            raise StorageRefused('Protected environment must still contain zero source credentials')
        if self.api('actions/workflows/environment-approval-probe.yml').get('state') != 'disabled_manually':
            raise StorageRefused('Approval probe must be retired before credential entry')
        if self.api('actions/workflows/environment-probe-dispatcher.yml').get('state') != 'disabled_manually':
            raise StorageRefused('Temporary dispatcher must be retired before credential entry')
        negative = 'actions/runs/' + self.negative_run
        positive = 'actions/runs/' + self.positive_run
        verify_approval_runs(self.api(negative), self.api(positive),
                             self.api(negative + '/pending_deployments'), self.api(positive + '/approvals'), self.sha)

    def store(self, token):
        # The caller has verified the sole Workspace and refreshed ready().
        self.stored = True  # Consume before upload: lost reply cannot authorize retry.
        self.command(['gh', 'secret', 'set', SECRET_NAME, '--env', ENVIRONMENT, '--repo', REPO], input=token)
        inventory = self.api('environments/' + ENVIRONMENT + '/secrets')
        names = [item.get('name') for item in inventory.get('secrets', [])]
        if inventory.get('total_count') != 1 or names != [SECRET_NAME]:
            raise StorageRefused('Credential upload outcome uncertain; inspect protected metadata')
