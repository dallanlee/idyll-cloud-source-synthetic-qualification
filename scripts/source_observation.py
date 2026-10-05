"""Inactive, finite observation of the sole fabricated ClickUp task.

Imports have no provider or credential effects. Source fields never cross the
executor boundary except the positive evidence allowlist returned below.
"""
import hashlib
import json
import re
from source_bridge import EXPECTED_DESCRIPTION, FixedSourceServices, claim_metadata, instant
from protected_oauth_storage import verify_environment

OBSERVATION_CONFIGURED = False
TASK_ID = '86bccact7'
WORKSPACE_ID = '90141728025'
LIST_ID = '901421854627'
SOURCE_URL = 'https://api.clickup.com/api/v2/task/86bccact7'
EXPECTED_DESCRIPTION_SHA256 = 'a8cf682015d6333af14144ce568b043db0f9c7cb28b9b78f0a7005c52e9c55cf'
CONTRACT = 'idyll-cloud-q-v1-observation'
WORKFLOW_PATH = '.github/workflows/source-observation-qualification.yml'
REPOSITORY = 'dallanlee/idyll-cloud-source-synthetic-qualification'
BRANCH_REF = 'refs/heads/codex/qualification'
REPO_URL = FixedSourceServices.REPO_URL
BOT = {'id': 41898282, 'login': 'github-actions[bot]', 'type': 'Bot'}
STOP_CONTRACT_V2 = 'idyll-cloud-q-v2-retained-stop'
LEGACY_STOP_CONTRACT = 'idyll-cloud-q-v1-retained-stop'
DISPATCH_CONTRACT = 'idyll-cloud-q-v1-case-dispatcher'


def validate_manifest(manifest, *, contract=CONTRACT, case=None):
    if (not isinstance(manifest, dict)
            or set(manifest) != {'contract', 'occurrence_id', 'due_at', 'cutoff_at',
                                'source_sha', 'run_id', 'attempt'}
            or manifest.get('contract') != contract or manifest.get('attempt') != 1
            or not claim_metadata({key: manifest[key]
                for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
            or not isinstance(manifest['due_at'], str)
            or not isinstance(manifest['cutoff_at'], str)):
        raise ValueError('Finite authority refused')
    if case not in (None, 'retained-stop', 'observation'):
        raise ValueError('Finite authority refused')
    if contract == STOP_CONTRACT_V2:
        if case not in (None, 'retained-stop'):
            raise ValueError('Finite authority refused')
        max_duration = 600
    elif contract == DISPATCH_CONTRACT:
        if case == 'retained-stop':
            max_duration = 600
        elif case in (None, 'observation'):
            max_duration = 120
        else:
            raise ValueError('Finite authority refused')
    elif contract == LEGACY_STOP_CONTRACT:
        if case not in (None, 'retained-stop'):
            raise ValueError('Finite authority refused')
        max_duration = 120
    elif contract == CONTRACT:
        if case not in (None, 'observation'):
            raise ValueError('Finite authority refused')
        max_duration = 120
    else:
        raise ValueError('Finite authority refused')
    due, cutoff = instant(manifest['due_at']), instant(manifest['cutoff_at'])
    if not 0 < (cutoff - due).total_seconds() <= max_duration:
        raise ValueError('Finite authority refused')
    return due, cutoff


def verify_native_authority(request, manifest, *, workflow=WORKFLOW_PATH):
    def get(path):
        status, value = request('GET', REPO_URL + path)
        if status != 200:
            raise ValueError('Native authority refused')
        return value
    repo = get('')
    if (not isinstance(repo, dict) or type(repo.get('id')) is not int
            or repo['id'] != 1402638368 or repo.get('private') is not False):
        raise ValueError('Native authority refused')
    branch = get('/git/ref/heads/codex/qualification')
    if (branch.get('ref') != BRANCH_REF
            or branch.get('object', {}).get('type') != 'commit'
            or branch['object'].get('sha') != manifest['source_sha']):
        raise ValueError('Native authority refused')
    verify_environment(get('/environments/qualification-source'),
        get('/environments/qualification-source/deployment-branch-policies'))
    run = get('/actions/runs/' + manifest['run_id'])
    if (type(run.get('id')) is not int or str(run['id']) != manifest['run_id']
            or run.get('repository', {}).get('id') != 1402638368
            or run.get('head_sha') != manifest['source_sha']
            or run.get('head_branch') != 'codex/qualification'
            or run.get('event') != 'workflow_dispatch'
            or type(run.get('run_attempt')) is not int or run['run_attempt'] != 1
            or run.get('path') != workflow or run.get('status') != 'in_progress'
            or run.get('conclusion') is not None
            or any(any(run.get(actor, {}).get(k) != v for k, v in BOT.items())
                   for actor in ('actor', 'triggering_actor'))):
        raise ValueError('Native authority refused')
    approvals = get('/actions/runs/' + manifest['run_id'] + '/approvals')
    if (not isinstance(approvals, list) or len(approvals) != 1
            or approvals[0].get('state') != 'approved'
            or approvals[0].get('user', {}).get('id') != 13070764
            or [(env.get('id'), env.get('name')) for env in approvals[0].get('environments', [])]
               != [(23353662059, 'qualification-source')]):
        raise ValueError('Native authority refused')

    return approvals[0]


def empty_receipt(outcome):
    return {'contract': CONTRACT, 'outcome': outcome,
            'source_attempt_count': 0, 'source_action_count': 0,
            'github_attempt_count': 0, 'github_action_count': 0,
            'automatic_retry_allowed': False}


def verify_claim_attribution(request, claim):
    metadata = {key: claim[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')}
    status, ref = request('GET', REPO_URL + '/git/ref/' + claim['ref'][5:])
    if (status != 200 or ref.get('ref') != claim['ref']
            or ref.get('object', {}).get('type') != 'tag'
            or ref['object'].get('sha') != claim['tag_sha']):
        raise ValueError('Durable claim refused')
    status, annotation = request('GET', REPO_URL + '/git/tags/' + claim['tag_sha'])
    if (status != 200 or annotation.get('sha') != claim['tag_sha']
            or annotation.get('tag') != claim['ref'][10:]
            or annotation.get('message') != json.dumps(metadata, sort_keys=True, separators=(',', ':'))
            or annotation.get('object', {}).get('type') != 'commit'
            or annotation['object'].get('sha') != metadata['source_sha']):
        raise ValueError('Durable claim refused')


def admit_environment(env, checkout_sha, *, now, configured=OBSERVATION_CONFIGURED,
                      prefix='QUAL_OBSERVATION_', contract=CONTRACT, case=None):
    """Protected configuration plus native Actions context; never CLI auth."""
    if configured is not True:
        return None
    try:
        sha, run = env[prefix + 'ACCEPTED_CODE_SHA'], env['GITHUB_RUN_ID']
        occurrence = env[prefix + 'APPROVED_OCCURRENCE_ID']
        if (env.get('GITHUB_ACTIONS') != 'true'
                or env.get('GITHUB_REPOSITORY') != REPOSITORY
                or env.get('GITHUB_REPOSITORY_ID') != '1402638368'
                or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                or env.get('GITHUB_REF') != BRANCH_REF
                or env.get('GITHUB_RUN_ATTEMPT') != '1'
                or env.get('GITHUB_SHA') != sha or checkout_sha != sha
                or env.get(prefix + 'APPROVED_RUN_ID') != run
                or env.get(prefix + 'OCCURRENCE_ID') != occurrence
                or env.get(prefix + 'APPROVED') != contract):
            return None
        if case is None:
            if prefix == 'QUAL_DISPATCH_':
                case = env.get('QUAL_DISPATCH_CASE')
            elif prefix == 'QUAL_STOP_' or contract == STOP_CONTRACT_V2:
                case = 'retained-stop'
            elif contract == CONTRACT:
                case = 'observation'
        manifest = {'contract': contract, 'occurrence_id': occurrence,
            'due_at': env[prefix + 'DUE_AT'], 'cutoff_at': env[prefix + 'CUTOFF_AT'],
            'source_sha': sha, 'run_id': run, 'attempt': 1}
        due, cutoff = validate_manifest(manifest, contract=contract, case=case)
        if now.tzinfo is None or not due <= now < cutoff:
            return None
        return manifest
    except Exception:
        return None


def observe(manifest, transport, *, now, progress=lambda value: None):
    """One reviewed boundary execution; live callers must use the supervisor."""
    result = empty_receipt('INVALID_MANIFEST')
    try:
        due, cutoff = validate_manifest(manifest)
        result.update({key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
        def gate():
            current = now()
            if current.tzinfo is None or not due <= current < cutoff:
                raise TimeoutError('Finite window expired')
        def request(method, url, body=None, *, deadline=None):
            gate()
            source = url == SOURCE_URL
            prefix = 'source' if source else 'github'
            if source and (method != 'GET' or body is not None or result['source_attempt_count']):
                raise ValueError('Source operation refused')
            if not source and result['github_attempt_count'] >= 20:
                raise ValueError('Control operation cap exceeded')
            result[prefix + '_attempt_count'] += 1
            result[prefix + '_action_count'] = None
            progress({key: result[key] for key in
                ('source_attempt_count', 'source_action_count', 'github_attempt_count', 'github_action_count')})
            value = transport(method, url, body, deadline=cutoff)
            result[prefix + '_action_count'] = result[prefix + '_attempt_count']
            gate()
            if url == REPO_URL + '/git/ref/heads/codex/qualification' and value[0] == 200:
                branch = value[1]
                if (branch.get('ref') != BRANCH_REF or branch.get('object', {}).get('type') != 'commit'
                        or branch['object'].get('sha') != manifest['source_sha']):
                    raise ValueError('Accepted branch changed')
            return value
        gate()
        result['outcome'] = 'AUTHORITY_REFUSED'
        verify_native_authority(request, manifest)
        services = FixedSourceServices(request)
        result['outcome'] = 'UNKNOWN_CONTROL_RESULT'
        if services.revoked() is not False:
            return dict(result, outcome='REVOKED')
        gate()  # retained stop observed before the immutable claim
        claimed = services.claim(manifest)
        result['claim'] = services.claim_receipt
        if claimed is not True:
            return dict(result, outcome='ALREADY_CLAIMED')
        verify_claim_attribution(request, services.claim_receipt)
        if services.revoked() is not False:
            return dict(result, outcome='REVOKED')
        gate()  # retained stop observed again before the only source call
        started = now()
        status, task = request('GET', SOURCE_URL)
        completed = now()
        if not due <= started <= completed < cutoff:
            raise TimeoutError('Finite window expired')
        result['outcome'] = 'SOURCE_MISMATCH'
        receipt = validate_task(status, task)
        result['receipt'] = dict(receipt, started_at=started.isoformat(), completed_at=completed.isoformat())
        result['outcome'] = 'SOURCE_OBSERVED'
    except TimeoutError:
        result['outcome'] = 'DEADLINE_EXPIRED'
    except Exception:
        if result['source_attempt_count'] and result['source_action_count'] is None:
            result['outcome'] = 'UNKNOWN_SOURCE_RESULT'
        elif result['github_action_count'] is None:
            result['outcome'] = 'UNKNOWN_CONTROL_RESULT'
        # Keep only a fixed outcome, never a provider error or rejected raw field.
    return result


def validate_task(status, task):
    """Validate the entire binding before returning any source-derived field."""
    if type(status) is not int or status != 200 or not isinstance(task, dict):
        raise ValueError('Source observation refused')
    workspace = task.get('team_id')
    if type(workspace) is int:
        workspace = str(workspace)
    revision = task.get('date_updated')
    listing = task.get('list')
    if (task.get('id') != TASK_ID or workspace != WORKSPACE_ID
            or not isinstance(listing, dict) or listing.get('id') != LIST_ID
            or not isinstance(revision, str)
            or re.fullmatch(r'(?:0|[1-9][0-9]{0,19})', revision) is None
            or task.get('description') != EXPECTED_DESCRIPTION):
        raise ValueError('Source observation refused')
    digest = hashlib.sha256(task['description'].encode('utf-8')).hexdigest()
    if digest != EXPECTED_DESCRIPTION_SHA256:
        raise ValueError('Source observation refused')
    return {'task_id': TASK_ID, 'workspace_id': WORKSPACE_ID, 'list_id': LIST_ID,
            'date_updated': revision, 'description_equal': True,
            'description_sha256': digest}


class FixedHTTPTransport:
    """No redirects, proxy, retry, CLI credential lookup or configurable source.

    The containing executor MUST be supervised; socket timeouts alone do not
    bound DNS. Tokens exist only in memory and the bounded stdin handoff.
    """
    def __init__(self, github_token, clickup_token=None, *, stop_probe=False, dispatch_case=None):
        if (stop_probe or dispatch_case is not None) and clickup_token is not None:
            raise ValueError('Source-free mode refuses source credentials')
        if stop_probe and dispatch_case is not None:
            raise ValueError('One finite mode required')
        for token in (github_token,) + (() if clickup_token is None else (clickup_token,)):
            if (not isinstance(token, str) or not token or len(token) > 4096
                    or any(c.isspace() for c in token)):
                raise ValueError('Credential refused')
        if clickup_token is not None and clickup_token.startswith('pk_'):
            raise ValueError('OAuth credential required')
        self.github_token, self.clickup_token = github_token, clickup_token
        self.stop_probe = stop_probe
        if dispatch_case not in (None, 'retained-stop', 'observation'):
            raise ValueError('Dispatch target refused')
        self.dispatch_case = dispatch_case
        self.source_consumed = False
        self.patch_consumed = self.delete_consumed = self.dispatch_consumed = False

    def allowed(self, method, url, body):
        if self.dispatch_case is not None:
            from finite_case_dispatcher import TARGETS
            if method == 'POST':
                try:
                    return (url == REPO_URL + '/actions/workflows/' + TARGETS[self.dispatch_case] + '/dispatches'
                        and isinstance(body, dict) and set(body) == {'ref', 'inputs'}
                        and body['ref'] == 'codex/qualification' and isinstance(body['inputs'], dict)
                        and set(body['inputs']) == {'occurrence_id'}
                        and re.fullmatch(r'idyll-cloud-q-[a-z0-9-]{1,100}', body['inputs']['occurrence_id']) is not None)
                except Exception:
                    return False
            return method == 'GET' and body is None and (url in (REPO_URL,
                REPO_URL + '/git/ref/heads/codex/qualification') or re.fullmatch(
                    re.escape(REPO_URL) + r'/actions/runs/[0-9]{1,30}', url) is not None)
        if url == SOURCE_URL:
            return method == 'GET' and body is None and self.clickup_token is not None and not self.stop_probe
        if method == 'GET' and body is None:
            fixed = ('', '/git/ref/heads/codex/qualification', '/git/ref/tags/idyll-cloud-q-stop-v1',
                     '/environments/qualification-source',
                     '/environments/qualification-source/deployment-branch-policies')
            dynamic = (r'/actions/runs/[0-9]{1,30}(?:/approvals)?',
                       r'/git/ref/tags/idyll-cloud-q-occurrence/idyll-cloud-q-[a-z0-9-]{1,100}',
                       r'/git/tags/[0-9a-f]{40}')
            if self.stop_probe:
                dynamic += (r'/git/commits/[0-9a-f]{40}', r'/rulesets/(?:24406997|24406998)')
            return url in tuple(REPO_URL + path for path in fixed) or any(
                re.fullmatch(re.escape(REPO_URL) + path, url) for path in dynamic)
        if method == 'POST' and isinstance(body, dict):
            if url == REPO_URL + '/git/refs':
                return (set(body) == {'ref', 'sha'} and isinstance(body['ref'], str)
                    and re.fullmatch(r'refs/tags/idyll-cloud-q-occurrence/idyll-cloud-q-[a-z0-9-]{1,100}', body['ref'])
                    and isinstance(body['sha'], str) and re.fullmatch(r'[0-9a-f]{40}', body['sha']))
            if url == REPO_URL + '/git/tags':
                try:
                    metadata = json.loads(body['message'])
                    return (set(body) == {'tag', 'message', 'object', 'type'} and claim_metadata(metadata)
                        and body['message'] == json.dumps(metadata, sort_keys=True, separators=(',', ':'))
                        and body['tag'] == 'idyll-cloud-q-occurrence/' + metadata['occurrence_id']
                        and body['object'] == metadata['source_sha'] and body['type'] == 'commit')
                except Exception:
                    return False
        if self.stop_probe and url == REPO_URL + '/git/refs/tags/idyll-cloud-q-stop-v1':
            if method == 'DELETE' and body is None:
                return True
            if method == 'PATCH' and isinstance(body, dict):
                return body == {'sha': '260d783935a0f47eed9222ec66f48e7502cb30b7', 'force': True}
        return False

    def __call__(self, method, url, body=None, *, deadline):
        from datetime import datetime, timezone
        from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
        from urllib.error import HTTPError
        if not self.allowed(method, url, body):
            raise ValueError('Operation refused')
        if method in ('PATCH', 'DELETE') or self.dispatch_case is not None and method == 'POST':
            field = 'patch_consumed' if method == 'PATCH' else 'delete_consumed' if method == 'DELETE' else 'dispatch_consumed'
            if getattr(self, field):
                raise ValueError('Finite operation consumed')
            setattr(self, field, True)
        source = url == SOURCE_URL
        if source:
            if self.source_consumed:
                raise ValueError('Source operation already consumed')
            self.source_consumed = True  # also consumes a lost/unknown reply
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise TimeoutError('Finite deadline expired')
        token = self.clickup_token if source else self.github_token
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
                   'User-Agent': 'idyll-cloud-q-observation'}
        if not source:
            headers.update({'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10'})
        data = None if body is None else json.dumps(body, separators=(',', ':')).encode('utf-8')
        if data is not None:
            headers['Content-Type'] = 'application/json'
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        try:
            opener = build_opener(ProxyHandler({}), NoRedirect())
            try:
                response = opener.open(Request(url, data=data, headers=headers, method=method),
                                       timeout=min(8, remaining))
            except HTTPError as error:
                response = error
            with response:
                status, raw = response.status, response.read(262145)
            if len(raw) > 262144 or 300 <= status < 400:
                raise ValueError('Unusable response')
            if datetime.now(timezone.utc) >= deadline:
                raise TimeoutError('Finite deadline expired')
            value = json.loads(raw) if raw else {}
            if not isinstance(value, (dict, list)):
                raise ValueError('Unusable response')
            return status, value
        except Exception:
            raise RuntimeError('Unknown provider result') from None
