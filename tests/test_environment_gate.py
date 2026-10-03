"""Protected-storage gate tested at provider-response boundaries."""
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from protected_oauth_storage import verify_environment, verify_approval_runs, StorageRefused


class EnvironmentTests(unittest.TestCase):
    def test_native_approval_requires_distinct_actor_and_a_live_negative_guard(self):
        sha = '1' * 40
        common = {'head_sha': sha, 'head_branch': 'codex/qualification', 'event': 'workflow_dispatch',
                  'run_attempt': 1, 'path': '.github/workflows/environment-approval-probe.yml'}
        negative = dict(common, actor={'id': 13070764, 'login': 'dallanlee'}, status='waiting', conclusion=None)
        positive = dict(common, actor={'id': 41898282, 'login': 'github-actions[bot]', 'type': 'Bot'},
                        status='completed', conclusion='success')
        pending = [{'environment': {'id': 23353662059, 'name': 'qualification-source'},
                    'current_user_can_approve': False}]
        approvals = [{'state': 'approved', 'user': {'id': 13070764},
                      'environments': [{'id': 23353662059, 'name': 'qualification-source'}]}]
        verify_approval_runs(negative, positive, pending, approvals, sha)
        changed = copy.deepcopy(positive)
        changed['actor'] = {'id': 13070764, 'login': 'dallanlee'}
        with self.assertRaises(StorageRefused): verify_approval_runs(negative, changed, pending, approvals, sha)
        changed = copy.deepcopy(pending)
        changed[0]['current_user_can_approve'] = True
        with self.assertRaises(StorageRefused): verify_approval_runs(negative, positive, changed, approvals, sha)
        with self.assertRaises(StorageRefused): verify_approval_runs(negative, positive, pending, [], sha)

    def test_protected_environment_requires_the_fixed_human_and_branch(self):
        environment = {'id': 23353662059, 'name': 'qualification-source',
            'can_admins_bypass': False,
            'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': True,
                'reviewers': [{'type': 'User', 'reviewer': {'id': 13070764, 'login': 'dallanlee'}}]},
                {'type': 'branch_policy'}],
            'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
        branches = {'total_count': 1, 'branch_policies': [{'name': 'codex/qualification', 'type': 'branch'}]}
        verify_environment(environment, branches)
        for field, value in (('can_admins_bypass', True), ('id', 1)):
            altered = copy.deepcopy(environment)
            altered[field] = value
            with self.assertRaises(StorageRefused): verify_environment(altered, branches)
        altered = copy.deepcopy(environment)
        altered['protection_rules'][0]['prevent_self_review'] = False
        with self.assertRaises(StorageRefused): verify_environment(altered, branches)
        with self.assertRaises(StorageRefused): verify_environment(environment, {
            'total_count': 1, 'branch_policies': [{'name': '*', 'type': 'branch'}]})


if __name__ == '__main__': unittest.main()
