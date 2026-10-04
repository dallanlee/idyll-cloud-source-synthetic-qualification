"""Approved observer seams; synthetic boundary models, no provider access."""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import source_observation as observer
from test_source_bridge import ProviderAPI

DESCRIPTION = ('Synthetic history fixture only. Request idyll-cloud-q-synthetic-fixture-01; '
               'contract idyll-cloud-q-v1; revision synthetic-only-r1.')
TASK = {'id': '86bccact7', 'team_id': 90141728025,
        'list': {'id': '901421854627'}, 'date_updated': '1791071022000',
        'description': DESCRIPTION, 'private_extra': 'never-return-this'}

SHA = '1' * 40
MANIFEST = {'contract': 'idyll-cloud-q-v1-observation',
    'occurrence_id': 'idyll-cloud-q-observation-offline-01',
    'due_at': '2026-10-04T00:00:00Z', 'cutoff_at': '2026-10-04T00:01:30Z',
    'source_sha': SHA, 'run_id': '123', 'attempt': 1}
NOW = datetime(2026, 10, 4, 0, 0, 10, tzinfo=timezone.utc)


class ObservationAPI(ProviderAPI):
    def __init__(self):
        super().__init__()
        self.task, self.status = dict(TASK), 200
        self.approvals = [{'state': 'approved', 'user': {'id': 13070764},
            'environments': [{'id': 23353662059, 'name': 'qualification-source'}]}]
        self.run = {'id': 123, 'head_sha': SHA, 'head_branch': 'codex/qualification',
            'event': 'workflow_dispatch', 'run_attempt': 1,
            'path': '.github/workflows/source-observation-qualification.yml',
            'repository': {'id': 1402638368}, 'status': 'in_progress', 'conclusion': None,
            'actor': {'id': 41898282, 'login': 'github-actions[bot]', 'type': 'Bot'},
            'triggering_actor': {'id': 41898282, 'login': 'github-actions[bot]', 'type': 'Bot'}}
        self.environment = {'id': 23353662059, 'name': 'qualification-source',
            'can_admins_bypass': False,
            'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': True,
                'reviewers': [{'type': 'User', 'reviewer': {'id': 13070764}}]}],
            'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
        self.calls = []

    def __call__(self, method, url, body=None, *, deadline=None):
        self.calls.append((method, url))
        if url == observer.SOURCE_URL:
            self.source_reads += 1
            return self.status, self.task
        if url.endswith('/environments/qualification-source'):
            return 200, self.environment
        if url.endswith('/deployment-branch-policies'):
            return 200, {'total_count': 1, 'branch_policies': [{'name': 'codex/qualification', 'type': 'branch'}]}
        if url.endswith('/actions/runs/123/approvals'):
            return 200, self.approvals
        if url.endswith('/actions/runs/123'):
            return 200, self.run
        return super().__call__(method, url, body, deadline=deadline)


class ObservationTests(unittest.TestCase):
    def test_helper_returns_only_after_native_approval_authentication(self):
        api = ObservationAPI()
        api.approvals[0]['comment'] = 'not a witness: source semantics stay unchanged'
        self.assertEqual(observer.verify_native_authority(api, MANIFEST), api.approvals[0])
        self.assertEqual(len(api.calls), 6)
        api.approvals[0]['user']['id'] = 1
        with self.assertRaises(ValueError):
            observer.verify_native_authority(api, MANIFEST)

    def test_capture_actual_raw_revision_with_only_the_allowed_evidence(self):
        evidence = observer.validate_task(200, TASK)
        self.assertEqual(evidence, {
            'task_id': '86bccact7', 'workspace_id': '90141728025',
            'list_id': '901421854627', 'date_updated': '1791071022000',
            'description_equal': True,
            'description_sha256': 'a8cf682015d6333af14144ce568b043db0f9c7cb28b9b78f0a7005c52e9c55cf'})

    def test_native_approved_fixed_read_claims_once_and_blocks_replay(self):
        api = ObservationAPI()
        first = observer.observe(MANIFEST, api, now=lambda: NOW)
        replay = observer.observe(MANIFEST, api, now=lambda: NOW)
        self.assertEqual((first['outcome'], replay['outcome'], api.source_reads),
                         ('SOURCE_OBSERVED', 'ALREADY_CLAIMED', 1))
        self.assertEqual(first['receipt']['date_updated'], '1791071022000')
        self.assertEqual(first['claim']['run_id'], '123')
        self.assertEqual(first['source_attempt_count'], 1)
        self.assertEqual(first['github_attempt_count'], 14)
        self.assertNotIn('never-return', str(first))

    def test_wrong_content_status_or_identity_never_emits_raw_source(self):
        cases = [dict(TASK, id='other'), dict(TASK, team_id=True),
                 dict(TASK, list=None), dict(TASK, description='private-sensitive-text'),
                 dict(TASK, date_updated=1791071022000), dict(TASK, date_updated=' 1791071022000'),
                 dict(TASK, date_updated='1e12'), dict(TASK, date_updated='01791071022000'),
                 dict(TASK, date_updated=True), []]
        for task in cases:
            with self.subTest(task=task):
                api = ObservationAPI()
                api.task = task
                result = observer.observe(MANIFEST, api, now=lambda: NOW)
                self.assertEqual(result['outcome'], 'SOURCE_MISMATCH')
                self.assertNotIn('receipt', result)
                self.assertNotIn('private-sensitive-text', str(result))
        api = ObservationAPI()
        api.status = 403
        self.assertEqual(observer.observe(MANIFEST, api, now=lambda: NOW)['outcome'], 'SOURCE_MISMATCH')

    def test_missing_or_mismatched_native_approval_blocks_claim_and_source(self):
        for field, value in [('approvals', []), ('run', dict(ObservationAPI().run, head_sha='2' * 40)),
                             ('run', dict(ObservationAPI().run, actor={'id': 13070764})),
                             ('run', dict(ObservationAPI().run, run_attempt=2))]:
            with self.subTest(field=field, value=value):
                api = ObservationAPI()
                setattr(api, field, value)
                result = observer.observe(MANIFEST, api, now=lambda: NOW)
                self.assertEqual((result['outcome'], api.source_reads, len(api.tags)),
                                 ('AUTHORITY_REFUSED', 0, 0))

    def test_retained_stop_and_unknown_claim_do_not_allow_source_or_replay(self):
        api = ObservationAPI()
        api.refs['refs/tags/idyll-cloud-q-stop-v1'] = {'ref': 'refs/tags/idyll-cloud-q-stop-v1'}
        result = observer.observe(MANIFEST, api, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.source_reads, len(api.tags)), ('REVOKED', 0, 0))
        api = ObservationAPI()
        def lost_reply(method, url, body=None, *, deadline=None):
            response = api(method, url, body, deadline=deadline)
            if method == 'POST' and url.endswith('/git/refs'):
                raise OSError('private-error-token')
            return response
        first = observer.observe(MANIFEST, lost_reply, now=lambda: NOW)
        second = observer.observe(MANIFEST, api, now=lambda: NOW)
        self.assertEqual((first['outcome'], second['outcome'], api.source_reads),
                         ('UNKNOWN_CONTROL_RESULT', 'ALREADY_CLAIMED', 0))

    def test_claim_echo_without_durable_attributed_readback_cannot_open_source(self):
        api = ObservationAPI()
        def wrong_readback(method, url, body=None, *, deadline=None):
            status, value = api(method, url, body, deadline=deadline)
            if method == 'GET' and '/git/tags/' in url:
                value = dict(value, message='{}')
            return status, value
        result = observer.observe(MANIFEST, wrong_readback, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.source_reads), ('UNKNOWN_CONTROL_RESULT', 0))

    def test_expired_boundary_blocks_before_any_control_or_source(self):
        api = ObservationAPI()
        result = observer.observe(MANIFEST, api, now=lambda: datetime(2026, 10, 4, 0, 1, 30, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], api.calls), ('DEADLINE_EXPIRED', []))

    def test_stop_between_claim_and_read_blocks_access_and_late_read_cannot_be_success(self):
        api = ObservationAPI()
        def stopped(method, url, body=None, *, deadline=None):
            response = api(method, url, body, deadline=deadline)
            if method == 'POST' and url.endswith('/git/refs'):
                api.refs['refs/tags/idyll-cloud-q-stop-v1'] = {'ref': 'refs/tags/idyll-cloud-q-stop-v1'}
            return response
        self.assertEqual(observer.observe(MANIFEST, stopped, now=lambda: NOW)['outcome'], 'REVOKED')
        self.assertEqual(api.source_reads, 0)
        api = ObservationAPI()
        current = [NOW]
        def late(method, url, body=None, *, deadline=None):
            response = api(method, url, body, deadline=deadline)
            if url == observer.SOURCE_URL:
                current[0] = datetime(2026, 10, 4, 0, 1, 30, tzinfo=timezone.utc)
            return response
        result = observer.observe(MANIFEST, late, now=lambda: current[0])
        self.assertEqual((result['outcome'], result['source_action_count']), ('DEADLINE_EXPIRED', 1))
        self.assertNotIn('receipt', result)

    def test_accepted_branch_moving_after_native_gate_blocks_source(self):
        api = ObservationAPI()
        def changed(method, url, body=None, *, deadline=None):
            result = api(method, url, body, deadline=deadline)
            if url.endswith('/approvals'):
                api.refs[observer.BRANCH_REF]['object']['sha'] = '2' * 40
            return result
        result = observer.observe(MANIFEST, changed, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.source_reads), ('UNKNOWN_CONTROL_RESULT', 0))

    def test_entry_authority_is_protected_actions_only_and_inactive_by_default(self):
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': observer.REPOSITORY,
            'GITHUB_REPOSITORY_ID': '1402638368', 'GITHUB_REF': observer.BRANCH_REF,
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_SHA': SHA,
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
            'QUAL_OBSERVATION_ACCEPTED_CODE_SHA': SHA,
            'QUAL_OBSERVATION_APPROVED_RUN_ID': '123',
            'QUAL_OBSERVATION_OCCURRENCE_ID': MANIFEST['occurrence_id'],
            'QUAL_OBSERVATION_APPROVED_OCCURRENCE_ID': MANIFEST['occurrence_id'],
            'QUAL_OBSERVATION_DUE_AT': MANIFEST['due_at'],
            'QUAL_OBSERVATION_CUTOFF_AT': MANIFEST['cutoff_at'],
            'QUAL_OBSERVATION_APPROVED': observer.CONTRACT}
        self.assertIsNone(observer.admit_environment(env, SHA, now=NOW))
        admitted = observer.admit_environment(env, SHA, now=NOW, configured=True)
        self.assertEqual(admitted, MANIFEST)
        for key in env:
            altered = dict(env)
            del altered[key]
            self.assertIsNone(observer.admit_environment(altered, SHA, now=NOW, configured=True), key)
        self.assertIsNone(observer.admit_environment(env, '2' * 40, now=NOW, configured=True))


if __name__ == '__main__':
    unittest.main()
