"""Fresh finite machine dispatch boundary; ephemeral Actions token only."""
import sys
import json
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import finite_case_dispatcher as dispatcher
from test_source_observation import ObservationAPI, MANIFEST, NOW
from source_observation import FixedHTTPTransport
from test_source_bridge import HTTPReply


class DispatchAPI(ObservationAPI):
    def __init__(self, *, lost=False):
        super().__init__()
        self.run['path'] = '.github/workflows/qualification-case-dispatcher.yml'
        self.run['actor'] = self.run['triggering_actor'] = {'id': 13070764, 'login': 'dallanlee', 'type': 'User'}
        self.run['run_number'] = 1
        self.dispatches, self.lost = 0, lost
    def __call__(self, method, url, body=None, *, deadline=None):
        if method == 'POST':
            self.dispatches += 1
            self.asserted_target = url
            if self.lost:
                raise OSError('sensitive-provider-error')
            return 200, {'workflow_run_id': 987,
                'run_url': 'https://api.github.com/repos/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/987',
                'html_url': 'https://github.com/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/987'}
        return super().__call__(method, url, body, deadline=deadline)


class DispatchTests(unittest.TestCase):
    def test_real_transport_pins_the_documented_contract_and_emits_only_dispatch_attribution(self):
        api = DispatchAPI()
        api.run['run_number'] = 2
        versions = []
        class HTTPSProvider:
            def open(self, request, *, timeout):
                versions.append(dict(request.header_items())['X-github-api-version'])
                body = json.loads(request.data) if request.data else None
                status, value = api(request.get_method(), request.full_url, body)
                return HTTPReply(status, json.dumps(value).encode())
        current = datetime.now(timezone.utc)
        manifest = dict(MANIFEST, contract=dispatcher.CONTRACT,
            due_at=(current - timedelta(seconds=1)).isoformat(),
            cutoff_at=(current + timedelta(seconds=30)).isoformat())
        with patch('urllib.request.build_opener', return_value=HTTPSProvider()):
            result = dispatcher.dispatch_case(manifest,
                FixedHTTPTransport('fake-github', dispatch_case='retained-stop'),
                case='retained-stop', run_number=2, now=lambda: datetime.now(timezone.utc))
        self.assertEqual((result['outcome'], result['dispatch_status'], result['target_run_id'], api.dispatches),
                         ('DISPATCH_CONFIRMED', 200, '987', 1))
        self.assertEqual(versions, ['2026-03-10'] * 4)
        self.assertNotIn('run_url', result)
        self.assertNotIn('html_url', result)

    def test_pinned20260310_run_details_confirm_exactly_one_dispatch(self):
        api = DispatchAPI()
        def documented(method, url, body=None, *, deadline=None):
            status, value = api(method, url, body, deadline=deadline)
            if method == 'POST':
                return 200, {'workflow_run_id': 987,
                    'run_url': 'https://api.github.com/repos/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/987',
                    'html_url': 'https://github.com/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/987'}
            return status, value
        result = dispatcher.dispatch_case(dict(MANIFEST, contract=dispatcher.CONTRACT), documented,
            case='retained-stop', run_number=1, now=lambda: NOW)
        self.assertEqual((result['outcome'], result['dispatch_attempt_count'], api.dispatches,
                          result.get('dispatch_status'), result.get('target_run_id')),
                         ('DISPATCH_CONFIRMED', 1, 1, 200, '987'))
        self.assertEqual((result['github_attempt_count'], result['github_action_count'], result['source_attempt_count']),
                         (4, 4, 0))

    def test_legacy_or_malformed_dispatch_receipts_never_confirm_or_repeat(self):
        valid = {'workflow_run_id': 987,
            'run_url': 'https://api.github.com/repos/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/987',
            'html_url': 'https://github.com/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/987'}
        cases = [(204, {}), (202, valid), (422, {'message': 'private-sentinel'}),
                 (200, {}), (200, []), (200, dict(valid, workflow_run_id=True)),
                 (200, dict(valid, workflow_run_id='987')), (200, dict(valid, workflow_run_id=0)),
                 (200, dict(valid, workflow_run_id=123)),
                 (200, {'workflow_run_id': 9223372036854775808,
                    'run_url': 'https://api.github.com/repos/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/9223372036854775808',
                    'html_url': 'https://github.com/dallanlee/idyll-cloud-source-synthetic-qualification/actions/runs/9223372036854775808'}),
                 (200, dict(valid, run_url='https://example.invalid/private-sentinel')),
                 (200, dict(valid, html_url=valid['html_url'] + '?private-sentinel'))]
        for status, details in cases:
            with self.subTest(status=status, details=details):
                api = DispatchAPI()
                api.run['run_number'] = 2
                def response(method, url, body=None, *, deadline=None):
                    original = api(method, url, body, deadline=deadline)
                    return (status, details) if method == 'POST' else original
                result = dispatcher.dispatch_case(dict(MANIFEST, contract=dispatcher.CONTRACT), response,
                    case='retained-stop', run_number=2, now=lambda: NOW)
                self.assertEqual((result['outcome'], api.dispatches, result.get('dispatch_status')),
                                 ('UNKNOWN_DISPATCH_RESULT', 1, status))
                self.assertNotIn('target_run_id', result)
                self.assertNotIn('private-sentinel', str(result))

    def test_fresh_owner_dispatcher_can_start_only_the_compiled_finite_case_once(self):
        api = DispatchAPI()
        result = dispatcher.dispatch_case(dict(MANIFEST, contract=dispatcher.CONTRACT), api,
            case='retained-stop', run_number=1, now=lambda: NOW)
        self.assertEqual((result['outcome'], result['dispatch_attempt_count'], api.dispatches),
                         ('DISPATCH_CONFIRMED', 1, 1))
        self.assertTrue(api.asserted_target.endswith('/actions/workflows/retained-stop-qualification.yml/dispatches'))
        self.assertEqual(result['source_attempt_count'], 0)

    def test_lost_dispatch_response_is_consumed_without_retry_and_wrong_native_actor_blocks(self):
        api = DispatchAPI(lost=True)
        result = dispatcher.dispatch_case(dict(MANIFEST, contract=dispatcher.CONTRACT), api,
            case='retained-stop', run_number=1, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.dispatches), ('UNKNOWN_DISPATCH_RESULT', 1))
        self.assertNotIn('sensitive-provider-error', str(result))
        api = DispatchAPI()
        api.run['actor'] = {'id': 41898282}
        result = dispatcher.dispatch_case(dict(MANIFEST, contract=dispatcher.CONTRACT), api,
            case='retained-stop', run_number=1, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.dispatches), ('AUTHORITY_REFUSED', 0))

    def test_fresh_run_number_authority_is_required_even_for_a_machine_dispatch(self):
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'dallanlee/idyll-cloud-source-synthetic-qualification',
            'GITHUB_REPOSITORY_ID': '1402638368', 'GITHUB_REF': 'refs/heads/codex/qualification',
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_SHA': MANIFEST['source_sha'],
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '1',
            'QUAL_DISPATCH_ACCEPTED_CODE_SHA': MANIFEST['source_sha'],
            'QUAL_DISPATCH_APPROVED_RUN_NUMBER': '1',
            'QUAL_DISPATCH_OCCURRENCE_ID': MANIFEST['occurrence_id'],
            'QUAL_DISPATCH_APPROVED_OCCURRENCE_ID': MANIFEST['occurrence_id'],
            'QUAL_DISPATCH_DUE_AT': MANIFEST['due_at'], 'QUAL_DISPATCH_CUTOFF_AT': MANIFEST['cutoff_at'],
            'QUAL_DISPATCH_APPROVED': dispatcher.CONTRACT, 'QUAL_DISPATCH_CASE': 'retained-stop'}
        self.assertIsNone(dispatcher.admit_dispatch(env, MANIFEST['source_sha'], now=NOW, configured=False))
        admitted = dispatcher.admit_dispatch(env, MANIFEST['source_sha'], now=NOW, configured=True)
        self.assertEqual(admitted['contract'], dispatcher.CONTRACT)
        for key in env:
            altered = dict(env)
            del altered[key]
            self.assertIsNone(dispatcher.admit_dispatch(altered, MANIFEST['source_sha'], now=NOW, configured=True), key)


if __name__ == '__main__':
    unittest.main()
