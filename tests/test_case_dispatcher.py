"""Fresh finite machine dispatch boundary; ephemeral Actions token only."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import finite_case_dispatcher as dispatcher
from test_source_observation import ObservationAPI, MANIFEST, NOW


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
            return 204, {}
        return super().__call__(method, url, body, deadline=deadline)


class DispatchTests(unittest.TestCase):
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
