import copy
import unittest
from scripts.reconcile_occurrence import reconcile


EXPECTED = {
    'occurrence_id': 'idyll-cloud-q-20261002-recovery-03-only',
    'due_at': '2026-10-02T22:21:00Z',
    'cutoff_at': '2026-10-02T22:22:30Z',
    'source_sha': '1111111111111111111111111111111111111111',
    'source_object': 'synthetic-object',
    'source_marker': 'synthetic-r3',
}
NOW = '2026-10-02T22:25:04Z'


def success_run(run_id='1001'):
    return {
        'run_id': run_id, 'attempt': 1,
        'occurrence_id': EXPECTED['occurrence_id'],
        'source_sha': EXPECTED['source_sha'],
        'status': 'success', 'source_action_count': 1,
        'receipt': {
            'source_object': 'synthetic-object', 'source_marker': 'synthetic-r3',
            'started_at': '2026-10-02T22:21:43Z',
            'completed_at': '2026-10-02T22:21:56Z',
        },
    }


class ReconciliationTests(unittest.TestCase):
    def test_complete_history_exposes_missed_occurrence_without_retrying(self):
        result = reconcile(EXPECTED, [], now=NOW, history_complete=True)
        self.assertEqual(result['outcome'], 'MISSED')
        self.assertFalse(result['automatic_retry_allowed'])

    def test_incomplete_history_never_claims_a_miss_or_allows_blind_retry(self):
        result = reconcile(EXPECTED, [], now=NOW, history_complete=False)
        self.assertEqual(result['outcome'], 'UNKNOWN_HISTORY')
        self.assertFalse(result['automatic_retry_allowed'])

    def test_success_requires_one_exact_source_receipt_in_the_original_window(self):
        result = reconcile(EXPECTED, [success_run()], now=NOW, history_complete=True)
        self.assertEqual(result['outcome'], 'VERIFIED_SUCCESS')
        self.assertFalse(result['automatic_retry_allowed'])

    def test_multiple_provider_runs_expose_duplicate_effects(self):
        result = reconcile(EXPECTED, [success_run(), success_run('1002')],
                           now=NOW, history_complete=True)
        self.assertEqual(result['outcome'], 'DUPLICATE_EFFECTS')
        self.assertFalse(result['automatic_retry_allowed'])

    def test_provider_cancelled_status_alone_does_not_prove_executor_termination(self):
        run = success_run()
        run.update(status='cancelled', source_action_count=0)
        run.pop('receipt')
        result = reconcile(EXPECTED, [run], now=NOW, history_complete=True,
                           stop_requested_at='2026-10-02T22:21:20Z')
        self.assertEqual(result['outcome'], 'STOP_UNVERIFIED')
        self.assertFalse(result['automatic_retry_allowed'])

    def test_missing_native_run_identity_remains_unqualified(self):
        run = success_run()
        run['run_id'] = None
        result = reconcile(EXPECTED, [run], now=NOW, history_complete=True)
        self.assertEqual(result['outcome'], 'UNKNOWN_RUN_ID')

    def test_success_label_with_late_source_access_is_rejected(self):
        run = success_run()
        run['receipt']['completed_at'] = '2026-10-02T22:22:31Z'
        result = reconcile(EXPECTED, [run], now=NOW, history_complete=True)
        self.assertEqual(result['outcome'], 'OUT_OF_WINDOW')

    def test_bad_run_metadata_cannot_be_mistaken_for_verified_source_evidence(self):
        for field, value in [('attempt', None), ('source_action_count', True),
                             ('occurrence_id', 'unrelated-occurrence')]:
            with self.subTest(field=field):
                run = success_run()
                run[field] = value
                result = reconcile(EXPECTED, [run], now=NOW, history_complete=True)
                self.assertEqual(result['outcome'], 'INVALID_EVIDENCE')

    def test_future_receipt_is_not_accepted_as_an_observed_completion(self):
        result = reconcile(EXPECTED, [success_run()], now='2026-10-02T22:21:45Z',
                           history_complete=True)
        self.assertEqual(result['outcome'], 'INVALID_EVIDENCE')

    def test_duplicate_delivery_of_identical_receipt_is_not_a_second_execution(self):
        run = success_run()
        result = reconcile(EXPECTED, [run, copy.deepcopy(run)], now=NOW, history_complete=True)
        self.assertEqual(result['outcome'], 'VERIFIED_SUCCESS')

    def test_conflicting_receipts_for_same_run_require_reconciliation(self):
        run = success_run()
        conflict = copy.deepcopy(run)
        conflict['source_action_count'] = 0
        result = reconcile(EXPECTED, [run, conflict], now=NOW, history_complete=True)
        self.assertEqual(result['outcome'], 'UNKNOWN_RESULT')

    def test_malformed_receipts_fail_closed_without_exposing_the_input(self):
        for receipt in [None, {'started_at': 'missing-timezone', 'completed_at': NOW},
                        {'started_at': '2026-10-02T22:21:43'}]:
            with self.subTest(receipt=receipt):
                run = success_run()
                run['receipt'] = receipt
                result = reconcile(EXPECTED, [run], now=NOW, history_complete=True)
                self.assertEqual(result, {'outcome': 'INVALID_EVIDENCE',
                                          'automatic_retry_allowed': False})


if __name__ == '__main__':
    unittest.main()
