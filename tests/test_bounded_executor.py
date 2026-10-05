"""Approved process deadline seam, including a real blocked DNS child."""
import os
import json
import sys
import time
import unittest
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from bounded_executor import run_supervised, sanitize_result
from test_source_observation import MANIFEST


def payload_and_deadline(seconds=0.7):
    current = datetime.now(timezone.utc)
    deadline = current + timedelta(seconds=seconds)
    manifest = dict(MANIFEST, due_at=(current - timedelta(seconds=1)).isoformat(), cutoff_at=deadline.isoformat())
    return {'mode': 'observation', 'manifest': manifest,
            'github_token': 'fake-github', 'clickup_token': 'fake-oauth'}, deadline


class ExecutorTests(unittest.TestCase):
    def test_old_receipts_stay_historical_and_v2_cannot_forge_witnessless_pass(self):
        from test_retained_stop import StopAPI, NOW
        import retained_stop_probe as probe
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        receipt = probe.probe_retained_stop(manifest, StopAPI(), now=lambda: NOW)
        self.assertEqual(sanitize_result(receipt, manifest), receipt)
        for key, changed in [('control_witness', None), ('github_attempt_count', 19),
                             ('github_action_count', 19), ('source_attempt_count', 1)]:
            bad = dict(receipt, **{key: changed})
            with self.subTest(key=key), self.assertRaises(ValueError):
                sanitize_result(bad, manifest)
        for changed in ({'raw_comment': 'private-sentinel'}, {'version': True}, {'reviewer_id': True},
                        {'comment_sha256': 'x'}, {'observed_at': '2027-01-01T00:00:00Z'}):
            with self.assertRaises(ValueError):
                sanitize_result(dict(receipt, control_witness=dict(receipt['control_witness'], **changed)), manifest)
        old = dict(receipt, contract=probe.LEGACY_CONTRACT, github_attempt_count=19, github_action_count=19)
        old.pop('control_witness')
        self.assertEqual(sanitize_result(old, dict(manifest, contract=probe.LEGACY_CONTRACT)), old)
        old_diagnostic = {key: old[key] for key in ('contract', 'automatic_retry_allowed',
            'occurrence_id', 'source_sha', 'run_id', 'attempt', 'source_attempt_count', 'source_action_count')}
        old_diagnostic.update(outcome='AUTHORITY_REFUSED', github_attempt_count=8, github_action_count=8,
            patch_attempt_count=0, delete_attempt_count=0, refusal_stage='stop_ruleset_bypass_missing',
            ruleset_http_status={'stop': 200, 'occurrence': 200})
        self.assertEqual(sanitize_result(old_diagnostic, dict(manifest, contract=probe.LEGACY_CONTRACT)), old_diagnostic)
        with self.assertRaises(ValueError):
            sanitize_result(dict(old, control_witness=receipt['control_witness']), dict(manifest, contract=probe.LEGACY_CONTRACT))

    def test_real_probe_ruleset_refusal_and_http_stage_survive_supervised_ipc(self):
        fixture = str(Path(__file__).parent / 'fixtures' / 'executor_frames.py')
        for case, stage, statuses, count in (
                ('stop-diagnostic', 'stop_ruleset_bypass_mismatch', {'stop': 200, 'occurrence': 200}, 8),
                ('stop-diagnostic-http', 'occurrence_ruleset_http', {'stop': 200, 'occurrence': 404}, 8),
                ('stop-diagnostic-stop-http', 'stop_ruleset_http', {'stop': 403}, 7)):
            with self.subTest(case=case):
                payload, deadline = payload_and_deadline(1.5)
                payload['mode'] = 'retained-stop'
                payload['manifest']['contract'] = 'idyll-cloud-q-v2-retained-stop'
                del payload['clickup_token']
                result = run_supervised(payload, deadline, child_command=[sys.executable, '-B', fixture, case])
                self.assertEqual((result['outcome'], result.get('refusal_stage'), result.get('ruleset_http_status'),
                    result['github_attempt_count'], result['github_action_count'], result['source_attempt_count']),
                    ('AUTHORITY_REFUSED', stage, statuses, count, count, 0))
                self.assertEqual((result['patch_attempt_count'], result['delete_attempt_count']), (0, 0))
                self.assertTrue(result['executor']['reaped'])
                self.assertNotIn('private-sentinel', str(result))
                with self.assertRaises(ProcessLookupError):
                    os.kill(result['executor']['pid'], 0)

    def test_parent_refuses_unearned_or_unbounded_ruleset_diagnostics_and_wrong_contracts(self):
        fixture = str(Path(__file__).parent / 'fixtures' / 'executor_frames.py')
        cases = ['unknown-code', 'raw-status', 'extra-status', 'bool-status', 'float-status', 'small-status',
                 'large-status', 'missing-stage', 'missing-status', 'http-200', 'wrong-outcome',
                 'nonzero-operations', 'claimed']
        for case, mode, contract in (
                [(case, 'retained-stop', 'idyll-cloud-q-v2-retained-stop') for case in cases]
                + [('contract-observation', 'observation', 'idyll-cloud-q-v1-observation'),
                   ('contract-dispatch', 'dispatch', 'idyll-cloud-q-v1-case-dispatcher')]):
            with self.subTest(case=case, mode=mode):
                payload, deadline = payload_and_deadline(1.5)
                payload['mode'], payload['manifest']['contract'] = mode, contract
                if mode != 'observation':
                    del payload['clickup_token']
                if mode == 'dispatch':
                    payload.update(case='retained-stop', run_number=2)
                result = run_supervised(payload, deadline,
                    child_command=[sys.executable, '-B', fixture, 'stop-diagnostic-' + case])
                self.assertEqual(result['outcome'], 'UNKNOWN_CONTROL_RESULT')
                self.assertNotIn('refusal_stage', result)
                self.assertNotIn('ruleset_http_status', result)
                self.assertNotIn('private-sentinel', str(result))
                self.assertTrue(result['executor']['reaped'])
                with self.assertRaises(ProcessLookupError):
                    os.kill(result['executor']['pid'], 0)

    def test_blocked_dns_is_killed_and_reaped_before_control_returns(self):
        command = [sys.executable, '-B', str(Path(__file__).parent / 'fixtures' / 'blocked_dns.py')]
        start = time.monotonic()
        payload, deadline = payload_and_deadline()
        result = run_supervised(payload, deadline, child_command=command)
        self.assertEqual((result['outcome'], result['source_attempt_count'], result['source_action_count']),
                         ('DEADLINE_EXPIRED', 1, None))
        self.assertTrue(result['executor']['reaped'])
        with self.assertRaises(ProcessLookupError):
            os.kill(result['executor']['pid'], 0)
        self.assertLess(time.monotonic() - start, 3)

    def test_inactive_cli_never_consumes_credentials_or_starts_executor(self):
        cli = Path(__file__).resolve().parents[1] / 'scripts' / 'run_source_observation.py'
        for arguments in ([], ['--retained-stop'], ['--dispatch']):
            result = subprocess.run([sys.executable, '-B', str(cli)] + arguments,
                capture_output=True, timeout=3, env={'QUAL_GITHUB_TOKEN': 'private-sentinel',
                    'QUAL_CLICKUP_OAUTH_TOKEN': 'private-sentinel'})
            self.assertEqual(result.returncode, 2)
            receipt = json.loads(result.stdout)
            self.assertIn(receipt['outcome'], {'OBSERVATION_NOT_CONFIGURED', 'AUTHORITY_REFUSED'})
            self.assertEqual((receipt['source_attempt_count'], receipt['github_attempt_count']), (0, 0))
            if not arguments:
                self.assertEqual(receipt['outcome'], 'OBSERVATION_NOT_CONFIGURED')
            self.assertNotIn(b'private-sentinel', result.stdout + result.stderr)
            self.assertNotIn(b'pid', result.stdout)

    def test_direct_executor_has_no_authority_without_its_supervisor(self):
        cli = Path(__file__).resolve().parents[1] / 'scripts' / 'run_source_observation.py'
        result = subprocess.run([sys.executable, '-I', '-B', str(cli), '--executor'],
            input=b'private-sentinel', capture_output=True, timeout=3, env={})
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'private-sentinel', result.stdout + result.stderr)

    def test_child_success_still_requires_reaping_and_raw_extra_fields_are_refused(self):
        fixture = str(Path(__file__).parent / 'fixtures' / 'executor_frames.py')
        for case, outcome in [('success', 'SOURCE_OBSERVED'), ('raw-extra', 'UNKNOWN_CONTROL_RESULT'),
                              ('unearned-success', 'UNKNOWN_CONTROL_RESULT'), ('flood', 'UNKNOWN_CONTROL_RESULT')]:
            with self.subTest(case=case):
                payload, deadline = payload_and_deadline(1.5)
                result = run_supervised(payload, deadline, child_command=[sys.executable, '-B', fixture, case])
                self.assertEqual(result['outcome'], outcome)
                self.assertTrue(result['executor']['reaped'])
                self.assertNotIn('private-sentinel', str(result))
                with self.assertRaises(ProcessLookupError):
                    os.kill(result['executor']['pid'], 0)

    def test_parent_deadline_also_bounds_a_child_that_never_reads_credentials(self):
        payload, deadline = payload_and_deadline(0.3)
        payload['github_token'] = 'a' * 4096
        payload['clickup_token'] = 'b' * 4096
        start = time.monotonic()
        result = run_supervised(payload, deadline,
            child_command=[sys.executable, '-c', 'import time; time.sleep(60)'])
        self.assertEqual(result['outcome'], 'DEADLINE_EXPIRED')
        self.assertTrue(result['executor']['reaped'])
        self.assertLess(time.monotonic() - start, 2)

    def test_parent_accepts_sanitized_dispatch_details_and_the_preserved_stop_identity(self):
        fixture = str(Path(__file__).parent / 'fixtures' / 'executor_frames.py')
        for case, mode, contract, outcome in (
                ('dispatch', 'dispatch', 'idyll-cloud-q-v1-case-dispatcher', 'DISPATCH_CONFIRMED'),
                ('stop', 'retained-stop', 'idyll-cloud-q-v2-retained-stop', 'RETAINED_STOP_PASS')):
            with self.subTest(case=case):
                payload, deadline = payload_and_deadline(1.5)
                payload['mode'] = mode
                payload['manifest']['contract'] = contract
                del payload['clickup_token']
                if mode == 'dispatch':
                    payload.update(case='retained-stop', run_number=2)
                result = run_supervised(payload, deadline, child_command=[sys.executable, '-B', fixture, case])
                self.assertEqual((result['outcome'], result['source_attempt_count'], result['executor']['reaped']),
                                 (outcome, 0, True))

    def test_supervisor_enforces_exact_case_windows_and_rejects_unauthorized_durations(self):
        fixture = str(Path(__file__).parent / 'fixtures' / 'executor_frames.py')
        now = datetime.now(timezone.utc)

        # Retained-stop: 601s rejected before subprocess
        payload, _ = payload_and_deadline(1.5)
        payload['mode'] = 'retained-stop'
        payload['manifest']['contract'] = 'idyll-cloud-q-v2-retained-stop'
        payload['manifest']['due_at'] = (now - timedelta(seconds=1)).isoformat()
        payload['manifest']['cutoff_at'] = (now + timedelta(seconds=601)).isoformat()
        del payload['clickup_token']
        cutoff = datetime.fromisoformat(payload['manifest']['cutoff_at'])
        res = run_supervised(payload, cutoff, child_command=[sys.executable, '-B', fixture, 'stop'])
        self.assertEqual(res['outcome'], 'UNKNOWN_CONTROL_RESULT')

        # Dispatch with case='observation' and 121s rejected before subprocess
        payload, _ = payload_and_deadline(1.5)
        payload['mode'] = 'dispatch'
        payload['manifest']['contract'] = 'idyll-cloud-q-v1-case-dispatcher'
        payload['manifest']['due_at'] = (now - timedelta(seconds=1)).isoformat()
        payload['manifest']['cutoff_at'] = (now + timedelta(seconds=121)).isoformat()
        payload.update(case='observation', run_number=2)
        del payload['clickup_token']
        cutoff = datetime.fromisoformat(payload['manifest']['cutoff_at'])
        res = run_supervised(payload, cutoff, child_command=[sys.executable, '-B', fixture, 'dispatch'])
        self.assertEqual(res['outcome'], 'UNKNOWN_CONTROL_RESULT')

        # Observation with 121s rejected before subprocess
        payload, _ = payload_and_deadline(1.5)
        payload['manifest']['due_at'] = (now - timedelta(seconds=1)).isoformat()
        payload['manifest']['cutoff_at'] = (now + timedelta(seconds=121)).isoformat()
        cutoff = datetime.fromisoformat(payload['manifest']['cutoff_at'])
        res = run_supervised(payload, cutoff, child_command=[sys.executable, '-B', fixture, 'success'])
        self.assertEqual(res['outcome'], 'UNKNOWN_CONTROL_RESULT')

        # Dispatch with wrongcase rejected before subprocess
        payload, _ = payload_and_deadline(1.5)
        payload['mode'] = 'dispatch'
        payload['manifest']['contract'] = 'idyll-cloud-q-v1-case-dispatcher'
        payload['manifest']['due_at'] = (now - timedelta(seconds=1)).isoformat()
        payload['manifest']['cutoff_at'] = (now + timedelta(seconds=60)).isoformat()
        payload.update(case='wrongcase', run_number=2)
        del payload['clickup_token']
        cutoff = datetime.fromisoformat(payload['manifest']['cutoff_at'])
        res = run_supervised(payload, cutoff, child_command=[sys.executable, '-B', fixture, 'dispatch'])
        self.assertEqual(res['outcome'], 'UNKNOWN_CONTROL_RESULT')

        # Exact cutoff: cutoff already reached raises TimeoutError -> DEADLINE_EXPIRED
        payload, deadline = payload_and_deadline(1.5)
        expired_cutoff = datetime.now(timezone.utc) - timedelta(seconds=1)
        res = run_supervised(payload, expired_cutoff, child_command=[sys.executable, '-B', fixture, 'success'])
        self.assertEqual(res['outcome'], 'DEADLINE_EXPIRED')


if __name__ == '__main__':
    unittest.main()
