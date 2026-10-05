"""Approved seam: one bounded source read and a truthful occurrence receipt.

External services are modeled at their public API boundary. This is local
qualification of the adapter, not evidence of real provider behavior.
"""
import sys
import unittest
import threading
import subprocess
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from source_bridge import execute, FixedSourceServices, ProtectedTransport

MANIFEST = {
    'contract': 'idyll-cloud-q-v1',
    'occurrence_id': 'idyll-cloud-q-20261002-source-01',
    'due_at': '2026-10-02T22:00:00Z', 'cutoff_at': '2026-10-02T22:01:30Z',
    'source_sha': '1111111111111111111111111111111111111111',
    'run_id': '123', 'attempt': 1,
}
SOURCE = {
    'id': 'synthetic-task-unconfigured', 'team_id': 'synthetic-workspace-unconfigured',
    'list': {'id': 'synthetic-list-unconfigured'}, 'date_updated': '0',
    'description': 'Synthetic history fixture only. Request idyll-cloud-q-synthetic-fixture-01; contract idyll-cloud-q-v1; revision synthetic-only-r1.',
}

class Services:
    """Boundary double retaining claims across invocations, like the candidate API."""
    def __init__(self):
        self.claims = set()
        self.source_reads = 0
    def repository_identity(self):
        return {'id': 1402638368, 'private': False}
    def revoked(self):
        return False
    def claim(self, manifest):
        occurrence_id = manifest['occurrence_id']
        if occurrence_id in self.claims:
            return False
        self.claims.add(occurrence_id)
        return True
    def read_fixture(self, *, deadline):
        self.source_reads += 1
        return dict(SOURCE)


class ProviderAPI:
    """Local model of API responses, not a GitHub or ClickUp observation."""
    def __init__(self):
        self.refs = {'refs/heads/codex/qualification': {'ref': 'refs/heads/codex/qualification', 'object': {'sha': '1111111111111111111111111111111111111111', 'type': 'commit'}}}
        self.tags = {}
        self.lock = threading.Lock()
        self.source_reads = 0
    def __call__(self, method, url, body=None, *, deadline=None):
        repo = 'https://api.github.com/repos/dallanlee/idyll-cloud-source-synthetic-qualification'
        if (method, url) == ('GET', repo):
            return 200, {'id': 1402638368, 'private': False, 'other_metadata': 'omitted'}
        if (method, url) == ('GET', 'https://api.clickup.com/api/v2/task/synthetic-task-unconfigured'):
            self.source_reads += 1
            return 200, dict(SOURCE)
        if method == 'GET' and url.startswith(repo + '/git/ref/'):
            ref = 'refs/' + url.split('/git/ref/', 1)[1]
            return (200, self.refs[ref]) if ref in self.refs else (404, {})
        if method == 'GET' and url.startswith(repo + '/git/tags/'):
            sha = url.rsplit('/', 1)[1]
            return (200, self.tags[sha]) if sha in self.tags else (404, {})
        if (method, url) == ('POST', repo + '/git/tags'):
            with self.lock:
                sha = format(len(self.tags) + 1, '040x')
                tag = {'sha': sha, 'tag': body['tag'], 'message': body['message'],
                       'object': {'sha': body['object'], 'type': 'commit'}}
                self.tags[sha] = tag
                return 201, tag
        if (method, url) == ('POST', repo + '/git/refs'):
            with self.lock:
                ref = body['ref']
                if ref in self.refs:
                    return 422, {}
                self.refs[ref] = {'ref': ref, 'object': {'sha': body['sha'], 'type': 'tag' if body['sha'] in self.tags else 'commit'}}
                return 201, dict(self.refs[ref])
        raise AssertionError('Request outside modeled provider contract')


class HTTPReply:
    def __init__(self, status=200, body=b'{"ok":true}'):
        self.status, self.body = status, body
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size):
        return self.body[:size]

class HTTPSBoundary:
    def __init__(self, reply=None):
        self.reply = reply or HTTPReply()
        self.requests = []
    def open(self, request, *, timeout):
        self.requests.append((request.full_url, dict(request.header_items()), timeout))
        return self.reply

class SourceBridgeTests(unittest.TestCase):
    def setUp(self):
        # Model the reviewed future adapter without enabling the public runner.
        enabled = patch('source_bridge.SOURCE_CONFIGURED', True)
        enabled.start()
        self.addCleanup(enabled.stop)

    def test_reads_the_fixed_fixture_once_and_rejects_a_replay(self):
        service = Services()
        now = lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc)
        result = execute(MANIFEST, service, now=now)
        repeated = execute(MANIFEST, service, now=now)
        self.assertEqual((result['outcome'], repeated['outcome'], service.source_reads),
                         ('SOURCE_MATCH', 'ALREADY_CLAIMED', 1))
        self.assertFalse(result['automatic_retry_allowed'])
        self.assertEqual(result['receipt']['source_object'], 'synthetic-task-unconfigured')
        self.assertEqual(result['source_action_count'], 1)

    def test_unknown_revocation_state_does_not_allow_source_access(self):
        service = Services()
        service.revoked = lambda: None
        result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], service.source_reads), ('UNKNOWN_CONTROL_RESULT', 0))

    def test_unknown_claim_result_blocks_access_without_claiming_a_duplicate(self):
        service = Services()
        service.claim = lambda *args: None
        result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], service.source_reads), ('UNKNOWN_CONTROL_RESULT', 0))

    def test_provider_adapter_reads_only_the_allowed_task(self):
        allowed_url = 'https://api.clickup.com/api/v2/task/synthetic-task-unconfigured'
        def transport(method, url, body=None, *, deadline=None):
            if (method, url, body) != ('GET', allowed_url, None):
                raise AssertionError('Unexpected outbound request')
            return 200, dict(SOURCE)
        service = FixedSourceServices(transport)
        self.assertEqual(service.read_fixture(deadline=datetime(2026, 10, 2, 22, 1, 30, tzinfo=timezone.utc)), SOURCE)

    def test_fresh_adapter_instances_preserve_the_same_occurrence_claim(self):
        api = ProviderAPI()
        now = lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc)
        first = execute(MANIFEST, FixedSourceServices(api), now=now)
        replay = execute(MANIFEST, FixedSourceServices(api), now=now)
        self.assertEqual((first['outcome'], replay['outcome'], api.source_reads),
                         ('SOURCE_MATCH', 'ALREADY_CLAIMED', 1))

    def test_transport_rejects_an_unapproved_url_before_network_access(self):
        transport = ProtectedTransport('fake-github-key', 'fake-clickup-key')
        with self.assertRaises(ValueError):
            transport('GET', 'https://example.invalid/collect')
        with self.assertRaises(ValueError):
            transport('DELETE', 'https://api.clickup.com/api/v2/task/synthetic-task-unconfigured')

    def test_entrypoint_without_reviewed_authority_exits_without_source_access(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/run_source_qualification.py'
        run = subprocess.run([sys.executable, '-B', str(script)],
            env={'QUAL_GITHUB_TOKEN': 'sentinel-not-a-real-key',
                 'QUAL_CLICKUP_OAUTH_TOKEN': 'sentinel-not-a-real-key'},
            capture_output=True, text=True, timeout=5)
        result = json.loads(run.stdout)
        self.assertEqual((run.returncode, result['outcome'], result['source_action_count']),
                         (2, 'SOURCE_NOT_CONFIGURED', 0))
        self.assertNotIn('sentinel', run.stdout + run.stderr)

    def test_changed_source_is_not_reported_with_the_expected_marker(self):
        service = Services()
        service.read_fixture = lambda **kwargs: dict(SOURCE, description='Changed outside this occurrence')
        result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], result['receipt']['source_marker']), ('SOURCE_MISMATCH', None))

    def test_two_concurrent_deliveries_produce_one_modeled_source_read(self):
        api = ProviderAPI()
        barrier = threading.Barrier(2)
        def deliver():
            barrier.wait(timeout=3)
            return execute(MANIFEST, FixedSourceServices(api),
                now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))['outcome']
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: deliver(), range(2)))
        self.assertEqual((sorted(outcomes), api.source_reads),
                         (['ALREADY_CLAIMED', 'SOURCE_MATCH'], 1))

    def test_early_and_late_arrivals_do_not_claim_or_read(self):
        for minute, second in ((59, 59), (1, 31)):
            with self.subTest(minute=minute):
                service = Services()
                hour = 21 if minute == 59 else 22
                result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, hour, minute, second, tzinfo=timezone.utc))
                self.assertEqual((result['outcome'], service.claims, service.source_reads),
                                 ('OUT_OF_WINDOW', set(), 0))

    def test_revocation_after_claim_blocks_source_and_retains_claim(self):
        service = Services()
        states = iter((False, True))
        service.revoked = lambda: next(states)
        result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], service.source_reads, len(service.claims)), ('REVOKED', 0, 1))

    def test_lost_claim_response_never_replays_a_possibly_acquired_claim(self):
        api = ProviderAPI()
        def uncertain(method, url, body=None, *, deadline=None):
            result = api(method, url, body)
            if method == 'POST' and url.endswith('/git/refs'):
                raise TimeoutError('sentinel-private-key-must-not-appear')
            return result
        now = lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc)
        first = execute(MANIFEST, FixedSourceServices(uncertain), now=now)
        replay = execute(MANIFEST, FixedSourceServices(api), now=now)
        self.assertEqual((first['outcome'], replay['outcome'], api.source_reads),
                         ('UNKNOWN_CONTROL_RESULT', 'ALREADY_CLAIMED', 0))
        self.assertNotIn('sentinel', json.dumps(first))

    def test_unknown_source_result_has_one_attempt_and_no_automatic_retry(self):
        service = Services()
        def uncertain(**kwargs):
            raise TimeoutError('sentinel-private-key-must-not-appear')
        service.read_fixture = uncertain
        result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], result['source_attempt_count'], result['source_action_count']),
                         ('UNKNOWN_SOURCE_RESULT', 1, None))
        self.assertFalse(result['automatic_retry_allowed'])
        self.assertNotIn('sentinel', json.dumps(result))

    def test_source_finishing_after_cutoff_is_preserved_as_late(self):
        moments = iter((datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc),) * 3
                       + (datetime(2026, 10, 2, 22, 1, 31, tzinfo=timezone.utc),))
        result = execute(MANIFEST, Services(), now=lambda: next(moments))
        self.assertEqual((result['outcome'], result['source_action_count']), ('OUT_OF_WINDOW', 1))

    def test_input_cannot_change_the_allowed_source(self):
        service = Services()
        result = execute(dict(MANIFEST, task_id='another-task'), service,
                         now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], service.source_reads), ('INVALID_MANIFEST', 0))

    def test_missing_stop_ref_with_unverified_contents_access_does_not_read(self):
        api = ProviderAPI()
        def restricted(method, url, body=None, *, deadline=None):
            if url.endswith('/git/ref/heads/codex/qualification'):
                return 403, {}
            return api(method, url, body)
        result = execute(MANIFEST, FixedSourceServices(restricted),
                         now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], api.source_reads), ('UNKNOWN_CONTROL_RESULT', 0))

    def test_source_transport_validation_error_keeps_attempt_unknown(self):
        service = Services()
        def rejected(**kwargs):
            raise ValueError('sentinel-private-key')
        service.read_fixture = rejected
        result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], result['source_attempt_count'], result['source_action_count']),
                         ('UNKNOWN_SOURCE_RESULT', 1, None))

    def test_malformed_dates_are_rejected_as_manifest_before_controls(self):
        service = Services()
        result = execute(dict(MANIFEST, due_at=12), service,
                         now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], service.source_reads), ('INVALID_MANIFEST', 0))

    def test_malformed_source_response_remains_a_completed_source_attempt(self):
        service = Services()
        service.read_fixture = lambda **kwargs: dict(SOURCE, list=12)
        result = execute(MANIFEST, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual((result['outcome'], result['source_action_count']), ('INVALID_SOURCE_EVIDENCE', 1))

    def test_source_service_passes_the_total_deadline_to_transport(self):
        seen = []
        cutoff = datetime(2026, 10, 2, 22, 1, 30, tzinfo=timezone.utc)
        def transport(method, url, body=None, *, deadline=None):
            seen.append(deadline)
            return 200, dict(SOURCE)
        FixedSourceServices(transport).read_fixture(deadline=cutoff)
        self.assertEqual(seen, [datetime(2026, 10, 2, 22, 1, 30, tzinfo=timezone.utc)])

    def test_credentials_are_sent_only_to_their_designated_service(self):
        boundary = HTTPSBoundary()
        transport = ProtectedTransport('fake-github-key', 'fake-clickup-key')
        with patch('urllib.request.build_opener', return_value=boundary):
            gh = transport('GET', FixedSourceServices.REPO_URL)
            cu = transport('GET', FixedSourceServices.SOURCE_URL,
                           deadline=datetime.now(timezone.utc) + timedelta(seconds=5))
        authorizations = [request[1]['Authorization'] for request in boundary.requests]
        self.assertEqual((gh[0], cu[0], authorizations),
                         (200, 200, ['Bearer fake-github-key', 'Bearer fake-clickup-key']))

    def test_source_deadline_interrupts_a_slow_connection(self):
        class SlowConnection(HTTPSBoundary):
            def open(self, request, *, timeout):
                time.sleep(0.2)
                return super().open(request, timeout=timeout)
        boundary = SlowConnection()
        transport = ProtectedTransport('fake-github-key', 'fake-clickup-key')
        started = time.monotonic()
        with patch('urllib.request.build_opener', return_value=boundary):
            with self.assertRaises(RuntimeError):
                transport('GET', FixedSourceServices.SOURCE_URL,
                          deadline=datetime.now(timezone.utc) + timedelta(seconds=0.03))
        self.assertLess(time.monotonic() - started, 0.15)

    def test_transport_refuses_redirect_oversize_and_malformed_responses(self):
        cases = [(302, b'{"message":"sentinel-private-key"}'),
                 (200, b'x' * 262145), (200, b'[]'), (200, b'not-json')]
        for status, body in cases:
            with self.subTest(status=status, bytes=len(body)):
                boundary = HTTPSBoundary(HTTPReply(status, body))
                transport = ProtectedTransport('fake-github-key', 'fake-clickup-key')
                with patch('urllib.request.build_opener', return_value=boundary):
                    with self.assertRaises(RuntimeError) as failure:
                        transport('GET', FixedSourceServices.REPO_URL)
                self.assertNotIn('sentinel', str(failure.exception))
                self.assertEqual(len(boundary.requests), 1)

    def test_source_deadline_interrupts_a_slow_response_body(self):
        class SlowBody(HTTPReply):
            def read(self, size):
                time.sleep(0.2)
                return super().read(size)
        transport = ProtectedTransport('fake-github-key', 'fake-clickup-key')
        started = time.monotonic()
        with patch('urllib.request.build_opener', return_value=HTTPSBoundary(SlowBody())):
            with self.assertRaises(RuntimeError):
                transport('GET', FixedSourceServices.SOURCE_URL,
                          deadline=datetime.now(timezone.utc) + timedelta(seconds=0.03))
        self.assertLess(time.monotonic() - started, 0.15)

    def test_expired_source_deadline_does_not_open_a_connection(self):
        boundary = HTTPSBoundary()
        transport = ProtectedTransport('fake-github-key', 'fake-clickup-key')
        with patch('urllib.request.build_opener', return_value=boundary):
            with self.assertRaises(RuntimeError):
                transport('GET', FixedSourceServices.SOURCE_URL,
                          deadline=datetime(2020, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(boundary.requests, [])

    def test_source_error_body_does_not_escape_as_an_exception(self):
        boundary = HTTPSBoundary(HTTPReply(403, b'{"error":"sentinel-private-key"}'))
        service = FixedSourceServices(ProtectedTransport('fake-github-key', 'fake-clickup-key'))
        with patch('urllib.request.build_opener', return_value=boundary):
            with self.assertRaises(RuntimeError) as failure:
                service.read_fixture(deadline=datetime.now(timezone.utc) + timedelta(seconds=1))
        self.assertNotIn('sentinel', str(failure.exception))

    def test_environment_proxy_and_redirect_handlers_are_not_used(self):
        from urllib.request import ProxyHandler, HTTPRedirectHandler
        boundary = HTTPSBoundary()
        with patch('urllib.request.build_opener', return_value=boundary) as factory:
            ProtectedTransport('fake-github-key', 'fake-clickup-key')('GET', FixedSourceServices.REPO_URL)
        handlers = factory.call_args.args
        proxy = next(h for h in handlers if isinstance(h, ProxyHandler))
        redirect = next(h for h in handlers if isinstance(h, HTTPRedirectHandler))
        self.assertEqual(proxy.proxies, {})
        self.assertIsNone(redirect.redirect_request(None, None, 302, 'redirect', {}, 'https://example.invalid'))

    def test_tag_transport_rejects_noncanonical_metadata_before_network(self):
        metadata = {key: MANIFEST[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')}
        canonical = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
        body = {'tag': 'idyll-cloud-q-occurrence/' + MANIFEST['occurrence_id'],
                'message': canonical, 'object': MANIFEST['source_sha'], 'type': 'commit'}
        boundary = HTTPSBoundary()
        transport = ProtectedTransport('fake-github-key', 'fake-clickup-key')
        cases = [dict(body, message=json.dumps(metadata)),
                 dict(body, message='{"run_id":"arbitrary-content",' + canonical[1:]),
                 dict(body, tag=12)]
        with patch('urllib.request.build_opener', return_value=boundary):
            for invalid in cases:
                with self.subTest(body=invalid):
                    with self.assertRaises(ValueError):
                        transport('POST', FixedSourceServices.REPO_URL + '/git/tags', invalid)
        self.assertEqual(boundary.requests, [])

    def test_malformed_prior_claim_reports_unknown_control_without_source_access(self):
        now = lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc)
        for malformed in ({'message': None}, {'message': 'not-json'}, {'object': None}):
            with self.subTest(malformed=malformed):
                api = ProviderAPI()
                execute(MANIFEST, FixedSourceServices(api), now=now)
                def invalid(method, url, body=None, *, deadline=None):
                    status, value = api(method, url, body)
                    if method == 'GET' and '/git/tags/' in url:
                        return status, dict(value, **malformed)
                    return status, value
                result = execute(MANIFEST, FixedSourceServices(invalid), now=now)
                self.assertEqual((result['outcome'], result['source_attempt_count'], api.source_reads),
                                 ('UNKNOWN_CONTROL_RESULT', 0, 1))

    def test_prior_claim_attributes_the_acquiring_run_after_a_lost_reply(self):
        api = ProviderAPI()
        def uncertain(method, url, body=None, *, deadline=None):
            result = api(method, url, body)
            if method == 'POST' and url.endswith('/git/refs'):
                raise TimeoutError('Lost reply')
            return result
        now = lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc)
        first = execute(MANIFEST, FixedSourceServices(uncertain), now=now)
        replay = execute(dict(MANIFEST, run_id='124'), FixedSourceServices(api), now=now)
        self.assertEqual((first['outcome'], replay['outcome'], api.source_reads),
                         ('UNKNOWN_CONTROL_RESULT', 'ALREADY_CLAIMED', 0))
        self.assertEqual((replay['claim']['run_id'], replay['claim']['attempt']), ('123', 1))

    def test_a_personal_clickup_token_cannot_substitute_for_the_reviewed_oauth_grant(self):
        with self.assertRaises(ValueError):
            ProtectedTransport('fake-github-key', 'pk_fake-personal-token')

    def test_source_bridge_rejects_121_seconds_and_accepts_120_seconds(self):
        service = Services()
        # 120s is accepted (reaches claim or source)
        m_120 = dict(MANIFEST, cutoff_at='2026-10-02T22:02:00Z')
        res_120 = execute(m_120, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertNotEqual(res_120['outcome'], 'INVALID_MANIFEST')

        # 121s is rejected with INVALID_MANIFEST
        m_121 = dict(MANIFEST, cutoff_at='2026-10-02T22:02:01Z')
        res_121 = execute(m_121, service, now=lambda: datetime(2026, 10, 2, 22, 0, 10, tzinfo=timezone.utc))
        self.assertEqual(res_121['outcome'], 'INVALID_MANIFEST')


if __name__ == '__main__':
    unittest.main()
