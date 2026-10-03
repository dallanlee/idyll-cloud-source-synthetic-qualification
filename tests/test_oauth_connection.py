"""Credential-boundary behavior; all credentials and provider replies are fabricated."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from connect_clickup_oauth import (verify_workspace, ConnectionRefused, Consumer,
                                  ClickUpApi, ConnectionLanding)
from urllib.parse import urlencode


class WorkspaceTests(unittest.TestCase):
    def test_only_the_single_named_synthetic_workspace_is_accepted(self):
        self.assertEqual(verify_workspace({'teams': [{
            'id': '90141728025',
            'name': 'Idyll Cloud Qualification — Synthetic Only'}]}), '90141728025')
        for payload in ({'teams': []}, {'teams': [{'id': 'other'}]},
                        {'teams': [{'id': '90141728025', 'name': 'Other Workspace'}]},
                        {'teams': [{'id': '90141728025', 'name': 'Idyll Cloud Qualification — Synthetic Only'},
                                   {'id': 'other', 'name': 'Personal'}]}):
            with self.subTest(payload=payload), self.assertRaises(ConnectionRefused):
                verify_workspace(payload)


class ConsumerTests(unittest.TestCase):
    def test_gate_change_after_workspace_verification_prevents_upload(self):
        class Api:
            def exchange(self, *_args): return 'fabricated-token'
            def workspaces(self, _token): return {'teams': [{'id': '90141728025',
                'name': 'Idyll Cloud Qualification — Synthetic Only'}]}
        class Store:
            checks = 0
            def ready(self):
                self.checks += 1
                if self.checks == 2: raise ConnectionRefused('Controls changed')
            def store(self, _token): raise AssertionError('Changed controls must block upload')
        with self.assertRaisesRegex(ConnectionRefused, 'Controls changed'):
            Consumer('fabricated-public-id', Api(), Store()).connect('fabricated-code', 'fabricated-secret')

    def test_browser_return_releases_credentials_and_reports_uncertain_outcome_safely(self):
        class RefusedConsumer:
            def connect(self, *_args): raise RuntimeError('fabricated-secret')
        landing = ConnectionLanding('fabricated-public-id', RefusedConsumer(), 'fabricated-secret')
        landing.begin(urlencode({'csrf': landing.csrf, 'scope': '90141728025'}),
                      origin='http://127.0.0.1:8768', host='127.0.0.1:8768')
        landing.callback(urlencode({'state': landing.state, 'code': 'fabricated-code'}), host='127.0.0.1:8768')
        self.assertIn('outcome is uncertain', landing.done_message)
        self.assertNotIn('fabricated-secret', landing.done_message)
        self.assertIsNone(landing.client_secret)
        self.assertIsNone(landing._authorization_code)
    def test_closed_storage_gate_never_exchanges_a_code_and_cannot_replay(self):
        class Api:
            def exchange(self, *_args):
                raise AssertionError('Credential exchange must not be attempted')
        class Store:
            def ready(self): raise ConnectionRefused('Protected storage not qualified')
        consumer = Consumer('fabricated-public-id', Api(), Store())
        with self.assertRaisesRegex(ConnectionRefused, 'Protected storage not qualified'):
            consumer.connect('fabricated-code', 'fabricated-secret')
        with self.assertRaisesRegex(ConnectionRefused, 'already consumed'):
            consumer.connect('fabricated-code', 'fabricated-secret')

    def test_extra_workspace_discards_the_token_without_storage(self):
        class Api:
            def exchange(self, *_args): return 'fabricated-token'
            def workspaces(self, _token): return {'teams': [{'id': '90141728025',
                'name': 'Idyll Cloud Qualification — Synthetic Only'}, {'id': 'other'}]}
        class Store:
            def ready(self): pass
            def store(self, _token): raise AssertionError('Overbroad token must not be stored')
        with self.assertRaisesRegex(ConnectionRefused, 'Sole synthetic Workspace'):
            Consumer('fabricated-public-id', Api(), Store()).connect('fabricated-code', 'fabricated-secret')

    def test_failure_details_never_include_provider_credentials(self):
        class Api:
            def exchange(self, *_args): raise RuntimeError('fabricated-secret-and-code')
        class Store:
            def ready(self): pass
        with self.assertRaises(ConnectionRefused) as result:
            Consumer('fabricated-public-id', Api(), Store()).connect('fabricated-code', 'fabricated-secret')
        self.assertNotIn('fabricated-secret', str(result.exception))

    def test_storage_happens_only_after_workspace_readback_and_fresh_gate(self):
        events = []
        class Api:
            def exchange(self, client_id, client_secret, code):
                events.append('exchange')
                return 'fabricated-token'
            def workspaces(self, token):
                events.append('workspaces')
                return {'teams': [{'id': '90141728025',
                                  'name': 'Idyll Cloud Qualification — Synthetic Only'}]}
        class Store:
            def ready(self): events.append('gate')
            def store(self, token): events.append(('store', token))
        consumer = Consumer('fabricated-public-id', Api(), Store())
        self.assertEqual(consumer.connect('fabricated-code', 'fabricated-secret'), 'connected')
        self.assertEqual(events, ['gate', 'exchange', 'workspaces', 'gate',
                                  ('store', 'fabricated-token')])


class TransportTests(unittest.TestCase):
    def test_invalid_credentials_never_start_https_and_large_reply_is_refused(self):
        def no_connection(*_args, **_options): raise AssertionError('Must refuse before HTTPS')
        with self.assertRaises(ConnectionRefused):
            ClickUpApi(connection_factory=no_connection).workspaces('fabricated\r\nheader')
        class Reply:
            status = 200
            def getheaders(self): return [('Content-Type', 'application/json')]
            def read(self, limit): return b' ' * limit
        class Connection:
            def __init__(self, *_args, **_options): pass
            def request(self, *_args, **_options): pass
            def getresponse(self): return Reply()
            def close(self): pass
        with self.assertRaisesRegex(ConnectionRefused, 'too large'):
            ClickUpApi(connection_factory=Connection).workspaces('fabricated-token')

    def test_exchange_uses_fixed_https_endpoint_and_does_not_follow_redirects(self):
        calls = []
        class Reply:
            status = 302
            def getheaders(self): return [('Content-Type', 'application/json'), ('Location', 'https://other.invalid')]
            def read(self, _limit): raise AssertionError('Redirect body must not be consumed')
        class Connection:
            def __init__(self, host, **options): calls.append(('connection', host, options['timeout']))
            def request(self, method, path, body=None, headers=None): calls.append((method, path))
            def getresponse(self): return Reply()
            def close(self): calls.append('closed')
        with self.assertRaises(ConnectionRefused):
            ClickUpApi(connection_factory=Connection).exchange('fabricated-id', 'fabricated-secret', 'fabricated-code')
        self.assertEqual(calls, [('connection', 'api.clickup.com', 10),
            ('POST', '/api/v2/oauth/token'), 'closed'])


if __name__ == '__main__':
    unittest.main()
