"""Fixed provider request seam; modeled HTTPS, no network or credentials."""
import sys
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from source_observation import FixedHTTPTransport, SOURCE_URL, REPO_URL
from test_source_bridge import HTTPSBoundary, HTTPReply


class TransportTests(unittest.TestCase):
    def test_source_free_modes_refuse_a_source_credential_entirely(self):
        for mode in ({'stop_probe': True}, {'dispatch_case': 'retained-stop'}):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    FixedHTTPTransport('fake-github', 'fake-oauth', **mode)

    def test_only_fixed_get_can_consume_the_source_and_lost_reply_cannot_retry(self):
        deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
        provider = HTTPSBoundary(HTTPReply(200, b'{"id":"86bccact7"}'))
        transport = FixedHTTPTransport('fake-github', 'fake-oauth')
        with patch('urllib.request.build_opener', return_value=provider):
            for method, url in [('POST', SOURCE_URL), ('GET', SOURCE_URL + '?include_subtasks=true'),
                                ('GET', 'https://api.clickup.com/api/v2/team')]:
                with self.assertRaises(ValueError):
                    transport(method, url, deadline=deadline)
            transport('GET', SOURCE_URL, deadline=deadline)
            with self.assertRaises(ValueError):
                transport('GET', SOURCE_URL, deadline=deadline)
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(provider.requests[0][0], SOURCE_URL)
        self.assertEqual(provider.requests[0][1]['Authorization'], 'Bearer fake-oauth')

    def test_fixed_stop_operations_reach_https_once_each_and_empty204_is_understood(self):
        deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
        provider = HTTPSBoundary(HTTPReply(204, b''))
        transport = FixedHTTPTransport('fake-github', stop_probe=True)
        url = REPO_URL + '/git/refs/tags/idyll-cloud-q-stop-v1'
        body = {'sha': '260d783935a0f47eed9222ec66f48e7502cb30b7', 'force': True}
        with patch('urllib.request.build_opener', return_value=provider):
            self.assertEqual(transport('PATCH', url, body, deadline=deadline), (204, {}))
            self.assertEqual(transport('DELETE', url, deadline=deadline), (204, {}))
            for method, value in [('PATCH', body), ('DELETE', None)]:
                with self.assertRaises(ValueError):
                    transport(method, url, value, deadline=deadline)
        self.assertEqual(len(provider.requests), 2)

    def test_redirects_proxies_and_error_text_cannot_escape(self):
        from urllib.request import ProxyHandler, HTTPRedirectHandler
        deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
        provider = HTTPSBoundary(HTTPReply(302, b'private-sentinel'))
        with patch('urllib.request.build_opener', return_value=provider) as factory:
            with self.assertRaises(RuntimeError) as failure:
                FixedHTTPTransport('fake-github', 'fake-oauth')('GET', SOURCE_URL, deadline=deadline)
        self.assertNotIn('private-sentinel', str(failure.exception))
        handlers = factory.call_args.args
        self.assertEqual(next(h for h in handlers if isinstance(h, ProxyHandler)).proxies, {})
        redirect = next(h for h in handlers if isinstance(h, HTTPRedirectHandler))
        self.assertIsNone(redirect.redirect_request(None, None, 302, '', {}, 'https://example.invalid'))


if __name__ == '__main__':
    unittest.main()
