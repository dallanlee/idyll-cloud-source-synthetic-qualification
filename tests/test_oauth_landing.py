"""Boundary tests for preparation; no ClickUp or GitHub request is made."""
import importlib.util
from http.client import HTTPConnection
from http.server import HTTPServer
from pathlib import Path
from threading import Thread
import unittest
from urllib.parse import urlencode, urlsplit, parse_qs

SPEC = importlib.util.spec_from_file_location('oauth_landing', Path(__file__).parents[1] / 'scripts/prepare_clickup_oauth.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class LandingTests(unittest.TestCase):
    def setUp(self):
        self.clock = 100
        self.landing = module.Landing('public-synthetic-client', now=lambda: self.clock)
        self.body = urlencode({'csrf': self.landing.csrf, 'scope': module.WORKSPACE_ID})

    def start(self, body=None, **overrides):
        return self.landing.begin(self.body if body is None else body,
            **dict({'host':'127.0.0.1:8768','origin':module.ORIGIN}, **overrides))

    def test_authorization_destination_and_callback_are_fixed(self):
        result = urlsplit(self.start())
        self.assertEqual((result.scheme, result.netloc, result.path), ('https','app.clickup.com','/api'))
        self.assertEqual(parse_qs(result.query), {'client_id':['public-synthetic-client'],
            'redirect_uri':[module.REDIRECT_URI], 'state':[self.landing.state]})

    def test_foreign_host_origin_and_csrf_cannot_start_authorization(self):
        for changes in ({'host':'attacker.invalid:8768'}, {'origin':'https://attacker.invalid'},
                        {'origin':None}, {'origin':'null'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.start(**changes)
        with self.assertRaises(ValueError): self.start(urlencode({'csrf':'wrong', 'scope':module.WORKSPACE_ID}))
        self.assertFalse(self.landing.begun)

    def test_other_workspace_and_duplicate_parameters_cannot_start(self):
        with self.assertRaises(ValueError): self.start(urlencode({'csrf':self.landing.csrf,'scope':'other'}))
        with self.assertRaises(ValueError): self.start(self.body + '&scope=' + module.WORKSPACE_ID)

    def test_callback_requires_started_state_and_refuses_replay(self):
        query = urlencode({'code':'synthetic-code', 'state':self.landing.state})
        with self.assertRaises(ValueError): self.landing.callback(query, host='127.0.0.1:8768')
        self.start()
        self.landing.callback(query, host='127.0.0.1:8768')
        with self.assertRaises(ValueError): self.landing.callback(query, host='127.0.0.1:8768')
        self.landing.clear()
        self.assertIsNone(self.landing._authorization_code)

    def test_wrong_state_host_and_duplicate_codes_are_rejected(self):
        self.start()
        for query, host in ((urlencode({'code':'fake','state':'wrong'}),'127.0.0.1:8768'),
            (urlencode({'code':'fake','state':self.landing.state}),'attacker.invalid'),
            (urlencode({'code':'fake','state':self.landing.state})+'&code=second','127.0.0.1:8768')):
            with self.subTest(host=host), self.assertRaises(ValueError): self.landing.callback(query, host=host)
        self.assertIsNone(self.landing._authorization_code)

    def test_expired_start_or_callback_is_rejected(self):
        self.clock += 600
        with self.assertRaises(ValueError): self.start()
        self.clock -= 600
        self.start()
        self.clock += 600
        with self.assertRaises(ValueError): self.landing.callback(urlencode({'code':'fake','state':self.landing.state}), host='127.0.0.1:8768')

    def test_code_newlines_and_unexpected_fields_are_rejected(self):
        self.start()
        for values in ({'code':'fake\r\nheader','state':self.landing.state},
                       {'code':'fake','state':self.landing.state,'token':'fake-token'}):
            with self.assertRaises(ValueError): self.landing.callback(urlencode(values), host='127.0.0.1:8768')

    def test_unicode_state_is_rejected_with_no_credential_capture(self):
        with self.assertRaises(ValueError): self.start(urlencode({'csrf':'\u00e9', 'scope':module.WORKSPACE_ID}))
        self.start()
        with self.assertRaises(ValueError): self.landing.callback(urlencode({'code':'fake','state':'\u00e9'}), host='127.0.0.1:8768')
        self.assertIsNone(self.landing._authorization_code)


class LandingHttpTests(unittest.TestCase):
    """Exercise actual HTTP headers and form guards; never follow provider redirects."""

    def setUp(self):
        self.old_port, self.old_origin = module.PORT, module.ORIGIN
        self.landing = module.Landing('public-synthetic-client')
        self.server = HTTPServer((module.HOST, 0), module.handler_for(self.landing))
        module.PORT = self.server.server_port
        module.ORIGIN = f'http://{module.HOST}:{module.PORT}'
        self.thread = Thread(target=self.server.serve_forever, kwargs={'poll_interval':0.05})
        self.thread.start()
        self.body = urlencode({'csrf':self.landing.csrf, 'scope':module.WORKSPACE_ID})

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        module.PORT, module.ORIGIN = self.old_port, self.old_origin

    def request(self, method, path, *, origin=None, body=None):
        connection = HTTPConnection(module.HOST, module.PORT, timeout=2)
        headers = {}
        if method == 'POST': headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if origin is not None: headers['Origin'] = origin
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def test_loopback_form_keeps_browser_origin_without_cross_origin_referrers(self):
        status, headers, body = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertIn('form-action', headers['Content-Security-Policy'])
        self.assertIn('method="post"', body)

    def test_missing_null_and_foreign_origins_still_refuse_start(self):
        for origin in (None, 'null', 'https://attacker.invalid'):
            with self.subTest(origin=origin):
                status, headers, _ = self.request('POST', '/begin', origin=origin, body=self.body)
                self.assertEqual(status, 400)
                self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
                self.assertFalse(self.landing.begun)

    def test_redirect_callback_and_done_keep_no_referrer(self):
        status, headers, _ = self.request('POST', '/begin', origin=module.ORIGIN, body=self.body)
        self.assertEqual(status, 303)
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(urlsplit(headers['Location']).netloc, 'app.clickup.com')
        query = urlencode({'code':'synthetic-code', 'state':self.landing.state})
        status, headers, _ = self.request('GET', '/oauth/callback?' + query)
        self.assertEqual((status, headers['Location']), (303, '/done'))
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        status, headers, _ = self.request('GET', '/done')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')

    def test_csrf_guard_and_error_responses_are_unchanged(self):
        invalid = urlencode({'csrf':'wrong', 'scope':module.WORKSPACE_ID})
        status, headers, _ = self.request('POST', '/begin', origin=module.ORIGIN, body=invalid)
        self.assertEqual(status, 400)
        self.assertFalse(self.landing.begun)
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        status, headers, _ = self.request('GET', '/missing')
        self.assertEqual(status, 404)
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')


if __name__ == '__main__': unittest.main()
