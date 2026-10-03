"""Boundary tests for preparation; no ClickUp or GitHub request is made."""
import importlib.util
from pathlib import Path
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
        for changes in ({'host':'attacker.invalid:8768'}, {'origin':'https://attacker.invalid'}):
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


if __name__ == '__main__': unittest.main()
