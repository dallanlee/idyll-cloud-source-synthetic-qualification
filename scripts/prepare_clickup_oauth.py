"""One-use, loopback-only OAuth landing page; no token exchange or source read.

Run only after the separately approved ClickUp app exists. A human authorizes
only the synthetic Workspace on ClickUp. The returned code stays in RAM;
there is deliberately no HTTP or CLI endpoint that exports it. Using it in
another integration requires its own reviewed consumer and approved scope.
"""
import argparse
import html
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

HOST = '127.0.0.1'
PORT = 8768
ORIGIN = f'http://{HOST}:{PORT}'
REDIRECT_URI = ORIGIN + '/oauth/callback'
WORKSPACE_NAME = 'Idyll Cloud Qualification — Synthetic Only'
WORKSPACE_ID = '90141728025'
APP_NAME = 'Idyll Synthetic Source Qualification'


class Landing:
    def __init__(self, client_id, *, now=time.monotonic):
        if not isinstance(client_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,200}', client_id):
            raise ValueError('Invalid public client ID')
        self.client_id = client_id
        self.now = now
        self.expires = now() + 600
        self.csrf = secrets.token_urlsafe(32)
        self.state = secrets.token_urlsafe(32)
        self.begun = False
        self.consumed = False
        self._authorization_code = None

    def active(self):
        return self.now() < self.expires

    def begin(self, body, *, origin, host):
        if host != f'{HOST}:{PORT}' or origin != ORIGIN or not self.active() or self.begun:
            raise ValueError('Authorization start refused')
        values = parse_qs(body, strict_parsing=True, keep_blank_values=True, max_num_fields=2)
        if set(values) != {'csrf', 'scope'} or any(len(v) != 1 for v in values.values()):
            raise ValueError('Invalid authorization start')
        if (not secrets.compare_digest(values['csrf'][0], self.csrf)
                or values['scope'][0] != WORKSPACE_ID):
            raise ValueError('Authorization scope refused')
        self.begun = True
        return 'https://app.clickup.com/api?' + urlencode({
            'client_id': self.client_id, 'redirect_uri': REDIRECT_URI, 'state': self.state})

    def callback(self, query, *, host):
        if host != f'{HOST}:{PORT}' or not self.active() or not self.begun or self.consumed:
            raise ValueError('Authorization return refused')
        values = parse_qs(query, strict_parsing=True, keep_blank_values=True, max_num_fields=3)
        if set(values) != {'code', 'state'} or any(len(v) != 1 for v in values.values()):
            raise ValueError('Invalid authorization return')
        if (not secrets.compare_digest(values['state'][0], self.state)
                or not re.fullmatch(r'[A-Za-z0-9_.~+-]{1,2000}', values['code'][0])):
            raise ValueError('Authorization return refused')
        self.consumed = True
        self._authorization_code = values['code'][0]

    def clear(self):
        self._authorization_code = None
        self.csrf = self.state = ''
        self.consumed = True


def handler_for(landing):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Never log paths, query strings, codes or state.

        def reply(self, status, body='', location=None):
            data = body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy',
                             "default-src 'none'; form-action 'self' https://app.clickup.com; frame-ancestors 'none'; base-uri 'none'")
            self.send_header('Connection', 'close')
            if location:
                self.send_header('Location', location)
            self.end_headers()
            self.wfile.write(data)

        def valid_host(self):
            return self.headers.get_all('Host') == [f'{HOST}:{PORT}']

        def do_GET(self):
            if not self.valid_host() or len(self.path) > 4096:
                return self.reply(400, 'Request refused.')
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.fragment:
                return self.reply(400, 'Request refused.')
            if parsed.path == '/oauth/callback':
                try:
                    landing.callback(parsed.query, host=self.headers['Host'])
                except (ValueError, UnicodeError):
                    return self.reply(400, 'Authorization return refused. No token exchange ran.')
                # Remove the credential-bearing query from the active address bar.
                return self.reply(303, location='/done')
            if parsed.query or not landing.active():
                return self.reply(400, 'Request refused or preparation expired.')
            if parsed.path == '/done' and landing.consumed:
                return self.reply(200, '<h1>Authorization return received</h1>'
                                  '<p>The code is held only in memory. No token exchange, '
                                  'GitHub secret upload, source read or workflow dispatch ran.</p>'
                                  '<p>Authorization selection is not verified by this landing page. '
                                  'A separately reviewed consumer must verify the sole authorized Workspace.</p>')
            if parsed.path == '/' and not landing.begun:
                return self.reply(200, '<h1>Prepare synthetic ClickUp authorization</h1>'
                    '<p>Select only <strong>' + html.escape(WORKSPACE_NAME) + '</strong> on ClickUp.</p>'
                    '<p>OAuth can grant writes inside that Workspace. This page does not enforce '
                    'the selection or prove read-only token scope. Do not select another Workspace.</p>'
                    '<p>This preparation only holds a one-use authorization return in RAM. '
                    'It cannot exchange it, export it, read a task or upload a secret.</p>'
                    '<form action="/begin" method="post">'
                    '<input type="hidden" name="csrf" value="' + landing.csrf + '">'
                    '<input type="hidden" name="scope" value="' + WORKSPACE_ID + '">'
                    '<button type="submit">Open ClickUp Workspace authorization</button></form>')
            return self.reply(404, 'Not found.')

        def do_POST(self):
            if (not self.valid_host() or self.path != '/begin'
                    or self.headers.get_all('Origin') != [ORIGIN]
                    or self.headers.get('Transfer-Encoding') is not None
                    or self.headers.get_content_type() != 'application/x-www-form-urlencoded'):
                return self.reply(400, 'Authorization start refused.')
            lengths = self.headers.get_all('Content-Length')
            if not lengths or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,4}', lengths[0]):
                return self.reply(400, 'Authorization start refused.')
            size = int(lengths[0])
            if not 0 < size <= 2048:
                return self.reply(400, 'Authorization start refused.')
            try:
                body = self.rfile.read(size).decode('ascii')
                location = landing.begin(body, origin=self.headers['Origin'], host=self.headers['Host'])
            except (ValueError, UnicodeError):
                return self.reply(400, 'Authorization start refused.')
            return self.reply(303, location=location)

        def setup(self):
            super().setup()
            self.connection.settimeout(2)

    return Handler


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-id', required=True, help='Public client ID; never a client secret')
    args = parser.parse_args(argv)
    landing = Landing(args.client_id)
    with HTTPServer((HOST, PORT), handler_for(landing)) as server:
        server.timeout = 1
        print('Loopback OAuth preparation ready at ' + ORIGIN + '; expires in 10 minutes.', flush=True)
        try:
            while landing.active():
                server.handle_request()
        except KeyboardInterrupt:
            pass
        finally:
            landing.clear()
    print('Preparation closed; in-memory authorization data cleared.', flush=True)


if __name__ == '__main__':
    main()
