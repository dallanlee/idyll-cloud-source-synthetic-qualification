"""One-use OAuth consumer for the dedicated synthetic Workspace.

The production runtime remains disabled until the protected storage route has
independent review and native positive/negative approval evidence. No credential
belongs in command arguments, environment variables, logs or evidence files.
"""
import argparse
import getpass
import http.client
import json
import re
from http.server import HTTPServer
from prepare_clickup_oauth import (HOST, PORT, ORIGIN, WORKSPACE_ID, WORKSPACE_NAME,
                                  Landing, handler_for)


class ConnectionRefused(ValueError):
    """A safe, credential-free failure description."""


def verify_workspace(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('teams'), list):
        raise ConnectionRefused('Workspace response refused')
    teams = payload['teams']
    if (len(teams) != 1 or not isinstance(teams[0], dict)
            or teams[0].get('id') != WORKSPACE_ID
            or teams[0].get('name') != WORKSPACE_NAME):
        raise ConnectionRefused('Sole synthetic Workspace not verified; token discarded')
    return WORKSPACE_ID


class Consumer:
    """Single attempt across public provider and protected-storage boundaries."""
    def __init__(self, client_id, api, storage):
        self.client_id = client_id
        self.api = api
        self.storage = storage
        self.used = False

    def connect(self, code, client_secret):
        if self.used:
            raise ConnectionRefused('Connection attempt already consumed')
        self.used = True
        token = None
        try:
            self.storage.ready()
            token = self.api.exchange(self.client_id, client_secret, code)
            verify_workspace(self.api.workspaces(token))
            self.storage.ready()
            self.storage.store(token)
            return 'connected'
        except ConnectionRefused:
            raise
        except Exception:
            raise ConnectionRefused('Connection failed or outcome uncertain; inspect before retry') from None
        finally:
            token = code = client_secret = None


def credential(value):
    if not isinstance(value, str) or not re.fullmatch(r'[\x21-\x7e]{1,4000}', value):
        raise ConnectionRefused('Invalid credential format')
    return value


class ClickUpApi:
    """Only token exchange and authorized-Workspace verification; no redirects."""
    def __init__(self, *, connection_factory=http.client.HTTPSConnection):
        self.connection_factory = connection_factory

    def request(self, method, path, *, body=None, token=None):
        if (method, path) not in {('POST', '/api/v2/oauth/token'), ('GET', '/api/v2/team')}:
            raise ConnectionRefused('Request outside connection allowlist')
        headers = {'Accept': 'application/json'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(body).encode('ascii')
        if token is not None:
            headers['Authorization'] = credential(token)
        connection = self.connection_factory('api.clickup.com', timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            content_types = [value.split(';', 1)[0].strip().lower()
                             for name, value in response.getheaders() if name.lower() == 'content-type']
            if response.status != 200 or content_types != ['application/json']:
                raise ConnectionRefused('Provider response refused; no redirect followed')
            data = response.read(65537)
            if len(data) > 65536:
                raise ConnectionRefused('Provider response too large')
            return json.loads(data.decode('utf-8'))
        except ConnectionRefused:
            raise
        except Exception:
            raise ConnectionRefused('Provider request failed or outcome uncertain; no automatic retry') from None
        finally:
            connection.close()

    def exchange(self, client_id, client_secret, code):
        payload = self.request('POST', '/api/v2/oauth/token', body={
            'client_id': credential(client_id), 'client_secret': credential(client_secret),
            'code': credential(code)})
        if not isinstance(payload, dict):
            raise ConnectionRefused('Token response refused')
        return credential(payload.get('access_token'))

    def workspaces(self, token):
        return self.request('GET', '/api/v2/team', token=token)


class ConnectionLanding(Landing):
    def __init__(self, client_id, consumer, client_secret, **options):
        super().__init__(client_id, **options)
        self.consumer = consumer
        self.client_secret = client_secret
        self.done_message = ('<h1>Synthetic connection preparation</h1>'
                             '<p>Authorization has not returned.</p>')
        self.start_message = ('<p>After consent, this one-use handler exchanges the code, '
            'verifies that exactly the named synthetic Workspace is authorized, then stores '
            'the token in GitHub environment qualification-source. It does not read a task '
            'or dispatch a source workflow. The app secret stays in this process.</p>')

    def callback(self, query, *, host):
        super().callback(query, host=host)
        try:
            self.consumer.connect(self._authorization_code, self.client_secret)
            self.done_message = ('<h1>Synthetic Workspace connection stored</h1>'
                '<p>The sole authorized Workspace was verified and the token was uploaded '
                'to the protected GitHub environment. Metadata confirms the secret name, '
                'not its stored value. No task read or source dispatch ran.</p>')
        except Exception:
            self.done_message = ('<h1>Connection stopped</h1>'
                '<p>Verification failed or the outcome is uncertain. No automatic retry '
                'will run. Inspect ClickUp authorization and GitHub secret metadata '
                'before attempting another connection.</p>')
        finally:
            self._authorization_code = self.client_secret = None

    def clear(self):
        self.client_secret = None
        super().clear()


def main(argv=None):
    from protected_oauth_storage import GitHubStorage
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-id', required=True, help='Public client ID only')
    parser.add_argument('--accepted-sha', required=True)
    parser.add_argument('--negative-run', required=True)
    parser.add_argument('--positive-run', required=True)
    args = parser.parse_args(argv)
    # Refuse missing native evidence before asking the human for any credential.
    storage = GitHubStorage(args.accepted_sha, args.negative_run, args.positive_run)
    storage.ready()
    # getpass must have a real terminal; never fall back to echoed stdin.
    import sys
    if not sys.stdin.isatty():
        raise ConnectionRefused('Human terminal credential entry required')
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            client_secret = credential(getpass.getpass('New ClickUp app secret (hidden; never chat): '))
        except getpass.GetPassWarning:
            raise ConnectionRefused('Hidden credential entry unavailable; no echoed fallback allowed') from None
    landing = ConnectionLanding(args.client_id, Consumer(args.client_id, ClickUpApi(), storage), client_secret)
    client_secret = None
    with HTTPServer((HOST, PORT), handler_for(landing)) as server:
        server.timeout = 1
        print('Synthetic connection ready at ' + ORIGIN + '; expires in 10 minutes.', flush=True)
        try:
            while landing.active():
                server.handle_request()
        except KeyboardInterrupt:
            pass
        finally:
            landing.clear()
    print('Connection handler closed; credential references released.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except ConnectionRefused as error:
        print(str(error))
        raise SystemExit(1) from None
