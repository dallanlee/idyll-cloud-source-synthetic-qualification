"""Local candidate for a fixed, bounded ClickUp read inside a controlled runner.

No entrypoint, environment access, dispatch, scheduler or automatic recovery.
A separately reviewed caller must bind accepted manifests to provider metadata.
The public service boundary requires an atomic durable claim implementation.
"""
import re
import json
from datetime import datetime, timezone

CONTRACT = 'idyll-cloud-q-v1'
REPOSITORY_ID = 1402638368
# Public preparation is inert until a dedicated synthetic source is reviewed.
# This literal is deliberately not controlled by environment variables or input.
SOURCE_CONFIGURED = False
TASK_ID = 'synthetic-task-unconfigured'
WORKSPACE_ID = 'synthetic-workspace-unconfigured'
LIST_ID = 'synthetic-list-unconfigured'
SOURCE_MARKER = 'synthetic-only-r1'
EXPECTED_REVISION = '0'
EXPECTED_DESCRIPTION = ('Synthetic history fixture only. Request '
    'idyll-cloud-q-synthetic-fixture-01; contract idyll-cloud-q-v1; '
    'revision synthetic-only-r1.')


def instant(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timezone required')
    return result


def claim_metadata(value):
    return (isinstance(value, dict)
            and set(value) == {'occurrence_id', 'source_sha', 'run_id', 'attempt'}
            and isinstance(value['occurrence_id'], str)
            and re.fullmatch(r'idyll-cloud-q-[a-z0-9-]{1,100}', value['occurrence_id']) is not None
            and isinstance(value['source_sha'], str)
            and re.fullmatch(r'[0-9a-f]{40}', value['source_sha']) is not None
            and isinstance(value['run_id'], str)
            and re.fullmatch(r'[0-9]{1,30}', value['run_id']) is not None
            and type(value['attempt']) is int and 1 <= value['attempt'] <= 1000)


def execute(manifest, service, *, now):
    """Return evidence; an uncertain claim/read is never retried automatically.

    `service` is the external provider boundary, not a source URL from input.
    Live dispatch/credential binding and independent termination are unqualified.
    """
    result = {'contract': CONTRACT, 'source_action_count': 0,
              'source_attempt_count': 0, 'automatic_retry_allowed': False}
    def finish(outcome):
        return dict(result, outcome=outcome)
    try:
        if (set(manifest) != {'contract', 'occurrence_id', 'due_at', 'cutoff_at',
                              'source_sha', 'run_id', 'attempt'}
                or manifest['contract'] != CONTRACT
                or not isinstance(manifest['due_at'], str)
                or not isinstance(manifest['cutoff_at'], str)
                or not re.fullmatch(r'idyll-cloud-q-[a-z0-9-]{1,100}', manifest['occurrence_id'])
                or not re.fullmatch(r'[0-9a-f]{40}', manifest['source_sha'])
                or not re.fullmatch(r'[0-9]{1,30}', manifest['run_id'])
                or type(manifest['attempt']) is not int or not 1 <= manifest['attempt'] <= 1000):
            return finish('INVALID_MANIFEST')
        try:
            due, cutoff = instant(manifest['due_at']), instant(manifest['cutoff_at'])
        except (ValueError, TypeError, AttributeError):
            return finish('INVALID_MANIFEST')
        if not 0 < (cutoff - due).total_seconds() <= 120:
            return finish('INVALID_MANIFEST')
        result.update({key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
        def in_window():
            current = now()
            if current.tzinfo is None:
                raise ValueError('Timezone required')
            return due <= current <= cutoff
        if not in_window():
            return finish('OUT_OF_WINDOW')
        if service.repository_identity() != {'id': REPOSITORY_ID, 'private': False}:
            return finish('WRONG_REPOSITORY')
        revoked = service.revoked()
        if type(revoked) is not bool:
            return finish('UNKNOWN_CONTROL_RESULT')
        if revoked:
            return finish('REVOKED')
        claimed = service.claim(manifest)
        result['claim'] = getattr(service, 'claim_receipt', None)
        if type(claimed) is not bool:
            return finish('UNKNOWN_CONTROL_RESULT')
        if not claimed:
            return finish('ALREADY_CLAIMED')
        revoked = service.revoked()
        if type(revoked) is not bool:
            return finish('UNKNOWN_CONTROL_RESULT')
        if revoked:
            return finish('REVOKED')
        if not in_window():
            return finish('OUT_OF_WINDOW')
        started = now()
        if not due <= started <= cutoff:
            return finish('OUT_OF_WINDOW')
        result['source_attempt_count'] = 1
        result['source_action_count'] = None  # unknown until the source replies
        task = service.read_fixture(deadline=cutoff)
        completed = now()
        result['source_action_count'] = 1
        result['receipt'] = {
            'source_object': TASK_ID, 'source_marker': None,
            'started_at': started.isoformat(), 'completed_at': completed.isoformat(),
        }
        if not started <= completed <= cutoff:
            return finish('OUT_OF_WINDOW')
        if (task.get('id') != TASK_ID or str(task.get('team_id')) != WORKSPACE_ID
                or task.get('list', {}).get('id') != LIST_ID
                or task.get('date_updated') != EXPECTED_REVISION
                or task.get('description') != EXPECTED_DESCRIPTION):
            return finish('SOURCE_MISMATCH')
        result['receipt']['source_marker'] = SOURCE_MARKER
        return finish('SOURCE_MATCH')
    except (KeyError, TypeError, ValueError, AttributeError):
        if result['source_attempt_count']:
            return finish('UNKNOWN_SOURCE_RESULT' if result['source_action_count'] is None else 'INVALID_SOURCE_EVIDENCE')
        return finish('INVALID_EVIDENCE')
    except Exception:
        # Do not echo errors, response bodies, credential values or source text.
        return finish('UNKNOWN_SOURCE_RESULT' if result['source_attempt_count'] else 'UNKNOWN_CONTROL_RESULT')


class FixedSourceServices:
    """Candidate API adapter. Credentials belong to the transport, not manifests."""
    REPO_URL = 'https://api.github.com/repos/dallanlee/idyll-cloud-source-synthetic-qualification'
    SOURCE_URL = 'https://api.clickup.com/api/v2/task/synthetic-task-unconfigured'
    STOP_REF = 'refs/tags/idyll-cloud-q-stop-v1'

    def __init__(self, transport):
        self.transport = transport
        self.claim_receipt = None

    def read_fixture(self, *, deadline):
        status, task = self.transport('GET', self.SOURCE_URL, deadline=deadline)
        if status != 200 or not isinstance(task, dict):
            raise RuntimeError('Unknown source result')
        return task

    def repository_identity(self):
        status, repo = self.transport('GET', self.REPO_URL)
        if status != 200 or not isinstance(repo, dict):
            raise RuntimeError('Unknown repository identity')
        return {'id': repo.get('id'), 'private': repo.get('private')}

    def revoked(self):
        status, value = self.transport('GET', self.REPO_URL + '/git/ref/' + self.STOP_REF[5:])
        if status == 404:
            # A missing ref alone does not establish verified contents access.
            known, reference = self.transport('GET', self.REPO_URL + '/git/ref/heads/codex/qualification')
            if (known == 200 and isinstance(reference, dict)
                    and reference.get('ref') == 'refs/heads/codex/qualification'
                    and reference.get('object', {}).get('type') == 'commit'):
                return False
            raise RuntimeError('Unverified contents access')
        if status == 200 and isinstance(value, dict) and value.get('ref') == self.STOP_REF:
            return True
        raise RuntimeError('Unknown revocation state')

    def claim(self, manifest):
        metadata = {key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')}
        if not claim_metadata(metadata):
            raise ValueError('Invalid claim identity')
        name = 'idyll-cloud-q-occurrence/' + metadata['occurrence_id']
        ref = 'refs/tags/' + name
        message = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
        status, tag = self.transport('POST', self.REPO_URL + '/git/tags',
            {'tag': name, 'message': message, 'object': metadata['source_sha'], 'type': 'commit'})
        if (status != 201 or not isinstance(tag, dict)
                or not isinstance(tag.get('sha'), str)
                or not re.fullmatch(r'[0-9a-f]{40}', tag['sha'])
                or tag.get('tag') != name or tag.get('message') != message
                or tag.get('object', {}).get('sha') != metadata['source_sha']
                or tag.get('object', {}).get('type') != 'commit'):
            raise RuntimeError('Unknown claim annotation')
        tag_sha = tag['sha']
        status, value = self.transport('POST', self.REPO_URL + '/git/refs',
                                       {'ref': ref, 'sha': tag_sha})
        if status == 201:
            if (isinstance(value, dict) and value.get('ref') == ref
                    and value.get('object', {}).get('sha') == tag_sha
                    and value.get('object', {}).get('type') == 'tag'):
                self.claim_receipt = dict(metadata, ref=ref, tag_sha=tag_sha)
                return True
            raise RuntimeError('Unknown claim result')
        if status in (409, 422):
            try:
                found, existing = self.transport('GET', self.REPO_URL + '/git/ref/' + ref[5:])
                if (found == 200 and isinstance(existing, dict) and existing.get('ref') == ref
                        and existing.get('object', {}).get('type') == 'tag'):
                    existing_sha = existing['object'].get('sha')
                    if not isinstance(existing_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', existing_sha):
                        raise RuntimeError('Unknown prior claim')
                    found, annotation = self.transport('GET', self.REPO_URL + '/git/tags/' + existing_sha)
                    owner = json.loads(annotation['message']) if found == 200 else None
                    if (not claim_metadata(owner) or owner['occurrence_id'] != metadata['occurrence_id']
                            or annotation.get('sha') != existing_sha or annotation.get('tag') != name
                            or annotation.get('object', {}).get('type') != 'commit'
                            or annotation.get('object', {}).get('sha') != owner['source_sha']):
                        raise RuntimeError('Unknown prior claim owner')
                    # Reconciliation must cross-check this attribution with run history.
                    self.claim_receipt = dict(owner, ref=ref, tag_sha=existing_sha)
                    return False  # never overwrite/release/resume even an own lost-reply claim
            except (KeyError, TypeError, ValueError, AttributeError):
                raise RuntimeError('Unknown prior claim owner') from None
        raise RuntimeError('Unknown claim result')


class ProtectedTransport:
    """Fixed HTTPS endpoints, no redirects/retries/proxies or response logging.

    This restricts this code's requests; it does not narrow credential authority.
    No credential is loaded by import or stored in a manifest/receipt.
    """
    def __init__(self, github_token, clickup_oauth_token):
        for token in (github_token, clickup_oauth_token):
            if not isinstance(token, str) or not token or len(token) > 4096 or any(c.isspace() for c in token):
                raise ValueError('Invalid credential')
        if clickup_oauth_token.startswith('pk_'):
            raise ValueError('A reviewed OAuth connection is required')
        self.github_token = github_token
        self.clickup_token = clickup_oauth_token

    def __call__(self, method, url, body=None, *, deadline=None):
        if url == FixedSourceServices.SOURCE_URL and not SOURCE_CONFIGURED:
            raise ValueError('Synthetic source is not configured')
        import json
        from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
        from urllib.error import HTTPError
        repo = FixedSourceServices.REPO_URL
        claim_ref = r'refs/tags/idyll-cloud-q-occurrence/idyll-cloud-q-[a-z0-9-]{1,100}'
        allowed = False
        if method == 'GET' and body is None:
            allowed = (url in (repo, FixedSourceServices.SOURCE_URL,
                               repo + '/git/ref/tags/idyll-cloud-q-stop-v1',
                               repo + '/git/ref/heads/codex/qualification')
                       or re.fullmatch(re.escape(repo + '/git/ref/') + claim_ref[5:], url) is not None
                       or re.fullmatch(re.escape(repo + '/git/tags/') + r'[0-9a-f]{40}', url) is not None)
        if method == 'POST' and url == repo + '/git/refs' and isinstance(body, dict):
            allowed = (set(body) == {'ref', 'sha'} and isinstance(body.get('ref'), str)
                       and re.fullmatch(claim_ref, body['ref']) is not None
                       and isinstance(body.get('sha'), str)
                       and re.fullmatch(r'[0-9a-f]{40}', body['sha']) is not None)
        if method == 'POST' and url == repo + '/git/tags' and isinstance(body, dict):
            try:
                metadata = json.loads(body['message'])
                allowed = (set(body) == {'tag', 'message', 'object', 'type'}
                           and claim_metadata(metadata) and len(body['message']) <= 512
                           and body['message'] == json.dumps(metadata, sort_keys=True, separators=(',', ':'))
                           and isinstance(body['tag'], str)
                           and body['tag'] == 'idyll-cloud-q-occurrence/' + metadata['occurrence_id']
                           and body['object'] == metadata['source_sha'] and body['type'] == 'commit')
            except (KeyError, TypeError, ValueError):
                allowed = False
        if not allowed:
            raise ValueError('Request outside allowlist')
        token = self.clickup_token if url == FixedSourceServices.SOURCE_URL else self.github_token
        headers = {'Authorization': 'Bearer ' + token, 'User-Agent': 'idyll-cloud-q-v1',
                   'Accept': 'application/json'}
        if url != FixedSourceServices.SOURCE_URL:
            headers.update({'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10'})
        data = None if body is None else json.dumps(body).encode('utf-8')
        if data is not None:
            headers['Content-Type'] = 'application/json'
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = build_opener(ProxyHandler({}), NoRedirect())
        source_request = url == FixedSourceServices.SOURCE_URL
        alarm_installed = False
        try:
            timeout = 8
            if source_request:
                import signal
                import threading
                if (not isinstance(deadline, datetime) or deadline.tzinfo is None
                        or threading.current_thread() is not threading.main_thread()):
                    raise ValueError('A qualified source deadline is required')
                remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
                if remaining <= 0 or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
                    raise ValueError('Source deadline unavailable')
                previous_handler = signal.getsignal(signal.SIGALRM)
                def expired(signum, frame):
                    raise TimeoutError('Source deadline expired')
                signal.signal(signal.SIGALRM, expired)
                alarm_installed = True
                # Bounds connect, TLS, headers and body after name resolution.
                # Blocking DNS resolution and provider-side cessation remain unqualified.
                signal.setitimer(signal.ITIMER_REAL, remaining)
                timeout = min(8, remaining)  # never extend a short remaining window
            try:
                response = opener.open(Request(url, data=data, headers=headers, method=method), timeout=timeout)
            except HTTPError as error:
                response = error  # never follow/echo Location or error body
            with response:
                status = response.status
                raw = response.read(262145)
            if alarm_installed:
                signal.setitimer(signal.ITIMER_REAL, 0)
            if (len(raw) > 262144 or 300 <= status < 400
                    or source_request and datetime.now(timezone.utc) > deadline):
                raise ValueError('Unusable response')
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError('Unusable response')
            return status, payload
        except Exception:
            raise RuntimeError('Unusable provider response') from None
        finally:
            if alarm_installed:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_handler)
