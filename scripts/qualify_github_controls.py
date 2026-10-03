"""Finite control probe of this synthetic repository; no source access or retry."""
import json
import os
import re
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

REPOSITORY = 'dallanlee/idyll-cloud-source-synthetic-qualification'
REPOSITORY_ID = '1402638368'
API = 'https://api.github.com/repos/' + REPOSITORY


def main():
    receipt = {'source_attempt_count': 0, 'automatic_retry_allowed': False,
               'outcome': 'CONTROL_PROBE_BLOCKED'}
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    code_sha = os.environ.get('GITHUB_SHA', '')
    if (os.environ.get('GITHUB_REPOSITORY') != REPOSITORY
            or os.environ.get('GITHUB_REPOSITORY_ID') != REPOSITORY_ID
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('GITHUB_REF') != 'refs/heads/codex/qualification'
            or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'
            or not re.fullmatch(r'[0-9]{1,30}', run_id)
            or not re.fullmatch(r'[0-9a-f]{40}', code_sha)
            or os.environ.get('QUAL_CONTROLS_ACCEPTED_CODE_SHA') != code_sha):
        print(json.dumps(receipt, sort_keys=True))
        return 2
    try:
        token = os.environ.pop('GH_TOKEN')
        if not token or len(token) > 4096 or any(c.isspace() for c in token):
            raise ValueError('Invalid credential')
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = build_opener(ProxyHandler({}), NoRedirect())
        def request(method, path, body=None):
            # Every path below is fixed code plus validated run/SHA identifiers.
            headers = {'Authorization': 'Bearer ' + token,
                       'Accept': 'application/vnd.github+json',
                       'X-GitHub-Api-Version': '2026-03-10',
                       'User-Agent': 'idyll-cloud-q-control-probe'}
            data = None if body is None else json.dumps(body).encode()
            if data is not None:
                headers['Content-Type'] = 'application/json'
            try:
                response = opener.open(Request(API + path, data=data,
                                               headers=headers, method=method), timeout=8)
            except HTTPError as error:
                response = error
            with response:
                status, raw = response.status, response.read(262145)
            if len(raw) > 262144 or 300 <= status < 400:
                raise ValueError('Unusable response')
            return status, json.loads(raw) if raw else {}
        status, repo = request('GET', '')
        if status != 200 or repo.get('id') != int(REPOSITORY_ID) or repo.get('private') is not False:
            raise ValueError('Wrong repository')
        status, commit = request('GET', '/git/commits/' + code_sha)
        if status != 200 or commit.get('sha') != code_sha:
            raise ValueError('Unknown commit')
        stop_before, _ = request('GET', '/git/ref/tags/idyll-cloud-q-stop-v1')
        branch_before, before_ref = request('GET', '/git/ref/heads/codex/qualification')
        if (stop_before != 404 or branch_before != 200
                or before_ref.get('ref') != 'refs/heads/codex/qualification'
                or before_ref.get('object', {}).get('type') != 'commit'
                or before_ref['object'].get('sha') != code_sha):
            raise ValueError('Unsafe probe preconditions')
        status, alternate = request('POST', '/git/commits', {
            'message': 'Synthetic object for forbidden-ref-update proof',
            'tree': commit['tree']['sha'], 'parents': [code_sha]})
        if status != 201 or not re.fullmatch(r'[0-9a-f]{40}', alternate.get('sha', '')):
            raise ValueError('Unknown synthetic commit')
        occurrence = 'idyll-cloud-q-control-proof-' + run_id
        tag = 'idyll-cloud-q-occurrence/' + occurrence
        metadata = {'occurrence_id': occurrence, 'source_sha': code_sha,
                    'run_id': run_id, 'attempt': 1}
        message = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
        status, annotation = request('POST', '/git/tags', {
            'tag': tag, 'message': message, 'object': code_sha, 'type': 'commit'})
        if status != 201 or not re.fullmatch(r'[0-9a-f]{40}', annotation.get('sha', '')):
            raise ValueError('Unknown synthetic annotation')
        ref = 'refs/tags/' + tag
        claim_body = {'ref': ref, 'sha': annotation['sha']}
        created, _ = request('POST', '/git/refs', claim_body)
        if created != 201:
            raise ValueError('Claim not acquired; no retry')
        duplicate, _ = request('POST', '/git/refs', claim_body)
        found, reference = request('GET', '/git/ref/tags/' + tag)
        read_status, reread = request('GET', '/git/tags/' + annotation['sha'])
        update, _ = request('PATCH', '/git/refs/tags/' + tag,
                            {'sha': alternate['sha'], 'force': True})
        deletion, _ = request('DELETE', '/git/refs/tags/' + tag)
        stop_creation, _ = request('POST', '/git/refs',
                                   {'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'sha': code_sha})
        code_update, _ = request('PATCH', '/git/refs/heads/codex/qualification',
                                 {'sha': alternate['sha'], 'force': False})
        retained, final_ref = request('GET', '/git/ref/tags/' + tag)
        stop_after, _ = request('GET', '/git/ref/tags/idyll-cloud-q-stop-v1')
        branch_after, after_ref = request('GET', '/git/ref/heads/codex/qualification')
        checks = {
            'annotation_exact': annotation.get('message') == message,
            'duplicate_ref_refused': duplicate == 422,
            'claim_readback': found == 200 and read_status == 200
                and reference.get('object', {}).get('sha') == annotation['sha']
                and reread.get('message') == message,
            'claim_update_refused': update == 422,
            'claim_delete_refused': deletion == 422,
            'stop_creation_refused': stop_creation == 422,
            'code_update_refused': code_update == 422,
            'claim_retained': retained == 200 and final_ref == reference,
            'stop_remains_absent': stop_after == 404,
            'code_branch_unchanged': branch_after == 200 and after_ref == before_ref,
        }
        receipt.update(metadata, ref=ref, checks=checks,
                       annotation_echo={'exact': annotation.get('message') == message,
                                        'one_trailing_newline': annotation.get('message') == message + '\n'},
                       statuses={'duplicate': duplicate, 'claim_update': update,
                                 'claim_delete': deletion, 'stop_create': stop_creation,
                                 'code_update': code_update},
                       outcome='CONTROL_PROBE_PASS' if all(checks.values()) else 'CONTROL_PROBE_FAILED')
    except Exception:
        # Never print provider response bodies, errors, or the token.
        receipt['outcome'] = 'UNKNOWN_CONTROL_RESULT'
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['outcome'] == 'CONTROL_PROBE_PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
