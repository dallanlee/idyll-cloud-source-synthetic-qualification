"""Inactive fresh machine dispatcher, distinct from the protected reviewer."""
from source_observation import empty_receipt, validate_manifest, admit_environment, REPO_URL, BRANCH_REF

DISPATCH_CONFIGURED = True
CONTRACT = 'idyll-cloud-q-v1-case-dispatcher'
WORKFLOW_PATH = '.github/workflows/qualification-case-dispatcher.yml'
TARGETS = {'retained-stop': 'retained-stop-qualification.yml',
           'observation': 'source-observation-qualification.yml'}


def admit_dispatch(env, checkout_sha, *, now, configured=DISPATCH_CONFIGURED):
    try:
        number = env['GITHUB_RUN_NUMBER']
        if (not number.isascii() or not number.isdecimal() or not 1 <= int(number) <= 100000
                or env.get('QUAL_DISPATCH_APPROVED_RUN_NUMBER') != number
                or env.get('QUAL_DISPATCH_CASE') not in TARGETS):
            return None
        # The fresh dispatcher authority binds its known native run_number. Its
        # new run_id is subsequently verified against provider-native metadata.
        values = dict(env, QUAL_DISPATCH_APPROVED_RUN_ID=env['GITHUB_RUN_ID'])
        return admit_environment(values, checkout_sha, now=now, configured=configured,
                                 prefix='QUAL_DISPATCH_', contract=CONTRACT)
    except Exception:
        return None


def dispatch_case(manifest, transport, *, case, run_number, now, progress=lambda value: None):
    result = dict(empty_receipt('INVALID_MANIFEST'), contract=CONTRACT, dispatch_attempt_count=0)
    try:
        due, cutoff = validate_manifest(manifest, contract=CONTRACT)
        if case not in TARGETS or type(run_number) is not int or not 1 <= run_number <= 100000:
            raise ValueError('Finite dispatcher refused')
        result.update({key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
        def request(method, path, body=None):
            current = now()
            if current.tzinfo is None or not due <= current < cutoff:
                raise TimeoutError('Finite window expired')
            if result['github_attempt_count'] >= 4:
                raise ValueError('Dispatcher cap refused')
            result['github_attempt_count'] += 1
            result['github_action_count'] = None
            progress({key: result[key] for key in
                ('source_attempt_count', 'source_action_count', 'github_attempt_count', 'github_action_count')})
            response = transport(method, REPO_URL + path, body, deadline=cutoff)
            result['github_action_count'] = result['github_attempt_count']
            if not due <= now() < cutoff:
                raise TimeoutError('Finite window expired')
            return response
        result['outcome'] = 'AUTHORITY_REFUSED'
        status, repo = request('GET', '')
        if status != 200 or repo.get('id') != 1402638368 or repo.get('private') is not False:
            raise ValueError('Repository refused')
        status, branch = request('GET', '/git/ref/heads/codex/qualification')
        if (status != 200 or branch.get('ref') != BRANCH_REF
                or branch.get('object', {}).get('type') != 'commit'
                or branch['object'].get('sha') != manifest['source_sha']):
            raise ValueError('Exact branch refused')
        status, run = request('GET', '/actions/runs/' + manifest['run_id'])
        owner = {'id': 13070764, 'login': 'dallanlee', 'type': 'User'}
        if (status != 200 or type(run.get('id')) is not int or str(run['id']) != manifest['run_id']
                or run.get('repository', {}).get('id') != 1402638368
                or run.get('head_sha') != manifest['source_sha'] or run.get('head_branch') != 'codex/qualification'
                or run.get('event') != 'workflow_dispatch' or type(run.get('run_attempt')) is not int
                or run['run_attempt'] != 1 or type(run.get('run_number')) is not int
                or run['run_number'] != run_number or run.get('path') != WORKFLOW_PATH
                or run.get('status') != 'in_progress' or run.get('conclusion') is not None
                or any(any(run.get(actor, {}).get(k) != v for k, v in owner.items())
                       for actor in ('actor', 'triggering_actor'))):
            raise ValueError('Native dispatcher identity refused')
        result['outcome'] = 'UNKNOWN_DISPATCH_RESULT'
        result['dispatch_attempt_count'] = 1  # lost response consumes this exact run_number/attempt
        status, _ = request('POST', '/actions/workflows/' + TARGETS[case] + '/dispatches',
            {'ref': 'codex/qualification', 'inputs': {'occurrence_id': manifest['occurrence_id']}})
        if status == 204:
            result['outcome'] = 'DISPATCH_CONFIRMED'
    except TimeoutError:
        result['outcome'] = 'DEADLINE_EXPIRED'
    except Exception:
        if result['github_action_count'] is None:
            result['outcome'] = 'UNKNOWN_DISPATCH_RESULT' if result['dispatch_attempt_count'] else 'UNKNOWN_CONTROL_RESULT'
    return result
