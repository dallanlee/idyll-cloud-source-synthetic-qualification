"""Inactive new source-free proof of retained-stop update/delete refusal."""
from source_observation import empty_receipt, validate_manifest, verify_native_authority, verify_claim_attribution, REPO_URL
from source_bridge import FixedSourceServices

STOP_PROBE_CONFIGURED = False
CONTRACT = 'idyll-cloud-q-v1-retained-stop'
WORKFLOW_PATH = '.github/workflows/retained-stop-qualification.yml'
ALTERNATE_SHA = '260d783935a0f47eed9222ec66f48e7502cb30b7'
STOP_REF = 'refs/tags/idyll-cloud-q-stop-v1'


def ruleset_refused(status, value, operation):
    if status != 422 or not isinstance(value, dict):
        return False
    message = value.get('message')
    if not isinstance(message, str) or not message.startswith('Repository rule violations found'):
        return False
    errors = value.get('errors', [])
    details = message + '\n' + '\n'.join(
        error['message'] for error in errors if isinstance(error, dict) and isinstance(error.get('message'), str))
    return 'Cannot ' + operation + ' this protected ref' in details


def verify_rulesets(stop, claims):
    for rule, identity, restriction in ((stop, 24406998, {'creation', 'update', 'deletion'}),
                                         (claims, 24406997, {'update', 'deletion'})):
        if (not isinstance(rule, dict) or rule.get('id') != identity or rule.get('target') != 'tag'
                or rule.get('enforcement') != 'active'
                or {item.get('type') for item in rule.get('rules', [])} != restriction):
            raise ValueError('Protection identity refused')
    if (stop.get('conditions') != {'ref_name': {'include': [STOP_REF], 'exclude': []}}
            or stop.get('bypass_actors') != [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}]
            or claims.get('conditions') != {'ref_name': {
                'include': ['refs/tags/idyll-cloud-q-*', 'refs/tags/idyll-cloud-q-occurrence/*'],
                'exclude': [STOP_REF]}}
            or claims.get('bypass_actors') != []):
        raise ValueError('Protection scope refused')


def probe_retained_stop(manifest, transport, *, now, progress=lambda value: None):
    result = dict(empty_receipt('INVALID_MANIFEST'), contract=CONTRACT,
                  patch_attempt_count=0, delete_attempt_count=0)
    try:
        due, cutoff = validate_manifest(manifest, contract=CONTRACT)
        if manifest['source_sha'] == ALTERNATE_SHA:
            raise ValueError('Probe needs a distinct existing target')
        result.update({key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
        def gate():
            current = now()
            if current.tzinfo is None or not due <= current < cutoff:
                raise TimeoutError('Finite window expired')
        def request(method, url, body=None, *, deadline=None):
            gate()
            if not url.startswith(REPO_URL) or result['github_attempt_count'] >= 24:
                raise ValueError('Control cap refused')
            if method in ('PATCH', 'DELETE'):
                field = 'patch_attempt_count' if method == 'PATCH' else 'delete_attempt_count'
                if result[field] or url != REPO_URL + '/git/refs/tags/idyll-cloud-q-stop-v1':
                    raise ValueError('Probe operation refused')
                result[field] = 1
            result['github_attempt_count'] += 1
            result['github_action_count'] = None
            progress({key: result[key] for key in
                ('source_attempt_count', 'source_action_count', 'github_attempt_count', 'github_action_count')})
            value = transport(method, url, body, deadline=cutoff)
            result['github_action_count'] = result['github_attempt_count']
            gate()
            return value
        def get(path):
            status, value = request('GET', REPO_URL + path)
            if status != 200:
                raise ValueError('Native evidence absent')
            return value
        def stop_identity():
            value = get('/git/ref/tags/idyll-cloud-q-stop-v1')
            if (value.get('ref') != STOP_REF or value.get('object', {}).get('type') != 'commit'
                    or value['object'].get('sha') != manifest['source_sha']):
                raise ValueError('Retained stop changed or absent')
            return {'ref': STOP_REF, 'sha': manifest['source_sha'], 'type': 'commit'}
        gate()
        result['outcome'] = 'AUTHORITY_REFUSED'
        verify_native_authority(request, manifest, workflow=WORKFLOW_PATH)
        verify_rulesets(get('/rulesets/24406998'), get('/rulesets/24406997'))
        if get('/git/commits/' + ALTERNATE_SHA).get('sha') != ALTERNATE_SHA:
            raise ValueError('Existing alternate commit not verified')
        before = stop_identity()
        services = FixedSourceServices(request)
        result['outcome'] = 'UNKNOWN_CONTROL_RESULT'
        if services.claim(manifest) is not True:
            result['claim'] = services.claim_receipt
            return dict(result, outcome='ALREADY_CLAIMED')
        result['claim'] = services.claim_receipt  # immutable retained proof of job write capability
        verify_claim_attribution(request, services.claim_receipt)
        stop_identity()  # recheck immediately before first forbidden operation
        result['outcome'] = 'RETAINED_STOP_FAILED'
        patch_status, patch_body = request('PATCH', REPO_URL + '/git/refs/tags/idyll-cloud-q-stop-v1',
            {'sha': ALTERNATE_SHA, 'force': True})
        patch_refused = ruleset_refused(patch_status, patch_body, 'update')
        try:
            stop_identity()
        except Exception:
            return result  # do not delete an unexpectedly changed stop
        if not patch_refused:
            return result  # a generic validation refusal does not authorize the next probe
        delete_status, delete_body = request('DELETE', REPO_URL + '/git/refs/tags/idyll-cloud-q-stop-v1')
        delete_refused = ruleset_refused(delete_status, delete_body, 'delete')
        after = stop_identity()
        checks = {'patch_ruleset_refused': patch_refused, 'delete_ruleset_refused': delete_refused,
                  'stop_retained': before == after}
        result.update(checks=checks, statuses={'patch': patch_status, 'delete': delete_status},
                      retained_stop=after)
        result['outcome'] = 'RETAINED_STOP_PASS' if all(checks.values()) else 'RETAINED_STOP_FAILED'
    except TimeoutError:
        result['outcome'] = 'DEADLINE_EXPIRED'
    except Exception:
        if result['github_action_count'] is None:
            result['outcome'] = 'UNKNOWN_CONTROL_RESULT'
    return result
