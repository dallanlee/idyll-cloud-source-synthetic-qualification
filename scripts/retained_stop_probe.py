"""Inactive new source-free proof of retained-stop update/delete refusal."""
import hashlib
import json
import re
from source_bridge import instant
from protected_oauth_storage import verify_environment
from source_observation import empty_receipt, validate_manifest, verify_native_authority, verify_claim_attribution, REPO_URL
from source_bridge import FixedSourceServices

STOP_PROBE_CONFIGURED = True
LEGACY_CONTRACT = 'idyll-cloud-q-v1-retained-stop'
CONTRACT = 'idyll-cloud-q-v2-retained-stop'
WORKFLOW_PATH = '.github/workflows/retained-stop-qualification.yml'
ALTERNATE_SHA = '260d783935a0f47eed9222ec66f48e7502cb30b7'
EXPECTED_STOP_SHA = 'b825e6c6bf5f175569138112e92cf132507cadfd'
STOP_REF = 'refs/tags/idyll-cloud-q-stop-v1'
RULESET_REFUSAL_STAGES = frozenset(kind + '_ruleset_' + check
    for kind in ('stop', 'occurrence')
    for check in ('http', 'identity', 'rules', 'scope', 'bypass_missing', 'bypass_mismatch'))


class RulesetRefusal(ValueError):
    """Fixed local classification only; provider bodies never become reasons."""
    def __init__(self, stage):
        if stage not in RULESET_REFUSAL_STAGES:
            raise ValueError('Unrecognized protection classification')
        self.stage = stage
        super().__init__('Protection refused')


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


WITNESS_PREFIX = 'idyll-control-witness-v1 '
WITNESS_MAX_BYTES = 1536
WITNESS_MAX_AGE = 60
WITNESS_REFUSAL_STAGES = frozenset({'witness_malformed', 'witness_binding', 'witness_freshness'})
WITNESS_FIXED = {'attempt': 1, 'environment_id': 23353662059, 'repository_id': 1402638368,
                 'reviewer_id': 13070764, 'workflow_id': 374298239}
WITNESS_BINDINGS = ('occurrence_id', 'source_sha', 'run_id', 'due_at', 'cutoff_at')
CONSUMED_R5 = 'idyll-cloud-q-retained-stop-r5-01a10561'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def expected_ruleset(kind):
    admin = [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}]
    scopes = {
        'stop': (24406998, 'tag', [STOP_REF], [], ['creation', 'deletion', 'update'], admin),
        'occurrence': (24406997, 'tag', ['refs/tags/idyll-cloud-q-*', 'refs/tags/idyll-cloud-q-occurrence/*'],
                       [STOP_REF], ['deletion', 'update'], []),
        'code': (24407000, 'branch', ['refs/heads/main', 'refs/heads/codex/qualification'], [],
                 ['creation', 'deletion', 'non_fast_forward', 'update'], admin)}
    identity, target, include, exclude, rules, bypass = scopes[kind]
    return {'id': identity, 'target': target, 'enforcement': 'active',
            'conditions': {'ref_name': {'include': include, 'exclude': exclude}},
            'rules': rules, 'bypass_actors': bypass}


EXPECTED_POLICY = {
    'rulesets': {kind: expected_ruleset(kind) for kind in ('stop', 'occurrence', 'code')},
    'environment': {'id': 23353662059, 'name': 'qualification-source', 'can_admins_bypass': False,
        'prevent_self_review': True, 'reviewers': [{'type': 'User', 'id': 13070764}],
        'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True},
        'branches': [{'name': 'codex/qualification', 'type': 'branch'}]},
    'repository_id': 1402638368,
    'stop': {'ref': STOP_REF, 'sha': EXPECTED_STOP_SHA, 'type': 'commit'},
    'job_permissions': {'contents': 'write', 'actions': 'read'}}
POLICY_SHA256 = hashlib.sha256(canonical(EXPECTED_POLICY).encode('ascii')).hexdigest()


def project_ruleset(rule, kind, *, allow_hidden=False):
    expected = expected_ruleset(kind)
    def refuse(check):
        if kind == 'code':
            raise ValueError('Owner code protection refused')
        raise RulesetRefusal(kind + '_ruleset_' + check)
    if (not isinstance(rule, dict) or type(rule.get('id')) is not int
            or any(rule.get(key) != expected[key] for key in ('id', 'target', 'enforcement'))):
        refuse('identity')
    rules = rule.get('rules')
    if (not isinstance(rules, list) or any(not isinstance(item, dict) or set(item) != {'type'}
            or not isinstance(item['type'], str) for item in rules)):
        refuse('rules')
    types = [item['type'] for item in rules]
    if len(types) != len(set(types)) or sorted(types) != expected['rules']:
        refuse('rules')
    if rule.get('conditions') != expected['conditions']:
        refuse('scope')
    projection = {key: expected[key] for key in ('id', 'target', 'enforcement', 'rules', 'conditions')}
    if 'bypass_actors' not in rule:
        if not allow_hidden:
            refuse('bypass_missing')
    elif canonical(rule['bypass_actors']) != canonical(expected['bypass_actors']):
        refuse('bypass_mismatch')
    else:
        projection['bypass_actors'] = expected['bypass_actors']
    return projection


def verify_rulesets(stop, claims, *, allow_hidden=False):
    return {kind: project_ruleset(rule, kind, allow_hidden=allow_hidden)
            for kind, rule in (('stop', stop), ('occurrence', claims))}


def verify_owner_policy(stop, claims, code, environment, branches):
    """Complete owner observation; an omitted roster is always refused here."""
    verify_environment(environment, branches)
    # No unexpected protection rule is silently excluded from the owner projection.
    if (len(environment['protection_rules']) != 1 or type(environment['id']) is not int
            or type(branches.get('total_count')) is not int):
        raise ValueError('Owner environment projection refused')
    observed = dict(EXPECTED_POLICY, rulesets={kind: project_ruleset(rule, kind)
        for kind, rule in (('stop', stop), ('occurrence', claims), ('code', code))})
    if canonical(observed) != canonical(EXPECTED_POLICY):
        raise ValueError('Owner policy refused')
    return observed


class WitnessRefusal(ValueError):
    def __init__(self, stage):
        if stage not in WITNESS_REFUSAL_STAGES:
            raise ValueError('Unrecognized witness classification')
        self.stage = stage
        super().__init__('Control witness refused')


def witness_freshness(observed_at, manifest, now):
    try:
        observed, due, cutoff = (instant(value) for value in
                                (observed_at, manifest['due_at'], manifest['cutoff_at']))
        if (now.tzinfo is None or not due <= observed <= now < cutoff
                or (now - observed).total_seconds() > WITNESS_MAX_AGE):
            raise ValueError('stale')
    except Exception:
        raise WitnessRefusal('witness_freshness') from None


def verify_control_witness(comment, manifest, *, now):
    try:
        validate_manifest(manifest, contract=CONTRACT)
    except Exception:
        raise WitnessRefusal('witness_binding') from None
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate')
            result[key] = value
        return result
    try:
        if (not isinstance(comment, str) or not comment.isascii() or '\n' in comment
                or len(comment.encode('utf-8')) > WITNESS_MAX_BYTES or not comment.startswith(WITNESS_PREFIX)):
            raise ValueError('format')
        body = comment[len(WITNESS_PREFIX):]
        witness = json.loads(body, object_pairs_hook=unique)
        keys = set(WITNESS_FIXED) | set(WITNESS_BINDINGS) | {'controller_sha256', 'policy_sha256', 'observed_at'}
        if not isinstance(witness, dict) or set(witness) != keys or canonical(witness) != body:
            raise ValueError('shape')
        if (any(type(witness[key]) is not int for key in WITNESS_FIXED)
                or any(not isinstance(value, str) or not value.isascii()
                       for key, value in witness.items() if key not in WITNESS_FIXED)
                or any(re.fullmatch(r'[0-9a-f]{64}', witness[key]) is None
                       for key in ('controller_sha256', 'policy_sha256'))
                or re.fullmatch(r'[0-9a-f]{40}', witness['source_sha']) is None
                or re.fullmatch(r'[1-9][0-9]{0,18}', witness['run_id']) is None
                or int(witness['run_id']) > 9223372036854775807
                or re.fullmatch(r'idyll-cloud-q-[a-z0-9-]{1,100}', witness['occurrence_id']) is None):
            raise ValueError('types')
        for key in ('due_at', 'cutoff_at', 'observed_at'):
            if re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', witness[key]) is None:
                raise ValueError('time')
            instant(witness[key])
    except Exception:
        raise WitnessRefusal('witness_malformed') from None
    if (any(witness[key] != value for key, value in WITNESS_FIXED.items())
            or any(witness[key] != manifest[key] for key in WITNESS_BINDINGS)
            or manifest.get('contract') != CONTRACT or manifest.get('attempt') != 1
            or witness['occurrence_id'] == CONSUMED_R5 or witness['policy_sha256'] != POLICY_SHA256):
        raise WitnessRefusal('witness_binding')
    witness_freshness(witness['observed_at'], manifest, now)
    return {'version': 1, 'comment_sha256': hashlib.sha256(comment.encode('ascii')).hexdigest(),
            'observed_at': witness['observed_at'], 'reviewer_id': 13070764,
            'verification_mode': 'owner_snapshot_native_approval'}


def make_control_witness(manifest, *, observed_at, controller_sha256):
    """Pure formatting; caller must first establish the complete owner policy."""
    value = dict(WITNESS_FIXED, **{key: manifest[key] for key in WITNESS_BINDINGS},
                 observed_at=observed_at, controller_sha256=controller_sha256, policy_sha256=POLICY_SHA256)
    comment = WITNESS_PREFIX + canonical(value)
    verify_control_witness(comment, manifest, now=instant(observed_at))
    return comment


def probe_retained_stop(manifest, transport, *, now, progress=lambda value: None):
    result = dict(empty_receipt('INVALID_MANIFEST'), contract=CONTRACT,
                  patch_attempt_count=0, delete_attempt_count=0)
    ruleset_status = {}
    phase = 'admission'
    try:
        due, cutoff = validate_manifest(manifest, contract=CONTRACT)
        if manifest['source_sha'] == ALTERNATE_SHA or EXPECTED_STOP_SHA == ALTERNATE_SHA:
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
            if method in ('POST', 'PATCH', 'DELETE'):
                witness_freshness(result['control_witness']['observed_at'], manifest, now())
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
        def get_ruleset(kind, identity):
            status, value = request('GET', REPO_URL + '/rulesets/' + str(identity))
            if type(status) is int and 100 <= status <= 599:
                ruleset_status[kind] = status
            if type(status) is not int or status != 200:
                raise RulesetRefusal(kind + '_ruleset_http')
            return value
        def stop_identity():
            value = get('/git/ref/tags/idyll-cloud-q-stop-v1')
            if (value.get('ref') != STOP_REF or value.get('object', {}).get('type') != 'commit'
                    or value['object'].get('sha') != EXPECTED_STOP_SHA):
                raise ValueError('Retained stop changed or absent')
            return {'ref': STOP_REF, 'sha': EXPECTED_STOP_SHA, 'type': 'commit'}
        gate()
        result['outcome'] = 'AUTHORITY_REFUSED'
        approval = verify_native_authority(request, manifest, workflow=WORKFLOW_PATH)
        stop_rules, claim_rules = get_ruleset('stop', 24406998), get_ruleset('occurrence', 24406997)
        result['control_witness'] = verify_control_witness(approval.get('comment'), manifest, now=now())
        visible = verify_rulesets(stop_rules, claim_rules, allow_hidden=True)
        def recheck():
            observed = verify_rulesets(get_ruleset('stop', 24406998), get_ruleset('occurrence', 24406997),
                                      allow_hidden=True)
            if canonical(observed) != canonical(visible):
                raise ValueError('Visible protection changed')
            witness_freshness(result['control_witness']['observed_at'], manifest, now())
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
        result['outcome'] = 'RETAINED_STOP_FAILED'
        phase = 'patch'
        recheck()
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
        phase = 'delete'
        recheck()
        delete_status, delete_body = request('DELETE', REPO_URL + '/git/refs/tags/idyll-cloud-q-stop-v1')
        delete_refused = ruleset_refused(delete_status, delete_body, 'delete')
        after = stop_identity()
        checks = {'patch_ruleset_refused': patch_refused, 'delete_ruleset_refused': delete_refused,
                  'stop_retained': before == after}
        result.update(checks=checks, statuses={'patch': patch_status, 'delete': delete_status},
                      retained_stop=after)
        result['outcome'] = 'RETAINED_STOP_PASS' if all(checks.values()) else 'RETAINED_STOP_FAILED'
    except RulesetRefusal as error:
        # Publish only fully observed status slots, never infer omitted values.
        expected = {'stop'} if error.stage == 'stop_ruleset_http' else {'stop', 'occurrence'}
        if phase == 'admission' and set(ruleset_status) == expected:
            result.update(refusal_stage=error.stage, ruleset_http_status=ruleset_status)
    except WitnessRefusal as error:
        result['outcome'] = 'AUTHORITY_REFUSED' if result['github_attempt_count'] == 8 else 'RETAINED_STOP_FAILED'
        if result['github_attempt_count'] == 8 and 'control_witness' not in result:
            result['refusal_stage'] = error.stage
    except TimeoutError:
        result['outcome'] = 'DEADLINE_EXPIRED'
    except Exception:
        if result['github_action_count'] is None:
            result['outcome'] = 'UNKNOWN_CONTROL_RESULT'
    return result
