"""New source-free retained-stop probe boundary; no consumed run reuse."""
import sys
import json
import copy
from datetime import timedelta
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import retained_stop_probe as probe
from test_source_observation import ObservationAPI, MANIFEST, NOW, SHA


class StopAPI(ObservationAPI):
    def __init__(self, *, generic=False, changed=False):
        super().__init__()
        self.approvals[0]['comment'] = probe.make_control_witness(dict(MANIFEST, contract=probe.CONTRACT),
            observed_at=NOW.isoformat(), controller_sha256='a' * 64)
        self.run['path'] = '.github/workflows/retained-stop-qualification.yml'
        self.refs['refs/tags/idyll-cloud-q-stop-v1'] = {
            'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'object': {
                'sha': 'b825e6c6bf5f175569138112e92cf132507cadfd', 'type': 'commit'}}
        self.generic, self.changed = generic, changed
        self.patch_count = self.delete_count = 0

    def __call__(self, method, url, body=None, *, deadline=None):
        if url.endswith('/rulesets/24406998'):
            return 200, {'id': 24406998, 'target': 'tag', 'enforcement': 'active',
                'conditions': {'ref_name': {'include': ['refs/tags/idyll-cloud-q-stop-v1'], 'exclude': []}},
                'rules': [{'type': t} for t in ('creation', 'update', 'deletion')],
                'bypass_actors': [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}]}
        if url.endswith('/rulesets/24406997'):
            return 200, {'id': 24406997, 'target': 'tag', 'enforcement': 'active',
                'conditions': {'ref_name': {'include': ['refs/tags/idyll-cloud-q-*', 'refs/tags/idyll-cloud-q-occurrence/*'],
                    'exclude': ['refs/tags/idyll-cloud-q-stop-v1']}},
                'rules': [{'type': t} for t in ('update', 'deletion')], 'bypass_actors': []}
        if '/git/commits/' in url:
            return 200, {'sha': url.rsplit('/', 1)[1]}
        if method in ('PATCH', 'DELETE'):
            if method == 'PATCH':
                self.patch_count += 1
                if self.changed:
                    self.refs['refs/tags/idyll-cloud-q-stop-v1']['object']['sha'] = probe.ALTERNATE_SHA
            else:
                self.delete_count += 1
            return 422, {'message': 'generic validation failure' if self.generic else
                'Repository rule violations found', 'errors': [{'message':
                    'Cannot update this protected ref.' if method == 'PATCH' else 'Cannot delete this protected ref.'}]}
        return super().__call__(method, url, body, deadline=deadline)


class StopTests(unittest.TestCase):
    def test_delete_failure_retains_fixed_diagnostics_without_private_response_text(self):
        api = StopAPI()
        def generic_delete(method, url, body=None, *, deadline=None):
            if method == 'DELETE':
                api.delete_count += 1
                return 422, {'message': 'private-provider-sentinel validation failure',
                             'errors': [{'message': 'private-error-sentinel'}],
                             'documentation_url': 'https://private-sentinel.example'}
            return api(method, url, body, deadline=deadline)
        result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
            generic_delete, now=lambda: NOW)
        self.assertEqual(result['outcome'], 'RETAINED_STOP_FAILED')
        self.assertEqual(result['refusal_diagnostics']['delete'], {
            'http_422': True, 'body_is_object': True, 'message_is_text': True,
            'rule_violation_prefix': False, 'errors_is_array': True,
            'operation_in_message': False, 'operation_in_errors': False})
        self.assertEqual((api.patch_count, api.delete_count, api.source_reads), (1, 1, 0))
        self.assertEqual(result['github_attempt_count'], 23)
        self.assertNotIn('private-', json.dumps(result))

    def test_response_shapes_and_operation_details_stay_distinct_and_fail_closed(self):
        prefix = 'Repository rule violations found'
        cases = [
            (422, None, (True, False, False, False, False, False, False), False),
            (422, 'private-response-sentinel', (True, False, False, False, False, False, False), False),
            (422, [], (True, False, False, False, False, False, False), False),
            (422, {}, (True, True, False, False, True, False, False), False),
            (422, {'message': 1}, (True, True, False, False, True, False, False), False),
            (422, {'message': prefix}, (True, True, True, True, True, False, False), False),
            (422, {'message': prefix, 'errors': [{'message': 'Cannot update this protected ref'}]},
                (True, True, True, True, True, False, False), False),
            (422, {'message': prefix, 'errors': None},
                (True, True, True, True, False, False, False), False),
            (422, {'message': prefix, 'errors': 1},
                (True, True, True, True, False, False, False), False),
            (422, {'message': prefix + ': Cannot delete this protected ref', 'errors': None},
                (True, True, True, True, False, True, False), False),
            (422, {'message': prefix + ': Cannot delete this protected ref'},
                (True, True, True, True, True, True, False), True),
            (422, {'message': prefix, 'errors': [None, 'private-error-sentinel', {'message': 1},
                {'message': 'Cannot delete this protected ref. private-detail-sentinel'}]},
                (True, True, True, True, True, False, True), True),
            (403, {'message': prefix, 'errors': [{'message': 'Cannot delete this protected ref'}]},
                (False, True, True, True, True, False, True), False),
            (422, {'message': 'generic validation', 'errors': [{'message': 'Cannot delete this protected ref'}]},
                (True, True, True, False, True, False, True), False),
        ]
        keys = ('http_422', 'body_is_object', 'message_is_text', 'rule_violation_prefix',
                'errors_is_array', 'operation_in_message', 'operation_in_errors')
        for status, response, flags, passes in cases:
            with self.subTest(status=status, response=response):
                api = StopAPI()
                def altered(method, url, body=None, *, deadline=None):
                    original = api(method, url, body, deadline=deadline)
                    return (status, response) if method == 'DELETE' else original
                result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
                    altered, now=lambda: NOW)
                self.assertEqual(result['outcome'], 'RETAINED_STOP_PASS' if passes else 'RETAINED_STOP_FAILED')
                diagnostic = result['refusal_diagnostics']['delete']
                self.assertEqual(diagnostic, dict(zip(keys, flags)))
                self.assertTrue(all(type(flag) is bool for flag in diagnostic.values()))
                self.assertLess(len(json.dumps(result['refusal_diagnostics'])), 600)
                self.assertNotIn('private-', json.dumps(result))
                self.assertEqual((api.patch_count, api.delete_count, api.source_reads), (1, 1, 0))
                self.assertEqual(result['github_attempt_count'], 23 if response not in (
                    {'message': prefix, 'errors': None}, {'message': prefix, 'errors': 1},
                    {'message': prefix + ': Cannot delete this protected ref', 'errors': None}) else 22)

    def test_patch_early_exit_preserves_only_its_observed_diagnostics(self):
        for response in ({'message': 'private-patch-sentinel'},
                         {'message': 'Repository rule violations found', 'errors': None}):
            with self.subTest(response=response):
                api = StopAPI()
                def altered(method, url, body=None, *, deadline=None):
                    original = api(method, url, body, deadline=deadline)
                    return (422, response) if method == 'PATCH' else original
                result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
                    altered, now=lambda: NOW)
                self.assertEqual(result['outcome'], 'RETAINED_STOP_FAILED')
                self.assertEqual(set(result['refusal_diagnostics']), {'patch'})
                self.assertEqual((api.patch_count, api.delete_count, api.source_reads), (1, 0, 0))
                self.assertNotIn('private-', json.dumps(result))

    def test_lost_delete_response_adds_no_invented_observation(self):
        api = StopAPI()
        def lost(method, url, body=None, *, deadline=None):
            if method == 'DELETE':
                api.delete_count += 1
                raise ConnectionError('private-transport-sentinel')
            return api(method, url, body, deadline=deadline)
        result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
            lost, now=lambda: NOW)
        self.assertEqual(result['outcome'], 'UNKNOWN_CONTROL_RESULT')
        self.assertEqual(set(result['refusal_diagnostics']), {'patch'})
        self.assertEqual((api.patch_count, api.delete_count, api.source_reads), (1, 1, 0))
        self.assertNotIn('private-', json.dumps(result))

    def test_visible_stop_bypass_mismatch_is_identified_after_eight_reads_without_any_write(self):
        api, calls = StopAPI(), []
        def hidden_bypass(method, url, body=None, *, deadline=None):
            calls.append((method, url.removeprefix(probe.REPO_URL)))
            status, value = api(method, url, body, deadline=deadline)
            if url.endswith('/rulesets/24406998'):
                value = dict(value, raw_private_detail='never-return-this')
                value['bypass_actors'] = []
            return status, value
        result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
            hidden_bypass, now=lambda: NOW)
        self.assertEqual((result['outcome'], result['github_attempt_count'], result['github_action_count'],
            result['patch_attempt_count'], result['delete_attempt_count'], api.source_reads, len(api.tags)),
            ('AUTHORITY_REFUSED', 8, 8, 0, 0, 0, 0))
        self.assertEqual(calls, [('GET', path) for path in ('', '/git/ref/heads/codex/qualification',
            '/environments/qualification-source', '/environments/qualification-source/deployment-branch-policies',
            '/actions/runs/123', '/actions/runs/123/approvals', '/rulesets/24406998', '/rulesets/24406997')])
        self.assertEqual(result.get('refusal_stage'), 'stop_ruleset_bypass_mismatch')
        self.assertEqual(result.get('ruleset_http_status'), {'stop': 200, 'occurrence': 200})
        self.assertNotIn('never-return-this', str(result))

    def test_each_ruleset_predicate_has_a_fixed_code_and_missing_is_distinct_from_empty(self):
        cases = [('stop', 'id', 0, 'identity'), ('occurrence', 'target', 'branch', 'identity'),
            ('stop', 'enforcement', 'disabled', 'identity'), ('stop', 'rules', [], 'rules'),
            ('occurrence', 'rules', None, 'rules'), ('stop', 'conditions', {}, 'scope'),
            ('occurrence', 'conditions', {}, 'scope'), ('stop', 'bypass_actors', [], 'bypass_mismatch'),
            ('occurrence', 'bypass_actors', None, 'bypass_mismatch'),
            ('occurrence', 'bypass_actors', [{'actor_id': 5}], 'bypass_mismatch')]
        for kind, field, changed, code in cases:
            with self.subTest(kind=kind, field=field, changed=changed):
                api = StopAPI()
                path = '/rulesets/' + ('24406998' if kind == 'stop' else '24406997')
                def altered(method, url, body=None, *, deadline=None):
                    status, value = api(method, url, body, deadline=deadline)
                    if url.endswith(path):
                        value = dict(value)
                        if changed == 'missing':
                            value.pop(field)
                        else:
                            value[field] = changed
                    return status, value
                result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
                    altered, now=lambda: NOW)
                self.assertEqual((result['outcome'], result['github_attempt_count'], result['refusal_stage']),
                    ('AUTHORITY_REFUSED', 8, kind + '_ruleset_' + code))
                self.assertEqual(result['ruleset_http_status'], {'stop': 200, 'occurrence': 200})
                self.assertEqual((api.patch_count, api.delete_count, len(api.tags), api.source_reads), (0, 0, 0, 0))
        result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT), StopAPI(), now=lambda: NOW)
        self.assertEqual((result['outcome'], result['github_attempt_count']), ('RETAINED_STOP_PASS', 23))
        self.assertNotIn('refusal_stage', result)
        self.assertNotIn('ruleset_http_status', result)

    def test_ruleset_http_diagnostics_contain_only_observed_integer_statuses(self):
        for kind, status in [('stop', 403), ('occurrence', 404), ('occurrence', 422),
                              ('stop', True), ('stop', '403'), ('stop', 403.0), ('stop', 99), ('stop', 600)]:
            with self.subTest(kind=kind, status=status):
                api = StopAPI()
                path = '/rulesets/' + ('24406998' if kind == 'stop' else '24406997')
                def failed(method, url, body=None, *, deadline=None):
                    if url.endswith(path):
                        return status, {'raw_private_body': 'never-return-this'}
                    return api(method, url, body, deadline=deadline)
                result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
                    failed, now=lambda: NOW)
                count = 7 if kind == 'stop' else 8
                self.assertEqual((result['outcome'], result['github_attempt_count'], result['github_action_count'],
                                  api.patch_count, api.delete_count), ('AUTHORITY_REFUSED', count, count, 0, 0))
                if type(status) is int and 100 <= status <= 599:
                    self.assertEqual(result['refusal_stage'], kind + '_ruleset_http')
                    self.assertEqual(result['ruleset_http_status'],
                                     {'stop': status} if kind == 'stop' else {'stop': 200, 'occurrence': status})
                else:
                    self.assertNotIn('ruleset_http_status', result)
                    self.assertNotIn('refusal_stage', result)
                self.assertNotIn('never-return-this', str(result))

    def test_new_code_attributes_its_claim_while_preserving_the_exact_old_stop(self):
        api = StopAPI()
        new_code = '2' * 40
        old_stop = 'b825e6c6bf5f175569138112e92cf132507cadfd'
        api.refs['refs/heads/codex/qualification']['object']['sha'] = new_code
        api.run['head_sha'] = new_code
        api.refs['refs/tags/idyll-cloud-q-stop-v1']['object']['sha'] = old_stop
        api.approvals[0]['comment'] = probe.make_control_witness(
            dict(MANIFEST, contract=probe.CONTRACT, source_sha=new_code),
            observed_at=NOW.isoformat(), controller_sha256='a' * 64)
        snapshots = []
        def recorded(method, url, body=None, *, deadline=None):
            status, value = api(method, url, body, deadline=deadline)
            if method == 'GET' and url.endswith('/git/ref/tags/idyll-cloud-q-stop-v1') and status == 200:
                snapshots.append(value['object']['sha'])
            return status, value
        result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT, source_sha=new_code),
            recorded, now=lambda: NOW)
        self.assertEqual((result['outcome'], result.get('retained_stop'), result.get('claim', {}).get('source_sha')),
            ('RETAINED_STOP_PASS', {'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'sha': old_stop, 'type': 'commit'}, new_code))
        self.assertEqual(snapshots, [old_stop, old_stop, old_stop, old_stop])
        self.assertEqual((api.patch_count, api.delete_count, api.source_reads), (1, 1, 0))

    def test_retained_stop_rule_refusals_are_read_back_with_the_actual_job_boundary(self):
        api = StopAPI()
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        result = probe.probe_retained_stop(manifest, api, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.patch_count, api.delete_count, api.source_reads),
                         ('RETAINED_STOP_PASS', 1, 1, 0))
        self.assertEqual(result['retained_stop'],
            {'ref': 'refs/tags/idyll-cloud-q-stop-v1',
             'sha': 'b825e6c6bf5f175569138112e92cf132507cadfd', 'type': 'commit'})
        self.assertEqual(result['claim']['run_id'], '123')

    def test_generic_refusal_or_changed_stop_is_never_a_pass_or_delete_permission(self):
        for api in (StopAPI(generic=True), StopAPI(changed=True)):
            result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT), api, now=lambda: NOW)
            self.assertEqual((result['outcome'], api.delete_count, api.source_reads),
                             ('RETAINED_STOP_FAILED', 0, 0))

    def test_absent_stop_and_duplicate_occurrence_prevent_probe_writes(self):
        api = StopAPI()
        del api.refs['refs/tags/idyll-cloud-q-stop-v1']
        result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT), api, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.patch_count, api.delete_count), ('AUTHORITY_REFUSED', 0, 0))
        api = StopAPI()
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        probe.probe_retained_stop(manifest, api, now=lambda: NOW)
        repeated = probe.probe_retained_stop(manifest, api, now=lambda: NOW)
        self.assertEqual((repeated['outcome'], api.patch_count, api.delete_count), ('ALREADY_CLAIMED', 1, 1))



class WitnessTests(unittest.TestCase):
    def test_hidden_rosters_need_authenticated_comment_but_owner_must_see_them(self):
        api = StopAPI()
        def hidden(method, url, body=None, *, deadline=None):
            status, value = api(method, url, body, deadline=deadline)
            if '/rulesets/' in url:
                value.pop('bypass_actors')
            return status, value
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        result = probe.probe_retained_stop(manifest, hidden, now=lambda: NOW)
        self.assertEqual((result['outcome'], result['github_attempt_count'], api.source_reads),
                         ('RETAINED_STOP_PASS', 23, 0))
        api = StopAPI()
        api.approvals[0].pop('comment')
        result = probe.probe_retained_stop(manifest, api, now=lambda: NOW)
        self.assertEqual((result['refusal_stage'], result['github_action_count'], len(api.tags)),
                         ('witness_malformed', 8, 0))
        with self.assertRaises(ValueError):
            probe.project_ruleset({'id': 24406998}, 'stop')

    def test_every_binding_and_malformed_input_refuses_before_claim(self):
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        original = StopAPI().approvals[0]['comment']
        parsed = json.loads(original[len(probe.WITNESS_PREFIX):])
        values = [None, [], 'private-sentinel', original + ' ', original + 'x' * 1536,
                  original.replace('"attempt":1', '"attempt":1,"attempt":1')]
        for key, changed in [('attempt', True), ('attempt', 2), ('environment_id', 1),
                ('repository_id', 1), ('reviewer_id', 1), ('workflow_id', 1),
                ('occurrence_id', probe.CONSUMED_R5), ('source_sha', 'f' * 40), ('run_id', '124'),
                ('run_id', '0'), ('run_id', '0123'), ('run_id', '9' * 19),
                ('controller_sha256', 'A' * 64), ('policy_sha256', 'f' * 64),
                ('observed_at', '2026-10-04T00:00:11Z'), ('due_at', '2026-10-04T00:00:01Z'),
                ('extra', 'private-sentinel')]:
            values.append(probe.WITNESS_PREFIX + probe.canonical(dict(parsed, **{key: changed})))
        for comment in values:
            with self.subTest(comment=comment):
                api = StopAPI()
                api.approvals[0]['comment'] = comment
                result = probe.probe_retained_stop(manifest, api, now=lambda: NOW)
                self.assertEqual((result['outcome'], result['github_action_count'], len(api.tags),
                                  api.patch_count, api.delete_count, api.source_reads),
                                 ('AUTHORITY_REFUSED', 8, 0, 0, 0, 0))
                self.assertIn(result['refusal_stage'], probe.WITNESS_REFUSAL_STAGES)
                self.assertNotIn('private-sentinel', str(result))

    def test_stale_witness_and_visible_change_stop_each_remaining_mutation(self):
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        for boundary in ('claim', 'patch', 'delete'):
            for stale in (True, False):
                with self.subTest(boundary=boundary, stale=stale):
                    api, clock, reads = StopAPI(), [NOW], [0]
                    def changed(method, url, body=None, *, deadline=None):
                        status, value = api(method, url, body, deadline=deadline)
                        if url.endswith('/rulesets/24406998'):
                            reads[0] += 1
                            if not stale and reads[0] == {'claim': 1, 'patch': 2, 'delete': 3}[boundary]:
                                value['enforcement'] = 'disabled'
                        if stale and (boundary == 'claim' and '/git/commits/' in url or
                                     boundary == 'patch' and reads[0] == 2 or
                                     boundary == 'delete' and reads[0] == 3):
                            clock[0] = NOW + timedelta(seconds=61)
                        return status, value
                    result = probe.probe_retained_stop(manifest, changed, now=lambda: clock[0])
                    self.assertNotEqual(result['outcome'], 'RETAINED_STOP_PASS')
                    self.assertEqual((api.patch_count, api.delete_count),
                                     (1 if boundary == 'delete' else 0, 0))
                    self.assertEqual(api.source_reads, 0)

    def test_policy_is_strict_and_boundary_snapshots_cannot_detect_hidden_restore(self):
        api = StopAPI()
        stop = api('GET', probe.REPO_URL + '/rulesets/24406998')[1]
        for rules in ([{'type': 'creation'}, {'type': 'creation'}, {'type': 'update'}, {'type': 'deletion'}],
                      [{'type': 'creation', 'parameters': {}}, {'type': 'update'}, {'type': 'deletion'}]):
            with self.assertRaises(ValueError):
                probe.project_ruleset(dict(stop, rules=rules), 'stop')
        missing = dict(stop)
        missing.pop('bypass_actors')
        with self.assertRaises(ValueError):
            probe.project_ruleset(missing, 'stop')
        self.assertNotIn('bypass_actors', probe.project_ruleset(missing, 'stop', allow_hidden=True))
        # A malicious owner statement is canonical; hash correctness cannot prove its truth.
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        false_statement = probe.make_control_witness(manifest, observed_at=NOW.isoformat(), controller_sha256='f' * 64)
        self.assertEqual(probe.verify_control_witness(false_statement, manifest, now=NOW)['version'], 1)
        before = probe.project_ruleset(missing, 'stop', allow_hidden=True)
        hidden_intermediate = dict(stop, bypass_actors=[])
        after = probe.project_ruleset(missing, 'stop', allow_hidden=True)
        self.assertNotEqual(hidden_intermediate, stop)
        self.assertEqual(before, after)  # this unobserved change/restore is explicitly NOT detected

    def owner_policy_fixture(self):
        # Field shape from authenticated 2026-10-04 environment readback; metadata
        # IDs below are fabricated and do not imply a new native case or policy.
        env = copy.deepcopy(StopAPI().environment)
        env['protection_rules'][0].update(id=1, node_id='offline-reviewer-metadata')
        env['protection_rules'].append({'type': 'branch_policy', 'id': 2, 'node_id': 'offline-branch-metadata'})
        branches = {'total_count': 1, 'branch_policies': [{'name': 'codex/qualification', 'type': 'branch'}]}
        rules = []
        for kind in ('stop', 'occurrence', 'code'):
            value = copy.deepcopy(probe.expected_ruleset(kind))
            value['rules'] = [{'type': item} for item in value['rules']]
            rules.append(value)
        return rules, env, branches

    def test_owner_native_branch_marker_preserves_the_exact_policy_digest(self):
        rules, env, branches = self.owner_policy_fixture()
        import hashlib
        for shape in (env['protection_rules'], env['protection_rules'][::-1], env['protection_rules'][:1]):
            with self.subTest(shape=shape):
                observed = probe.verify_owner_policy(*rules, dict(env, protection_rules=shape), branches)
                self.assertEqual(observed, probe.EXPECTED_POLICY)
                self.assertEqual(hashlib.sha256(probe.canonical(observed).encode()).hexdigest(),
                                 '7c9eb179a2ac6169cd1c894ab90d470065f6fc73f841e4cbef8593e67784858f')

    def test_owner_branch_marker_rejects_unknown_duplicate_and_malformed_rules(self):
        rules, env, branches = self.owner_policy_fixture()
        reviewer, marker = env['protection_rules']
        bad = [[], [marker], [reviewer, reviewer], [reviewer, marker, marker],
               [reviewer, {'type': 'wait_timer', 'wait_timer': 0}], [reviewer, None],
               [reviewer, 'branch_policy'], [reviewer, {'type': 'branch_policy'}],
               [reviewer, dict(marker, unexpected=True)], [reviewer, dict(marker, id=True)],
               [reviewer, dict(marker, id=0)], [reviewer, dict(marker, node_id=None)],
               [reviewer, dict(marker, node_id='')], [reviewer, dict(marker, node_id='x' * 257)],
               [reviewer, dict(marker, node_id='non ascii \u2603')],
               [reviewer, dict(marker, node_id='contains whitespace')]]
        for shape in bad:
            with self.subTest(shape=shape), self.assertRaises(ValueError):
                probe.verify_owner_policy(*rules, dict(env, protection_rules=shape), branches)

    def test_owner_branch_marker_never_substitutes_for_protection_controls(self):
        rules, env, branches = self.owner_policy_fixture()
        for field, changed in [('can_admins_bypass', True), ('deployment_branch_policy', {
                'protected_branches': True, 'custom_branch_policies': False})]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.verify_owner_policy(*rules, dict(env, **{field: changed}), branches)
        for field, changed in [('prevent_self_review', False), ('reviewers', [{'type': 'User', 'reviewer': {'id': 1}}])]:
            altered = copy.deepcopy(env)
            altered['protection_rules'][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.verify_owner_policy(*rules, altered, branches)
        for changed in ({'total_count': 0, 'branch_policies': []},
                        {'total_count': 1, 'branch_policies': [{'name': 'main', 'type': 'branch'}]},
                        {'total_count': True, 'branch_policies': branches['branch_policies']}):
            with self.subTest(branches=changed), self.assertRaises(ValueError):
                probe.verify_owner_policy(*rules, env, changed)

    def test_versioned_contract_and_canonical_bound_witness(self):
        self.assertEqual(probe.CONTRACT, 'idyll-cloud-q-v2-retained-stop')
        manifest = dict(MANIFEST, contract=probe.CONTRACT)
        comment = probe.make_control_witness(manifest, observed_at=NOW.isoformat(), controller_sha256='a' * 64)
        summary = probe.verify_control_witness(comment, manifest, now=NOW)
        self.assertEqual(summary['verification_mode'], 'owner_snapshot_native_approval')
        self.assertEqual(summary['reviewer_id'], 13070764)
        for bad in (None, comment + ' ', comment.replace('"attempt":1', '"attempt":true'),
                    comment.replace('"attempt":1', '"attempt":1,"attempt":1'),
                    comment.replace('"run_id":"123"', '"run_id":"124"')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.verify_control_witness(bad, manifest, now=NOW)

if __name__ == '__main__':
    unittest.main()
