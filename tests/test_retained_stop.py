"""New source-free retained-stop probe boundary; no consumed run reuse."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import retained_stop_probe as probe
from test_source_observation import ObservationAPI, MANIFEST, NOW, SHA


class StopAPI(ObservationAPI):
    def __init__(self, *, generic=False, changed=False):
        super().__init__()
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
    def test_missing_stop_bypass_is_identified_after_eight_reads_without_any_write(self):
        api, calls = StopAPI(), []
        def hidden_bypass(method, url, body=None, *, deadline=None):
            calls.append((method, url.removeprefix(probe.REPO_URL)))
            status, value = api(method, url, body, deadline=deadline)
            if url.endswith('/rulesets/24406998'):
                value = dict(value, raw_private_detail='never-return-this')
                value.pop('bypass_actors')
            return status, value
        result = probe.probe_retained_stop(dict(MANIFEST, contract=probe.CONTRACT),
            hidden_bypass, now=lambda: NOW)
        self.assertEqual((result['outcome'], result['github_attempt_count'], result['github_action_count'],
            result['patch_attempt_count'], result['delete_attempt_count'], api.source_reads, len(api.tags)),
            ('AUTHORITY_REFUSED', 8, 8, 0, 0, 0, 0))
        self.assertEqual(calls, [('GET', path) for path in ('', '/git/ref/heads/codex/qualification',
            '/environments/qualification-source', '/environments/qualification-source/deployment-branch-policies',
            '/actions/runs/123', '/actions/runs/123/approvals', '/rulesets/24406998', '/rulesets/24406997')])
        self.assertEqual(result.get('refusal_stage'), 'stop_ruleset_bypass_missing')
        self.assertEqual(result.get('ruleset_http_status'), {'stop': 200, 'occurrence': 200})
        self.assertNotIn('never-return-this', str(result))

    def test_each_ruleset_predicate_has_a_fixed_code_and_missing_is_distinct_from_empty(self):
        cases = [('stop', 'id', 0, 'identity'), ('occurrence', 'target', 'branch', 'identity'),
            ('stop', 'enforcement', 'disabled', 'identity'), ('stop', 'rules', [], 'rules'),
            ('occurrence', 'rules', None, 'rules'), ('stop', 'conditions', {}, 'scope'),
            ('occurrence', 'conditions', {}, 'scope'), ('stop', 'bypass_actors', [], 'bypass_mismatch'),
            ('occurrence', 'bypass_actors', 'missing', 'bypass_missing'),
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
        self.assertEqual((result['outcome'], result['github_attempt_count']), ('RETAINED_STOP_PASS', 19))
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
        manifest = dict(MANIFEST, contract='idyll-cloud-q-v1-retained-stop')
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


if __name__ == '__main__':
    unittest.main()
