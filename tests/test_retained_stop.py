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
            'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'object': {'sha': SHA, 'type': 'commit'}}
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
    def test_retained_stop_rule_refusals_are_read_back_with_the_actual_job_boundary(self):
        api = StopAPI()
        manifest = dict(MANIFEST, contract='idyll-cloud-q-v1-retained-stop')
        result = probe.probe_retained_stop(manifest, api, now=lambda: NOW)
        self.assertEqual((result['outcome'], api.patch_count, api.delete_count, api.source_reads),
                         ('RETAINED_STOP_PASS', 1, 1, 0))
        self.assertEqual(result['retained_stop'],
            {'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'sha': SHA, 'type': 'commit'})
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
