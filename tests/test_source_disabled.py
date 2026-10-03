"""The public preparation package must stay inert even with apparent authority."""
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import run_source_qualification
from source_bridge import FixedSourceServices, ProtectedTransport


class DisabledSourceTests(unittest.TestCase):
    def test_complete_looking_environment_cannot_enable_unconfigured_source(self):
        values = {
            'QUAL_ACCEPTED_CODE_SHA': '1' * 40,
            'QUAL_OCCURRENCE_ID': 'idyll-cloud-q-synthetic-test',
            'QUAL_APPROVED_OCCURRENCE_ID': 'idyll-cloud-q-synthetic-test',
            'GITHUB_SHA': '1' * 40,
            'GITHUB_REPOSITORY_ID': '1402638368',
            'GITHUB_REPOSITORY': 'dallanlee/idyll-cloud-source-synthetic-qualification',
            'QUAL_ACCESS_APPROVED': 'idyll-cloud-q-v1-fixed-read',
            'QUAL_GITHUB_TOKEN': 'sentinel-no-real-key',
            'QUAL_CLICKUP_OAUTH_TOKEN': 'sentinel-no-real-key',
            'SOURCE_CONFIGURED': 'true',
        }
        output = io.StringIO()
        with patch.dict(os.environ, values, clear=True), \
                patch('run_source_qualification.ProtectedTransport') as transport, \
                contextlib.redirect_stdout(output):
            self.assertEqual(run_source_qualification.main(), 2)
            self.assertIn('QUAL_CLICKUP_OAUTH_TOKEN', os.environ)
            transport.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual((result['outcome'], result['source_attempt_count'],
                          result['source_action_count']), ('SOURCE_NOT_CONFIGURED', 0, 0))
        self.assertNotIn('sentinel', output.getvalue())

    def test_transport_blocks_source_before_building_any_http_client(self):
        with patch('urllib.request.build_opener') as opener:
            with self.assertRaises(ValueError):
                ProtectedTransport('fake-github-key', 'fake-clickup-key')(
                    'GET', FixedSourceServices.SOURCE_URL)
            opener.assert_not_called()

    def test_enabled_candidate_still_requires_exact_reviewed_authority(self):
        output = io.StringIO()
        with patch('run_source_qualification.SOURCE_CONFIGURED', True), \
                patch.dict(os.environ, {}, clear=True), \
                patch('run_source_qualification.ProtectedTransport') as transport, \
                contextlib.redirect_stdout(output):
            self.assertEqual(run_source_qualification.main(), 2)
            transport.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['outcome'], 'AUTHORITY_NOT_CONFIGURED')


if __name__ == '__main__':
    unittest.main()
