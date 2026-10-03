"""Counterexamples for misleading provider refusals; this is a local API model."""
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import qualify_github_controls as probe

SHA = '1' * 40


class Reply:
    def __init__(self, status, body):
        self.status, self.body = status, json.dumps(body).encode()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size):
        return self.body[:size]


class Provider:
    def __init__(self, *, before_stop=False, before_branch=False,
                 after_stop=False, after_branch=False, newline=False):
        self.before_stop, self.before_branch = before_stop, before_branch
        self.after_stop, self.after_branch = after_stop, after_branch
        self.newline = newline
        self.stop_reads = self.branch_reads = self.writes = self.creates = 0
        self.tag = None
        self.claim = None
    def open(self, request, *, timeout):
        path = request.full_url.removeprefix(probe.API)
        method = request.get_method()
        if method != 'GET':
            self.writes += 1
        if method == 'GET':
            if path == '':
                return Reply(200, {'id': int(probe.REPOSITORY_ID), 'private': False})
            if path == '/git/commits/' + SHA:
                return Reply(200, {'sha': SHA, 'tree': {'sha': '4' * 40}})
            if path == '/git/ref/tags/idyll-cloud-q-stop-v1':
                self.stop_reads += 1
                exists = self.before_stop if self.stop_reads == 1 else self.after_stop
                return Reply(200 if exists else 404, {})
            if path == '/git/ref/heads/codex/qualification':
                self.branch_reads += 1
                moved = self.before_branch if self.branch_reads == 1 else self.after_branch
                return Reply(200, {'ref': 'refs/heads/codex/qualification',
                                  'object': {'type': 'commit', 'sha': '5' * 40 if moved else SHA}})
            if path.startswith('/git/tags/'):
                return Reply(200, self.tag)
            if path.startswith('/git/ref/tags/idyll-cloud-q-occurrence/'):
                return Reply(200, self.claim)
        if method == 'POST' and path == '/git/commits':
            return Reply(201, {'sha': '3' * 40})
        if method == 'POST' and path == '/git/tags':
            self.tag = dict(json.loads(request.data), sha='2' * 40)
            self.tag['message'] += '\n' if self.newline else ''
            return Reply(201, self.tag)
        if method == 'POST' and path == '/git/refs':
            body = json.loads(request.data)
            if body['ref'].startswith('refs/tags/idyll-cloud-q-occurrence/'):
                self.creates += 1
                self.claim = {'ref': body['ref'], 'object': {'sha': body['sha'], 'type': 'tag'}}
                return Reply(201 if self.creates == 1 else 422, self.claim)
        if method in ('POST', 'PATCH', 'DELETE'):
            return Reply(422, {'message': 'A refusal has multiple possible causes'})
        raise AssertionError('Unexpected modeled request')


def run(provider):
    values = {'GITHUB_REPOSITORY': probe.REPOSITORY,
              'GITHUB_REPOSITORY_ID': probe.REPOSITORY_ID,
              'GITHUB_EVENT_NAME': 'workflow_dispatch',
              'GITHUB_REF': 'refs/heads/codex/qualification',
              'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '123',
              'GITHUB_SHA': SHA, 'QUAL_CONTROLS_ACCEPTED_CODE_SHA': SHA,
              'GH_TOKEN': 'sentinel-not-a-real-key'}
    output = io.StringIO()
    with patch.dict(os.environ, values, clear=True), \
            patch('qualify_github_controls.build_opener', return_value=provider), \
            contextlib.redirect_stdout(output):
        code = probe.main()
    assert 'sentinel' not in output.getvalue()
    return code, json.loads(output.getvalue())


class GitHubControlTests(unittest.TestCase):
    def test_refusal_plus_unchanged_state_is_a_modeled_pass(self):
        code, result = run(Provider())
        self.assertEqual((code, result['outcome']), (0, 'CONTROL_PROBE_PASS'))
        self.assertEqual(result['source_attempt_count'], 0)

    def test_existing_stop_or_advanced_branch_prevents_any_write(self):
        for provider in (Provider(before_stop=True), Provider(before_branch=True)):
            with self.subTest(provider=provider):
                code, result = run(provider)
                self.assertEqual((code, result['outcome'], provider.writes),
                                 (2, 'UNKNOWN_CONTROL_RESULT', 0))

    def test_a_422_with_changed_post_state_cannot_be_a_pass(self):
        for provider in (Provider(after_stop=True), Provider(after_branch=True)):
            with self.subTest(provider=provider):
                code, result = run(provider)
                self.assertEqual((code, result['outcome']), (2, 'CONTROL_PROBE_FAILED'))

    def test_trailing_newline_is_diagnosed_without_accepting_a_mismatch(self):
        code, result = run(Provider(newline=True))
        self.assertEqual((code, result['outcome']), (2, 'CONTROL_PROBE_FAILED'))
        self.assertEqual(result['annotation_echo'], {'exact': False, 'one_trailing_newline': True})


if __name__ == '__main__':
    unittest.main()
