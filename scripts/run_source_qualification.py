"""Candidate finite qualification entrypoint; absent approvals block all requests."""
import json
import os
from datetime import datetime, timezone
from source_bridge import execute, FixedSourceServices, ProtectedTransport, SOURCE_CONFIGURED


def main():
    blocked = {'contract': 'idyll-cloud-q-v1', 'outcome': 'AUTHORITY_NOT_CONFIGURED',
               'source_action_count': 0, 'source_attempt_count': 0,
               'automatic_retry_allowed': False}
    if not SOURCE_CONFIGURED:
        print(json.dumps(dict(blocked, outcome='SOURCE_NOT_CONFIGURED'), sort_keys=True))
        return 2
    # These are protected-environment configuration, not dispatch inputs.
    expected_sha = os.environ.get('QUAL_ACCEPTED_CODE_SHA')
    occurrence = os.environ.get('QUAL_OCCURRENCE_ID')
    expected_occurrence = os.environ.get('QUAL_APPROVED_OCCURRENCE_ID')
    if (not expected_sha or not expected_occurrence or occurrence != expected_occurrence
            or os.environ.get('GITHUB_SHA') != expected_sha
            or os.environ.get('GITHUB_REPOSITORY_ID') != '1402638368'
            or os.environ.get('GITHUB_REPOSITORY') != 'dallanlee/idyll-cloud-source-synthetic-qualification'
            or os.environ.get('QUAL_ACCESS_APPROVED') != 'idyll-cloud-q-v1-fixed-read'):
        print(json.dumps(blocked))
        return 2
    try:
        manifest = {
            'contract': 'idyll-cloud-q-v1', 'occurrence_id': occurrence,
            'due_at': os.environ['QUAL_APPROVED_DUE_AT'],
            'cutoff_at': os.environ['QUAL_APPROVED_CUTOFF_AT'],
            'source_sha': expected_sha, 'run_id': os.environ['GITHUB_RUN_ID'],
            'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
        }
        # No fallback to existing CLI/auth credentials or personal API tokens.
        transport = ProtectedTransport(os.environ.pop('QUAL_GITHUB_TOKEN'),
                                       os.environ.pop('QUAL_CLICKUP_OAUTH_TOKEN'))
        result = execute(manifest, FixedSourceServices(transport),
                         now=lambda: datetime.now(timezone.utc))
    except Exception:
        print(json.dumps(blocked))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result['outcome'] == 'SOURCE_MATCH' else 2


if __name__ == '__main__':
    raise SystemExit(main())
