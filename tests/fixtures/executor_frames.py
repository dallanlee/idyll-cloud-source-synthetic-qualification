"""Synthetic subprocess frames at the supervisor's public process seam."""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from source_observation import empty_receipt

payload = json.loads(sys.stdin.buffer.read(16385))
manifest = payload['manifest']
result = empty_receipt('SOURCE_OBSERVED')
result.update({key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
result.update(source_attempt_count=1, source_action_count=1, github_attempt_count=14, github_action_count=14,
    claim={'occurrence_id': manifest['occurrence_id'], 'source_sha': manifest['source_sha'],
           'run_id': manifest['run_id'], 'attempt': 1,
           'ref': 'refs/tags/idyll-cloud-q-occurrence/' + manifest['occurrence_id'], 'tag_sha': '2' * 40},
    receipt={'task_id': '86bccact7', 'workspace_id': '90141728025', 'list_id': '901421854627',
        'date_updated': '1791071022000', 'description_equal': True,
        'description_sha256': 'a8cf682015d6333af14144ce568b043db0f9c7cb28b9b78f0a7005c52e9c55cf',
        'started_at': datetime.now(timezone.utc).isoformat(), 'completed_at': datetime.now(timezone.utc).isoformat()})
case = sys.argv[1]
if case.startswith('stop-diagnostic'):
    # Exercise the real eight-read probe path before testing public parent IPC.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import retained_stop_probe as probe
    from test_retained_stop import StopAPI
    api = StopAPI()
    api.approvals[0]['comment'] = probe.make_control_witness(dict(manifest, contract=probe.CONTRACT),
        observed_at=datetime.now(timezone.utc).isoformat(), controller_sha256='a' * 64)
    def refused(method, url, body=None, *, deadline=None):
        status, value = api(method, url, body, deadline=deadline)
        if case == 'stop-diagnostic-stop-http' and url.endswith('/rulesets/24406998'):
            return 403, {'raw_body': 'private-sentinel'}
        if case == 'stop-diagnostic-http' and url.endswith('/rulesets/24406997'):
            return 404, {'raw_body': 'private-sentinel'}
        if url.endswith('/rulesets/24406998'):
            value = dict(value, raw_body='private-sentinel')
            value['bypass_actors'] = []
        return status, value
    result = probe.probe_retained_stop(dict(manifest, contract=probe.CONTRACT), refused,
        now=lambda: datetime.now(timezone.utc))
    result['contract'] = manifest['contract']  # wrong-contract cases must fail parent policy
    if case == 'stop-diagnostic-unknown-code':
        result['refusal_stage'] = 'private-sentinel'
    elif case == 'stop-diagnostic-raw-status':
        result['ruleset_http_status']['stop'] = 'private-sentinel'
    elif case == 'stop-diagnostic-extra-status':
        result['ruleset_http_status']['raw_body'] = 'private-sentinel'
    elif case == 'stop-diagnostic-bool-status':
        result['ruleset_http_status']['stop'] = True
    elif case == 'stop-diagnostic-float-status':
        result['ruleset_http_status']['stop'] = 200.0
    elif case == 'stop-diagnostic-small-status':
        result['ruleset_http_status']['stop'] = 99
    elif case == 'stop-diagnostic-large-status':
        result['ruleset_http_status']['stop'] = 600
    elif case == 'stop-diagnostic-missing-stage':
        result.pop('refusal_stage')
    elif case == 'stop-diagnostic-missing-status':
        result.pop('ruleset_http_status')
    elif case == 'stop-diagnostic-http-200':
        result['refusal_stage'] = 'occurrence_ruleset_http'
    elif case == 'stop-diagnostic-wrong-outcome':
        result['outcome'] = 'DEADLINE_EXPIRED'
    elif case == 'stop-diagnostic-nonzero-operations':
        result['patch_attempt_count'] = 1
    elif case == 'stop-diagnostic-claimed':
        result['claim'] = {'occurrence_id': manifest['occurrence_id'], 'source_sha': manifest['source_sha'],
            'run_id': manifest['run_id'], 'attempt': 1,
            'ref': 'refs/tags/idyll-cloud-q-occurrence/' + manifest['occurrence_id'], 'tag_sha': '2' * 40}
elif case == 'dispatch':
    result = dict(empty_receipt('DISPATCH_CONFIRMED'), contract=manifest['contract'],
        source_attempt_count=0, source_action_count=0, github_attempt_count=4, github_action_count=4,
        dispatch_attempt_count=1, dispatch_status=200, target_run_id='987',
        **{key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
elif case == 'stop':
    claim = result['claim']
    result = dict(empty_receipt('RETAINED_STOP_PASS'), contract=manifest['contract'],
        source_attempt_count=0, source_action_count=0, github_attempt_count=23, github_action_count=23,
        patch_attempt_count=1, delete_attempt_count=1, claim=claim,
        checks={'patch_ruleset_refused': True, 'delete_ruleset_refused': True, 'stop_retained': True},
        statuses={'patch': 422, 'delete': 422}, retained_stop={
            'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'sha': 'b825e6c6bf5f175569138112e92cf132507cadfd', 'type': 'commit'},
        **{key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
    from retained_stop_probe import make_control_witness, verify_control_witness
    now = datetime.now(timezone.utc)
    result['control_witness'] = verify_control_witness(make_control_witness(manifest,
        observed_at=now.isoformat(), controller_sha256='a' * 64), manifest, now=now)
elif case == 'raw-extra':
    result['raw_body'] = 'private-sentinel'
elif case == 'unearned-success':
    result.pop('receipt')
elif case == 'flood':
    print('private-sentinel' * 2000, flush=True)
    time.sleep(60)
print(json.dumps({'type': 'result', 'result': result}), flush=True)
time.sleep(60)  # parent must kill/reap even a child reporting success
