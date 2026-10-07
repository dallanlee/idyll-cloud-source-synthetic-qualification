"""Parent enforced wall/monotonic deadline for a fresh process group.

Bounded nonblocking credential/result IPC. No inherited credential environment,
stderr forwarding, provider retries or trust in the child's socket timeout.
"""
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from source_observation import empty_receipt, validate_manifest, FixedHTTPTransport
from source_bridge import claim_metadata, instant

MAX_IPC = 16384
COUNT_KEYS = ('source_attempt_count', 'source_action_count', 'github_attempt_count', 'github_action_count')
OUTCOMES = {'SOURCE_OBSERVED', 'SOURCE_MISMATCH', 'INVALID_MANIFEST', 'AUTHORITY_REFUSED',
    'UNKNOWN_CONTROL_RESULT', 'UNKNOWN_SOURCE_RESULT', 'ALREADY_CLAIMED', 'REVOKED',
    'DEADLINE_EXPIRED', 'OBSERVATION_NOT_CONFIGURED', 'RETAINED_STOP_PASS',
    'RETAINED_STOP_FAILED', 'DISPATCH_CONFIRMED', 'UNKNOWN_DISPATCH_RESULT'}


def counts(value):
    if not isinstance(value, dict) or set(value) != set(COUNT_KEYS):
        raise ValueError('IPC counts refused')
    for key, number in value.items():
        cap = 1 if key.startswith('source_') else 32
        if number is not None and (type(number) is not int or not 0 <= number <= cap):
            raise ValueError('IPC counts refused')
    return value


def sanitize_result(value, manifest):
    allowed = set(COUNT_KEYS) | {'contract', 'outcome', 'automatic_retry_allowed',
        'occurrence_id', 'source_sha', 'run_id', 'attempt', 'claim', 'receipt', 'checks',
        'statuses', 'retained_stop', 'dispatch_attempt_count', 'patch_attempt_count', 'delete_attempt_count',
        'dispatch_status', 'target_run_id', 'refusal_stage', 'ruleset_http_status', 'control_witness',
        'refusal_diagnostics'}
    if (not isinstance(value, dict) or set(value) - allowed
            or value.get('outcome') not in OUTCOMES or value.get('contract') != manifest['contract']
            or value.get('automatic_retry_allowed') is not False):
        raise ValueError('IPC result refused')
    counts({key: value[key] for key in COUNT_KEYS})
    for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt'):
        if key in value and value[key] != manifest[key]:
            raise ValueError('IPC attribution refused')
    from retained_stop_probe import CONTRACT as STOP_CONTRACT, LEGACY_CONTRACT, RULESET_REFUSAL_STAGES, WITNESS_REFUSAL_STAGES
    v2 = manifest['contract'] == STOP_CONTRACT
    if v2 and (any(value[key] != 0 for key in ('source_attempt_count', 'source_action_count'))
               or any(value[key] is not None and value[key] > 24 for key in ('github_attempt_count', 'github_action_count'))
               or {'receipt', 'dispatch_status', 'target_run_id', 'dispatch_attempt_count'} & set(value)):
        raise ValueError('IPC source-free cap refused')
    if 'refusal_diagnostics' in value:
        diagnostics = value['refusal_diagnostics']
        fields = {'http_422', 'body_is_object', 'message_is_text', 'rule_violation_prefix',
                  'errors_is_array', 'operation_in_message', 'operation_in_errors'}
        if (not v2 or not isinstance(diagnostics, dict)
                or set(diagnostics) not in ({'patch'}, {'patch', 'delete'})
                or 'control_witness' not in value or value.get('claim') is None
                or value.get('patch_attempt_count') != 1
                or 'delete' in diagnostics and value.get('delete_attempt_count') != 1
                or value['outcome'] not in {'RETAINED_STOP_PASS', 'RETAINED_STOP_FAILED',
                                          'UNKNOWN_CONTROL_RESULT', 'DEADLINE_EXPIRED'}):
            raise ValueError('IPC refusal diagnostic refused')
        for diagnostic in diagnostics.values():
            if (not isinstance(diagnostic, dict) or set(diagnostic) != fields
                    or any(type(flag) is not bool for flag in diagnostic.values())):
                raise ValueError('IPC refusal diagnostic shape refused')
    if 'control_witness' in value:
        witness = value['control_witness']
        if (not v2 or not isinstance(witness, dict) or set(witness) != {
                'version', 'comment_sha256', 'observed_at', 'reviewer_id', 'verification_mode'}
                or type(witness['version']) is not int or witness['version'] != 1
                or type(witness['reviewer_id']) is not int or witness['reviewer_id'] != 13070764
                or witness['verification_mode'] != 'owner_snapshot_native_approval'
                or not isinstance(witness['comment_sha256'], str)
                or re.fullmatch(r'[0-9a-f]{64}', witness['comment_sha256']) is None
                or not isinstance(witness['observed_at'], str)
                or not instant(manifest['due_at']) <= instant(witness['observed_at']) < instant(manifest['cutoff_at'])
                or any(key not in value for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt'))
                or value['github_attempt_count'] is None or value['github_attempt_count'] < 8):
            raise ValueError('IPC witness refused')
    if {'refusal_stage', 'ruleset_http_status'} & set(value):
        stage, statuses = value.get('refusal_stage'), value.get('ruleset_http_status')
        witness_refusal = v2 and isinstance(stage, str) and stage in WITNESS_REFUSAL_STAGES
        slots = {'stop'} if stage == 'stop_ruleset_http' else {'stop', 'occurrence'}
        count = 7 if stage == 'stop_ruleset_http' else 8
        if (manifest['contract'] not in (STOP_CONTRACT, LEGACY_CONTRACT) or value['outcome'] != 'AUTHORITY_REFUSED'
                or not isinstance(stage, str) or not (witness_refusal or stage in RULESET_REFUSAL_STAGES)
                or any(key not in value for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt'))
                or value['github_attempt_count'] != count or value['github_action_count'] != count
                or value['source_attempt_count'] != 0 or value['source_action_count'] != 0
                or value.get('patch_attempt_count') != 0 or value.get('delete_attempt_count') != 0
                or {'claim', 'receipt', 'checks', 'statuses', 'retained_stop', 'dispatch_attempt_count',
                    'dispatch_status', 'target_run_id'} & set(value)):
            raise ValueError('IPC protection diagnostic refused')
        if witness_refusal:
            if 'ruleset_http_status' in value or 'control_witness' in value:
                raise ValueError('IPC witness diagnostic refused')
        elif (not isinstance(statuses, dict) or set(statuses) != slots
                or any(type(status) is not int or not 100 <= status <= 599 for status in statuses.values())
                or stage == 'stop_ruleset_http' and statuses['stop'] == 200
                or stage == 'occurrence_ruleset_http' and (statuses['stop'] != 200 or statuses['occurrence'] == 200)
                or not stage.endswith('_http') and statuses != {'stop': 200, 'occurrence': 200}
                or v2 and not stage.endswith('_http') and 'control_witness' not in value):
            raise ValueError('IPC protection status refused')
    claim = value.get('claim')
    if claim is not None:
        if (not isinstance(claim, dict) or set(claim) != {'occurrence_id', 'source_sha', 'run_id', 'attempt', 'ref', 'tag_sha'}
                or not claim_metadata({key: claim[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
                or claim['occurrence_id'] != manifest['occurrence_id']
                or claim['ref'] != 'refs/tags/idyll-cloud-q-occurrence/' + claim['occurrence_id']
                or not isinstance(claim['tag_sha'], str) or not re.fullmatch(r'[0-9a-f]{40}', claim['tag_sha'])):
            raise ValueError('IPC claim refused')
    if 'receipt' in value:
        receipt = value['receipt']
        if (not isinstance(receipt, dict) or set(receipt) != {'task_id', 'workspace_id', 'list_id',
                'date_updated', 'description_equal', 'description_sha256', 'started_at', 'completed_at'}):
            raise ValueError('IPC source evidence refused')
        from source_observation import TASK_ID, WORKSPACE_ID, LIST_ID, EXPECTED_DESCRIPTION_SHA256
        if (receipt['task_id'] != TASK_ID or receipt['workspace_id'] != WORKSPACE_ID
                or receipt['list_id'] != LIST_ID or receipt['description_equal'] is not True
                or receipt['description_sha256'] != EXPECTED_DESCRIPTION_SHA256
                or not isinstance(receipt['date_updated'], str)
                or not re.fullmatch(r'(?:0|[1-9][0-9]{0,19})', receipt['date_updated'])
                or not instant(manifest['due_at']) <= instant(receipt['started_at'])
                    <= instant(receipt['completed_at']) < instant(manifest['cutoff_at'])):
            raise ValueError('IPC source evidence refused')
    if 'checks' in value:
        checks = value['checks']
        if (not isinstance(checks, dict) or set(checks) != {'patch_ruleset_refused', 'delete_ruleset_refused', 'stop_retained'}
                or any(type(item) is not bool for item in checks.values())):
            raise ValueError('IPC checks refused')
    if 'statuses' in value:
        if (not isinstance(value['statuses'], dict) or set(value['statuses']) != {'patch', 'delete'}
                or any(type(v) is not int or not 100 <= v <= 599 for v in value['statuses'].values())):
            raise ValueError('IPC status refused')
    if 'retained_stop' in value:
        from retained_stop_probe import EXPECTED_STOP_SHA
        stop = value['retained_stop']
        if stop != {'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'sha': EXPECTED_STOP_SHA, 'type': 'commit'}:
            raise ValueError('IPC stop refused')
    if 'dispatch_status' in value and (type(value['dispatch_status']) is not int
            or not 100 <= value['dispatch_status'] <= 599):
        raise ValueError('IPC dispatch status refused')
    if 'target_run_id' in value and (not isinstance(value['target_run_id'], str)
            or re.fullmatch(r'[1-9][0-9]{0,18}', value['target_run_id']) is None
            or int(value['target_run_id']) > 9223372036854775807
            or value['target_run_id'] == manifest['run_id']):
        raise ValueError('IPC dispatch identity refused')
    for key in ('dispatch_attempt_count', 'patch_attempt_count', 'delete_attempt_count'):
        if key in value and (type(value[key]) is not int or value[key] not in (0, 1)):
            raise ValueError('IPC cap refused')
    if value['outcome'] == 'SOURCE_OBSERVED' and (
            'receipt' not in value or claim is None
            or value['source_attempt_count'] != 1 or value['source_action_count'] != 1):
        raise ValueError('Unattributed source success refused')
    if value['outcome'] in ('SOURCE_OBSERVED', 'RETAINED_STOP_PASS') and any(
            claim is None or claim.get(key) != manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')):
        raise ValueError('Wrong executor attribution refused')
    if value['outcome'] == 'RETAINED_STOP_PASS' and (
            claim is None or 'retained_stop' not in value
            or manifest['contract'] not in (STOP_CONTRACT, LEGACY_CONTRACT)
            or v2 and ('control_witness' not in value or value['github_attempt_count'] != 23
                       or value['github_action_count'] != 23 or value.get('statuses') != {'patch': 422, 'delete': 422})
            or not all(value.get('checks', {}).values()) or len(value.get('checks', {})) != 3
            or value.get('patch_attempt_count') != 1 or value.get('delete_attempt_count') != 1
            or value['source_attempt_count'] != 0 or value['source_action_count'] != 0):
        raise ValueError('Unproved stop success refused')
    if value['outcome'] == 'DISPATCH_CONFIRMED' and (
            value.get('dispatch_attempt_count') != 1 or value['source_attempt_count'] != 0
            or value.get('dispatch_status') != 200 or 'target_run_id' not in value):
        raise ValueError('Unproved dispatch success refused')
    return value


def run_supervised(payload, cutoff, *, child_command=None):
    """Trusted caller/test process seam; production never accepts argv inputs."""
    manifest = payload['manifest']
    result = dict(empty_receipt('UNKNOWN_CONTROL_RESULT'), contract=manifest['contract'])
    result.update({key: manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')})
    process = None
    clock_limit = time.monotonic() + max(0, (cutoff - datetime.now(timezone.utc)).total_seconds())
    last_counts = None
    frame_buffer = bytearray()
    total_received = 0
    final = None
    previous_handlers = {}
    try:
        from source_observation import CONTRACT as OBSERVATION_CONTRACT
        from retained_stop_probe import CONTRACT as STOP_CONTRACT
        from finite_case_dispatcher import CONTRACT as DISPATCH_CONTRACT, TARGETS
        mode = payload.get('mode')
        contracts = {'observation': OBSERVATION_CONTRACT, 'retained-stop': STOP_CONTRACT,
                     'dispatch': DISPATCH_CONTRACT}
        if mode not in contracts:
            raise ValueError('Executor mode refused')
        expected = {'mode', 'manifest', 'github_token'}
        if mode == 'observation':
            expected.add('clickup_token')
        elif mode == 'dispatch':
            expected |= {'case', 'run_number'}
            if (payload.get('case') not in TARGETS or type(payload.get('run_number')) is not int
                    or not 1 <= payload['run_number'] <= 100000):
                raise ValueError('Dispatcher context refused')
        if set(payload) != expected:
            raise ValueError('Executor input refused')
        case = payload.get('case') if mode == 'dispatch' else 'retained-stop' if mode == 'retained-stop' else 'observation'
        due, admitted_cutoff = validate_manifest(manifest, contract=contracts[mode], case=case)
        if cutoff != admitted_cutoff or not due <= datetime.now(timezone.utc) < cutoff:
            raise TimeoutError('Finite deadline expired')
        # Pure validation before nonblocking IPC; no credential fallback.
        FixedHTTPTransport(payload['github_token'], payload.get('clickup_token'))
        if threading.current_thread() is threading.main_thread():
            def interrupted(signum, frame):
                raise TimeoutError('Supervisor interrupted')
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, interrupted)
        encoded = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        if len(encoded) > MAX_IPC or time.monotonic() >= clock_limit:
            raise TimeoutError('Finite deadline expired')
        command = child_command or [sys.executable, '-I', '-B',
            str(Path(__file__).with_name('run_source_observation.py')), '--executor']
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True,
            env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1',
                 'IDYLL_EXECUTOR_PARENT_PID': str(os.getpid())})
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        written = 0
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdin, selectors.EVENT_WRITE, 'input')
            selector.register(process.stdout, selectors.EVENT_READ, 'output')
            while final is None:
                remaining = min(clock_limit - time.monotonic(),
                    (cutoff - datetime.now(timezone.utc)).total_seconds())
                if remaining <= 0:
                    raise TimeoutError('Finite deadline expired')
                for key, event in selector.select(min(remaining, 0.1)):
                    if key.data == 'input':
                        sent = os.write(process.stdin.fileno(), encoded[written:written + 4096])
                        written += sent
                        if written == len(encoded):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 4096)
                        if not chunk:
                            raise ValueError('Executor result absent')
                        total_received += len(chunk)
                        frame_buffer.extend(chunk)
                        if total_received > MAX_IPC or len(frame_buffer) > MAX_IPC:
                            raise ValueError('Executor output cap exceeded')
                        while b'\n' in frame_buffer:
                            line, _, remainder = frame_buffer.partition(b'\n')
                            frame_buffer = bytearray(remainder)
                            frame = json.loads(line)
                            if not isinstance(frame, dict):
                                raise ValueError('Executor frame refused')
                            if set(frame) == {'type', 'counts'} and frame['type'] == 'progress':
                                last_counts = counts(frame['counts'])
                            elif set(frame) == {'type', 'result'} and frame['type'] == 'result' and final is None:
                                final = sanitize_result(frame['result'], manifest)
                            else:
                                raise ValueError('Executor frame refused')
                if process.poll() is not None and final is None:
                    # Drain a final buffered frame on the next selector iteration.
                    continue
        if datetime.now(timezone.utc) >= cutoff or time.monotonic() >= clock_limit:
            raise TimeoutError('Finite deadline expired')
        result = final
    except Exception as error:
        result['outcome'] = 'DEADLINE_EXPIRED' if isinstance(error, TimeoutError) else 'UNKNOWN_CONTROL_RESULT'
        # A partial/lost IPC receipt cannot prove a zero provider-operation count.
        for key in COUNT_KEYS:
            result[key] = None
        if payload.get('mode') != 'observation':
            result['source_attempt_count'] = result['source_action_count'] = 0
        if last_counts and last_counts['source_attempt_count'] == 1:
            result['source_attempt_count'] = 1
    finally:
        # A second termination signal must not interrupt group kill/reap.
        for signum in previous_handlers:
            signal.signal(signum, signal.SIG_IGN)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)  # kill group even after a success frame
            except ProcessLookupError:
                pass
            reaped = False
            try:
                process.wait(timeout=2)
                reaped = True
            except subprocess.TimeoutExpired:
                result['outcome'] = 'UNKNOWN_CONTROL_RESULT'
            for stream in (process.stdin, process.stdout):
                if not stream.closed:
                    stream.close()
            result['executor'] = {'pid': process.pid, 'process_group': process.pid,
                'reaped': reaped, 'terminated_at': datetime.now(timezone.utc).isoformat()}
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return result
