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
        'statuses', 'retained_stop', 'dispatch_attempt_count', 'patch_attempt_count', 'delete_attempt_count'}
    if (not isinstance(value, dict) or set(value) - allowed
            or value.get('outcome') not in OUTCOMES or value.get('contract') != manifest['contract']
            or value.get('automatic_retry_allowed') is not False):
        raise ValueError('IPC result refused')
    counts({key: value[key] for key in COUNT_KEYS})
    for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt'):
        if key in value and value[key] != manifest[key]:
            raise ValueError('IPC attribution refused')
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
        stop = value['retained_stop']
        if stop != {'ref': 'refs/tags/idyll-cloud-q-stop-v1', 'sha': manifest['source_sha'], 'type': 'commit'}:
            raise ValueError('IPC stop refused')
    for key in ('dispatch_attempt_count', 'patch_attempt_count', 'delete_attempt_count'):
        if key in value and (type(value[key]) is not int or value[key] not in (0, 1)):
            raise ValueError('IPC cap refused')
    if value['outcome'] == 'SOURCE_OBSERVED' and (
            'receipt' not in value or claim is None
            or value['source_attempt_count'] != 1 or value['source_action_count'] != 1):
        raise ValueError('Unattributed source success refused')
    if value['outcome'] in ('SOURCE_OBSERVED', 'RETAINED_STOP_PASS') and any(
            claim.get(key) != manifest[key] for key in ('occurrence_id', 'source_sha', 'run_id', 'attempt')):
        raise ValueError('Wrong executor attribution refused')
    if value['outcome'] == 'RETAINED_STOP_PASS' and (
            claim is None or 'retained_stop' not in value
            or not all(value.get('checks', {}).values()) or len(value.get('checks', {})) != 3
            or value.get('patch_attempt_count') != 1 or value.get('delete_attempt_count') != 1
            or value['source_attempt_count'] != 0 or value['source_action_count'] != 0):
        raise ValueError('Unproved stop success refused')
    if value['outcome'] == 'DISPATCH_CONFIRMED' and (
            value.get('dispatch_attempt_count') != 1 or value['source_attempt_count'] != 0):
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
        due, admitted_cutoff = validate_manifest(manifest, contract=contracts[mode])
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
