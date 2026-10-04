"""Inactive protected-Actions entrypoint; all network runs in its supervised child."""
import json
import os
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# -I isolates Python from user site/PYTHONPATH; load only reviewed local modules.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_observation as observer
import retained_stop_probe as stop_probe
import finite_case_dispatcher as dispatcher
from bounded_executor import MAX_IPC, run_supervised


def parent_death_guard():
    """Linux Actions executor also dies if its parent is abruptly killed."""
    if sys.platform != 'linux':
        raise ValueError('Qualified executor requires Linux')
    import ctypes
    expected_parent = int(os.environ['IDYLL_EXECUTOR_PARENT_PID'])
    if os.getppid() != expected_parent:
        raise ValueError('Supervisor absent')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_parent:
        raise ValueError('Parent termination guard unavailable')


def executor_main():
    # A direct invocation in the inactive package cannot load stdin credentials.
    if not observer.OBSERVATION_CONFIGURED and not stop_probe.STOP_PROBE_CONFIGURED and not dispatcher.DISPATCH_CONFIGURED:
        print(json.dumps(observer.empty_receipt('OBSERVATION_NOT_CONFIGURED')))
        return 2
    try:
        parent_death_guard()
        raw = sys.stdin.buffer.read(MAX_IPC + 1)
        if len(raw) > MAX_IPC:
            raise ValueError('IPC cap exceeded')
        payload = json.loads(raw)
        mode = payload['mode']
        expected = {'mode', 'manifest', 'github_token'} | ({'clickup_token'} if mode == 'observation' else set())
        if mode == 'dispatch':
            expected |= {'case', 'run_number'}
        if not isinstance(payload, dict) or set(payload) != expected:
            raise ValueError('IPC input refused')
        if mode == 'observation' and observer.OBSERVATION_CONFIGURED:
            execute = observer.observe
            transport = observer.FixedHTTPTransport(payload.pop('github_token'), payload.pop('clickup_token'))
        elif mode == 'retained-stop' and stop_probe.STOP_PROBE_CONFIGURED:
            execute = stop_probe.probe_retained_stop
            transport = observer.FixedHTTPTransport(payload.pop('github_token'), stop_probe=True)
        elif mode == 'dispatch' and dispatcher.DISPATCH_CONFIGURED:
            case, run_number = payload.pop('case'), payload.pop('run_number')
            transport = observer.FixedHTTPTransport(payload.pop('github_token'), dispatch_case=case)
            def execute(manifest, transport, *, now, progress):
                return dispatcher.dispatch_case(manifest, transport, case=case,
                    run_number=run_number, now=now, progress=progress)
        else:
            raise ValueError('Executor inactive')
        def progress(value):
            print(json.dumps({'type': 'progress', 'counts': value}, separators=(',', ':')), flush=True)
        result = execute(payload['manifest'], transport,
            now=lambda: datetime.now(timezone.utc), progress=progress)
        print(json.dumps({'type': 'result', 'result': result}, separators=(',', ':')), flush=True)
        return 0
    except Exception:
        # The parent treats missing/invalid frames conservatively; no raw error.
        return 2


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if arguments == ['--executor']:
        return executor_main()
    if arguments not in ([], ['--retained-stop'], ['--dispatch']):
        print(json.dumps(observer.empty_receipt('AUTHORITY_REFUSED')))
        return 2
    stop = arguments == ['--retained-stop']
    dispatch = arguments == ['--dispatch']
    configured = (dispatcher.DISPATCH_CONFIGURED if dispatch else
                  stop_probe.STOP_PROBE_CONFIGURED if stop else observer.OBSERVATION_CONFIGURED)
    contract = dispatcher.CONTRACT if dispatch else stop_probe.CONTRACT if stop else observer.CONTRACT
    prefix = 'QUAL_STOP_' if stop else 'QUAL_OBSERVATION_'
    blocked = dict(observer.empty_receipt('OBSERVATION_NOT_CONFIGURED'), contract=contract)
    if not configured:
        print(json.dumps(blocked, sort_keys=True))
        return 2
    try:
        root = Path(__file__).resolve().parents[1]
        git_env = {'PATH': os.defpath, 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_OPTIONAL_LOCKS': '0'}
        head = subprocess.run(['git', '-c', 'core.fsmonitor=false', 'rev-parse', 'HEAD'], cwd=root,
            capture_output=True, text=True, timeout=3, check=True, env=git_env).stdout.strip()
        dirty = subprocess.run(['git', '-c', 'core.fsmonitor=false', 'status', '--porcelain', '--untracked-files=all'], cwd=root,
            capture_output=True, text=True, timeout=3, check=True, env=git_env).stdout
        if dispatch:
            manifest = dispatcher.admit_dispatch(os.environ, head, now=datetime.now(timezone.utc), configured=configured)
        else:
            manifest = observer.admit_environment(os.environ, head, now=datetime.now(timezone.utc),
                configured=configured, prefix=prefix, contract=contract)
        if dirty or manifest is None:
            raise ValueError('Protected authority refused')
        payload = {'mode': 'dispatch' if dispatch else 'retained-stop' if stop else 'observation', 'manifest': manifest,
                   'github_token': os.environ.pop('QUAL_GITHUB_TOKEN')}
        if dispatch:
            payload.update(case=os.environ['QUAL_DISPATCH_CASE'], run_number=int(os.environ['GITHUB_RUN_NUMBER']))
        elif not stop:
            payload['clickup_token'] = os.environ.pop('QUAL_CLICKUP_OAUTH_TOKEN')
        result = run_supervised(payload, observer.instant(manifest['cutoff_at']))
    except Exception:
        result = dict(blocked, outcome='AUTHORITY_REFUSED')
    print(json.dumps(result, sort_keys=True))
    return 0 if result['outcome'] in ('SOURCE_OBSERVED', 'RETAINED_STOP_PASS', 'DISPATCH_CONFIRMED') else 2


if __name__ == '__main__':
    raise SystemExit(main())
