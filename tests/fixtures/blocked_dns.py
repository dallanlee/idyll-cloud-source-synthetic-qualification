"""Offline DNS stall: HTTP genuinely enters a substituted native resolver."""
import ctypes
import json
import socket
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from source_observation import FixedHTTPTransport, SOURCE_URL

payload = json.loads(sys.stdin.buffer.read(16385))
def blocked_resolver(*args, **kwargs):
    # libc blocks the child without outbound DNS/network traffic or Python alarms.
    print(json.dumps({'type': 'progress', 'counts': {'source_attempt_count': 1,
        'source_action_count': None, 'github_attempt_count': 0, 'github_action_count': 0}}), flush=True)
    ctypes.CDLL(None).sleep(60)
    raise OSError('resolver must be killed')
socket.getaddrinfo = blocked_resolver
FixedHTTPTransport(payload['github_token'], payload['clickup_token'])(
    'GET', SOURCE_URL, deadline=datetime.now(timezone.utc) + timedelta(seconds=30))
