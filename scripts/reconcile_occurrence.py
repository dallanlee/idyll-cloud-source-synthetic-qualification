"""Credential-free, read-only analysis of synthetic occurrence evidence.

This module never dispatches, retries, cancels or authorizes work. Its inputs
must come from a separately qualified provider/history adapter.
"""
from datetime import datetime


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Evidence timestamps require an explicit timezone')
    return parsed


def reconcile(expected, runs, *, now, history_complete, stop_requested_at=None):
    try:
        return _reconcile(expected, runs, now=now, history_complete=history_complete,
                          stop_requested_at=stop_requested_at)
    except (KeyError, TypeError, ValueError, AttributeError):
        # Do not echo malformed payloads: a future adapter may receive secrets.
        return {'outcome': 'INVALID_EVIDENCE', 'automatic_retry_allowed': False}


def _reconcile(expected, runs, *, now, history_complete, stop_requested_at):
    if timestamp(expected['due_at']) >= timestamp(expected['cutoff_at']):
        raise ValueError('Invalid occurrence window')
    timestamp(now)
    # A qualified independent termination adapter does not exist yet.
    # Provider terminal status is deliberately insufficient at this boundary.
    if stop_requested_at is not None:
        timestamp(stop_requested_at)
        return {'outcome': 'STOP_UNVERIFIED', 'automatic_retry_allowed': False}
    if history_complete is not True:
        return {'outcome': 'UNKNOWN_HISTORY', 'automatic_retry_allowed': False}
    unique = {}
    for run in runs:
        if not isinstance(run.get('run_id'), str) or not run['run_id']:
            return {'outcome': 'UNKNOWN_RUN_ID', 'automatic_retry_allowed': False}
        if (type(run.get('attempt')) is not int or run['attempt'] < 1
                or type(run.get('source_action_count')) is not int
                or run['source_action_count'] < 0
                or run.get('occurrence_id') != expected['occurrence_id']
                or run.get('source_sha') != expected['source_sha']):
            return {'outcome': 'INVALID_EVIDENCE', 'automatic_retry_allowed': False}
        key = (run.get('run_id'), run.get('attempt'))
        if key in unique and unique[key] != run:
            return {'outcome': 'UNKNOWN_RESULT', 'automatic_retry_allowed': False}
        unique[key] = run
    runs = list(unique.values())
    if sum(run.get('source_action_count', 0) for run in runs) > 1:
        return {'outcome': 'DUPLICATE_EFFECTS', 'automatic_retry_allowed': False}
    if len(runs) > 1:
        return {'outcome': 'MULTIPLE_RUNS_RECONCILE', 'automatic_retry_allowed': False}
    if runs:
        run = runs[0]
        receipt = run.get('receipt', {})
        if run.get('source_action_count') == 1 and not isinstance(receipt, dict):
            return {'outcome': 'INVALID_EVIDENCE', 'automatic_retry_allowed': False}
        if run.get('source_action_count') == 1 and receipt:
            if timestamp(receipt['completed_at']) > timestamp(now):
                return {'outcome': 'INVALID_EVIDENCE', 'automatic_retry_allowed': False}
            if not (timestamp(expected['due_at']) <= timestamp(receipt['started_at'])
                    <= timestamp(receipt['completed_at']) <= timestamp(expected['cutoff_at'])):
                return {'outcome': 'OUT_OF_WINDOW', 'automatic_retry_allowed': False}
        if (run.get('status') == 'success' and run.get('source_action_count') == 1
                and run.get('occurrence_id') == expected['occurrence_id']
                and run.get('source_sha') == expected['source_sha']
                and receipt.get('source_object') == expected['source_object']
                and receipt.get('source_marker') == expected['source_marker']
                and timestamp(expected['due_at']) <= timestamp(receipt['started_at'])
                <= timestamp(receipt['completed_at']) <= timestamp(expected['cutoff_at'])):
            return {'outcome': 'VERIFIED_SUCCESS', 'automatic_retry_allowed': False}
        return {'outcome': 'UNKNOWN_RESULT', 'automatic_retry_allowed': False}
    return {
        'outcome': 'MISSED' if timestamp(now) > timestamp(expected['cutoff_at']) else 'PENDING',
        'automatic_retry_allowed': False,
    }
