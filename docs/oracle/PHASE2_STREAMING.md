# PHASE 2 — RELIABLE STREAMING, RECONNECTION AND RECOVERY

## Session model

`trident/replay.py`. Every analysis gets a session id and every event a monotonic
sequence number. Order is defined by the sequence, not by the connection.

Events carry their sequence as the SSE `id:` field, which is the standard
`Last-Event-ID` mechanism.

## Reconnection

`GET /api/network/analyze/replay/{session_id}?last_event_id=N` returns exactly the
events after N.

- No duplicates: the cursor is exclusive.
- No gaps: sequence numbers are contiguous unless a client asks from before the
  retained window, in which case it is told the session expired rather than handed
  a partial report.
- The frontend resumes automatically on a mid-stream failure and reports
  "resumed" so the user knows.
- A replayed `SECTION` is skipped if that device has already been rendered, so a
  reconnect cannot produce two cards for one switch.

## Retention, measured

| Bound | Value |
|---|---|
| Sessions kept | 32 |
| Events per session | 2000 |
| Replay window | 30 minutes after completion |

Past those bounds a reconnect returns `expired: true` with a reason. That is the
honest answer: the client restarts rather than showing half a report as complete.

## Disconnect versus cancel

A dropped socket does **not** touch the session. Only
`POST /api/network/analyze/cancel/{id}` marks it cancelled. That distinction is
the difference between a laptop lid closing and a user pressing stop.

## Evidence

```
session 76650b9b36e5 | events: 13
replay after 3: SECTION ×7, FINDINGS, COVERAGE, COMPLETE | expired: False
```

Sequence numbers 1..13, cursor 3 returned 4..13 exactly.

## Tests

23 in `tests/test_replay.py`: monotonic ordering, exact cursor replay, no
duplicates across two reconnects, terminal states, bounded retention, session cap,
TTL expiry, unknown-session expiry, retention-window expiry, cancel semantics, a
disconnect not cancelling, SSE framing, and the three endpoints.

## Limits

- The registry is process-local and in-memory. A backend restart loses sessions and
  that surfaces as expiry, not silent loss.
- Replay is not resumable across processes; a multi-worker deployment would need a
  shared store.
