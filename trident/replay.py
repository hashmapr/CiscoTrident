"""Replayable analysis sessions.

A stream can break: a laptop sleeps, a proxy resets, a browser tab is backgrounded
too long. Losing a 33-device report because of that is a product failure, so events
are retained per session and can be replayed.

Design:

* Every analysis gets a **session id** and every event a **monotonic sequence
  number**. The sequence, not the connection, defines order.
* Clients reconnect with ``Last-Event-ID`` (the SSE standard) and receive only the
  events after it. No duplicates, no gaps.
* Retention is **bounded**: a fixed number of sessions and events per session. When
  a session expires, a reconnect returns an explicit ``EXPIRED`` result so the
  client can restart rather than silently rendering half a report.
* A disconnect is not a cancellation. Nothing is destroyed because a socket
  closed; only an explicit cancel or expiry clears a session.

The registry is process-local and in-memory. A backend restart loses sessions, and
that is reported as expiry rather than pretended otherwise.
"""

from __future__ import annotations

import enum
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field

#: How many finished sessions to keep for replay.
MAX_SESSIONS = 32
#: How many events to keep per session, newest kept on overflow.
MAX_EVENTS = 2000
#: How long a finished session remains replayable, in seconds.
SESSION_TTL = 30 * 60


class SessionState(enum.StrEnum):
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class Event:
    """One streamed event."""

    seq: int
    kind: str
    payload: dict
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {"seq": self.seq, "kind": self.kind, "at": self.at, "payload": self.payload}

    def to_sse(self) -> str:
        """SSE frame carrying its sequence as the event id, so ``Last-Event-ID`` works."""
        import json

        return f"id: {self.seq}\ndata: {json.dumps({'kind': self.kind, 'payload': self.payload})}\n\n"


@dataclass
class ReplayResult:
    """What a reconnecting client receives."""

    session_id: str
    state: SessionState | None
    events: list[Event]
    expired: bool = False
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "state": self.state.value if self.state else None,
            "expired": self.expired,
            "reason": self.reason,
            "events": [event.as_dict() for event in self.events],
        }


class Session:
    """One analysis session's event log."""

    def __init__(self, session_id: str, input_identity: str = "") -> None:
        self.session_id = session_id
        self.input_identity = input_identity
        self.state = SessionState.RUNNING
        self.created = time.time()
        self.finished: float | None = None
        self._events: list[Event] = []
        self._seq = 0
        self._lock = threading.Lock()

    def emit(self, kind: str, payload: dict | None = None) -> Event:
        with self._lock:
            self._seq += 1
            event = Event(seq=self._seq, kind=kind, payload=payload or {})
            self._events.append(event)
            if len(self._events) > MAX_EVENTS:
                # Drop the oldest. A client that reconnects further back than the
                # retained window is told the session expired rather than silently
                # receiving an incomplete report.
                del self._events[: len(self._events) - MAX_EVENTS]
            if kind in {"COMPLETE", "ERROR", "CANCELLED"}:
                self.state = (
                    SessionState.COMPLETE
                    if kind == "COMPLETE"
                    else SessionState.CANCELLED
                    if kind == "CANCELLED"
                    else SessionState.FAILED
                )
                self.finished = time.time()
            return event

    def replay(self, after: int = 0) -> list[Event]:
        with self._lock:
            return [event for event in self._events if event.seq > after]

    @property
    def last_seq(self) -> int:
        return self._seq

    @property
    def oldest_seq(self) -> int:
        with self._lock:
            return self._events[0].seq if self._events else 0


class SessionRegistry:
    """Bounded store of sessions for replay."""

    def __init__(self, max_sessions: int = MAX_SESSIONS, ttl: float = SESSION_TTL) -> None:
        self.max_sessions = max(1, max_sessions)
        self.ttl = ttl
        self._sessions: OrderedDict[str, Session] = OrderedDict()
        self._lock = threading.Lock()

    def create(self, input_identity: str = "") -> Session:
        session = Session(uuid.uuid4().hex, input_identity)
        with self._lock:
            self._sessions[session.session_id] = session
            self._evict_locked()
        return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if self._expired(session):
                return None
            return session

    def replay(self, session_id: str, after: int = 0) -> ReplayResult:
        """Replay events after ``after``, or report expiry explicitly."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return ReplayResult(
                    session_id=session_id,
                    state=None,
                    events=[],
                    expired=True,
                    reason="no such session; it may have expired or the server restarted",
                )
            if self._expired(session):
                return ReplayResult(
                    session_id=session_id,
                    state=session.state,
                    events=[],
                    expired=True,
                    reason="session expiry window has passed",
                )
            # A client asking for events older than retention cannot be served a
            # complete report, so say so instead of returning a partial one.
            if after and after < session.oldest_seq - 1:
                return ReplayResult(
                    session_id=session_id,
                    state=session.state,
                    events=[],
                    expired=True,
                    reason="requested events are outside the retained window",
                )
            return ReplayResult(
                session_id=session_id,
                state=session.state,
                events=session.replay(after),
            )

    def cancel(self, session_id: str) -> bool:
        session = self.get(session_id)
        if session is None:
            return False
        session.emit("CANCELLED", {"reason": "cancelled by client"})
        return True

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _expired(self, session: Session) -> bool:
        if session.finished is None:
            return False
        return time.time() - session.finished > self.ttl

    def _evict_locked(self) -> None:
        while len(self._sessions) > self.max_sessions:
            self._sessions.popitem(last=False)
        # Also drop anything past its TTL so a long-lived process does not leak.
        for session_id in [
            key for key, value in self._sessions.items() if self._expired(value)
        ]:
            self._sessions.pop(session_id, None)


#: The registry the endpoints share within one process.
REGISTRY = SessionRegistry()


__all__ = [
    "MAX_EVENTS",
    "MAX_SESSIONS",
    "REGISTRY",
    "SESSION_TTL",
    "Event",
    "ReplayResult",
    "Session",
    "SessionRegistry",
    "SessionState",
]
