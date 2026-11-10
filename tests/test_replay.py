"""Replayable analysis sessions.

A dropped connection must not cost a finished report, and a reconnect must not
duplicate or reorder anything. These tests pin both, plus the honest expiry path
when replay genuinely cannot be served.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from trident.replay import (
    MAX_EVENTS,
    ReplayResult,
    Session,
    SessionRegistry,
    SessionState,
)

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"


# ---------------------------------------------------------------------------
# Ordering and replay
# ---------------------------------------------------------------------------


def test_sequence_numbers_are_monotonic():
    session = Session("s1")
    events = [session.emit("SECTION", {"i": i}) for i in range(5)]
    assert [event.seq for event in events] == [1, 2, 3, 4, 5]


def test_replay_returns_only_events_after_the_cursor():
    session = Session("s1")
    for index in range(5):
        session.emit("SECTION", {"i": index})
    replayed = session.replay(after=2)
    assert [event.seq for event in replayed] == [3, 4, 5]


def test_replay_from_zero_returns_everything():
    session = Session("s1")
    for _ in range(3):
        session.emit("SECTION", {})
    assert len(session.replay(after=0)) == 3


def test_replay_at_the_end_returns_nothing():
    session = Session("s1")
    session.emit("COMPLETE")
    assert session.replay(after=session.last_seq) == []


def test_no_duplicates_and_no_gaps_across_two_reconnects():
    """The property that matters: cursor-based replay is exact."""
    session = Session("s1")
    for index in range(10):
        session.emit("SECTION", {"i": index})
    first = session.replay(after=0)
    cursor = first[3].seq
    second = session.replay(after=cursor)
    combined = first[:4] + second
    assert [event.seq for event in combined] == list(range(1, 11))
    assert len({event.seq for event in combined}) == 10


# ---------------------------------------------------------------------------
# Terminal states
# ---------------------------------------------------------------------------


def test_complete_sets_the_terminal_state():
    session = Session("s1")
    session.emit("COMPLETE")
    assert session.state is SessionState.COMPLETE
    assert session.finished is not None


def test_error_sets_a_failed_state():
    session = Session("s1")
    session.emit("ERROR", {"detail": "boom"})
    assert session.state is SessionState.FAILED


def test_cancelled_sets_a_cancelled_state():
    session = Session("s1")
    session.emit("CANCELLED", {})
    assert session.state is SessionState.CANCELLED


def test_a_running_session_has_no_finish_time():
    session = Session("s1")
    session.emit("SECTION", {})
    assert session.state is SessionState.RUNNING
    assert session.finished is None


# ---------------------------------------------------------------------------
# Bounded retention
# ---------------------------------------------------------------------------


def test_events_are_capped_and_the_newest_are_kept():
    session = Session("s1")
    for index in range(MAX_EVENTS + 50):
        session.emit("SECTION", {"i": index})
    replayed = session.replay(after=0)
    assert len(replayed) == MAX_EVENTS
    # The newest event must survive, and the oldest must be gone.
    assert replayed[-1].seq == MAX_EVENTS + 50
    assert replayed[0].seq > 1


def test_sessions_are_capped():
    registry = SessionRegistry(max_sessions=2)
    first = registry.create()
    second = registry.create()
    third = registry.create()
    assert registry.get(first.session_id) is None
    assert registry.get(second.session_id) is not None
    assert registry.get(third.session_id) is not None


# ---------------------------------------------------------------------------
# Expiry is explicit
# ---------------------------------------------------------------------------


def test_an_unknown_session_reports_expiry_rather_than_emptiness():
    registry = SessionRegistry()
    result = registry.replay("does-not-exist")
    assert isinstance(result, ReplayResult)
    assert result.expired is True
    assert result.reason
    assert result.events == []


def test_a_reconnect_beyond_retention_reports_expiry():
    registry = SessionRegistry()
    session = registry.create()
    for index in range(MAX_EVENTS + 20):
        session.emit("SECTION", {"i": index})
    # Asking from before the retained window cannot be served completely.
    result = registry.replay(session.session_id, after=1)
    assert result.expired is True
    assert "retained window" in result.reason


def test_a_reconnect_inside_retention_is_served():
    registry = SessionRegistry()
    session = registry.create()
    for _ in range(5):
        session.emit("SECTION", {})
    result = registry.replay(session.session_id, after=2)
    assert result.expired is False
    assert len(result.events) == 3


def test_a_ttl_expired_session_is_reported_as_expired():
    registry = SessionRegistry(ttl=0.0)
    session = registry.create()
    session.emit("COMPLETE")
    import time

    time.sleep(0.01)
    assert registry.get(session.session_id) is None
    assert registry.replay(session.session_id).expired is True


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


def test_cancel_marks_the_session_cancelled():
    registry = SessionRegistry()
    session = registry.create()
    assert registry.cancel(session.session_id) is True
    assert session.state is SessionState.CANCELLED


def test_cancelling_an_unknown_session_is_false_not_an_error():
    assert SessionRegistry().cancel("nope") is False


def test_a_disconnect_alone_does_not_cancel():
    """Closing a socket must not destroy a recoverable analysis."""
    registry = SessionRegistry()
    session = registry.create()
    session.emit("SECTION", {})
    # Nothing calls cancel; the session must still be alive and replayable.
    assert registry.get(session.session_id) is not None
    assert session.state is SessionState.RUNNING


# ---------------------------------------------------------------------------
# SSE framing
# ---------------------------------------------------------------------------


def test_an_event_carries_its_sequence_as_the_sse_id():
    session = Session("s1")
    event = session.emit("SECTION", {"i": 1})
    frame = event.to_sse()
    assert frame.startswith(f"id: {event.seq}\n")
    body = frame.split("data: ", 1)[1].strip()
    assert json.loads(body)["payload"] == {"i": 1}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _client():
    from fastapi.testclient import TestClient

    from trident.server import app

    return TestClient(app)


def test_stream_emits_a_session_id_first():
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    response = _client().post(
        "/api/network/analyze/stream",
        files={"file": ("l.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "quick"},
    )
    events = [
        json.loads(line[6:])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]
    assert events[0]["kind"] == "SESSION"
    assert events[0]["payload"]["session_id"]


def test_replay_endpoint_resumes_from_a_cursor():
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = _client()
    response = client.post(
        "/api/network/analyze/stream",
        files={"file": ("l.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "quick"},
    )
    events = [
        json.loads(line[6:])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]
    session_id = events[0]["payload"]["session_id"]
    replayed = client.get(
        f"/api/network/analyze/replay/{session_id}", params={"last_event_id": 3}
    ).json()
    assert replayed["expired"] is False
    kinds = [event["kind"] for event in replayed["events"]]
    assert "SECTION" in kinds
    assert kinds[-1] == "COMPLETE"
    # Nothing already seen is repeated.
    assert all(event["seq"] > 3 for event in replayed["events"])


def test_cancel_endpoint_is_explicit():
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = _client()
    response = client.post(
        "/api/network/analyze/stream",
        files={"file": ("l.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "quick"},
    )
    events = [
        json.loads(line[6:])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]
    session_id = events[0]["payload"]["session_id"]
    assert client.post(f"/api/network/analyze/cancel/{session_id}").json()["cancelled"] is True
    assert client.post("/api/network/analyze/cancel/nope").json()["cancelled"] is False
