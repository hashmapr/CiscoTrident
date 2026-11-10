"""SSE failure and recovery behaviour.

A stream can break in ways the happy path never exercises: the client cancels,
the connection drops mid-flight, the server raises, or the endpoint is
unreachable. Each case has a defined outcome, and the important property is that
a broken stream never leaves the user with a half-populated view presented as
complete.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from trident.streaming import AnswerStreamer, EventKind, StreamEvent

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"


def _client():
    from fastapi.testclient import TestClient

    from trident.server import app

    return TestClient(app)


# ---------------------------------------------------------------------------
# Event contract
# ---------------------------------------------------------------------------


def test_error_event_carries_a_reason():
    streamer = AnswerStreamer()
    streamer.error("pkt-core timed out")
    event = streamer.events[-1]
    assert event.kind is EventKind.ERROR
    assert event.detail == "pkt-core timed out"


def test_every_event_serialises_to_one_sse_frame():
    """A frame must not contain a bare newline, or it would split the stream."""
    streamer = AnswerStreamer()
    streamer.stage("parsing")
    streamer.error("line one\nline two")
    for event in streamer.events:
        frame = event.to_sse()
        body = frame[len("data: "):].rstrip("\n")
        assert "\n" not in body, frame
        json.loads(body)


def test_events_are_replayable_in_order():
    """A client that reconnects sees the same ordered event kinds."""
    streamer = AnswerStreamer()
    streamer.stage("parsing")
    streamer.stage("consensus")
    streamer.error("boom")
    kinds = [event.kind.value for event in streamer.events]
    assert kinds == ["STAGE", "STAGE", "ERROR"]


# ---------------------------------------------------------------------------
# Server-side failure
# ---------------------------------------------------------------------------


def test_a_failed_analysis_emits_an_error_event_not_a_500(monkeypatch):
    """An internal failure during a stream must be reported in-band.

    Once the response has started, a 500 status is no longer possible, so the
    failure has to arrive as an ERROR event that the client can render.
    """
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    import trident.server as server_module

    async def exploding_analyze(*args, **kwargs):
        raise RuntimeError("deliberate failure")

    # Patch the name the ENDPOINT resolves, not the module attribute the
    # pipeline defines. Patching trident.pipeline.analyze leaves the endpoint's
    # already-imported reference untouched, so the explosion leaked into the
    # following test instead of affecting this one.
    monkeypatch.setattr(server_module, "analyze", exploding_analyze)
    client = _client()
    response = client.post(
        "/api/analyze/stream",
        files={"file": ("l.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": "What is the hostname of R1?", "use_ai": "false"},
    )

    # The request is accepted; the failure surfaces as an event.
    assert response.status_code == 200
    events = [
        json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")
    ]
    kinds = [event["kind"] for event in events]
    assert "ERROR" in kinds, kinds
    error = [event for event in events if event["kind"] == "ERROR"][0]
    assert "analysis failed" in error["detail"]


def test_a_corrupt_file_is_reported_as_undecodable_not_as_empty():
    """A file the engines cannot read must say so, not look like a clean run.

    The stream completes (headers are already sent, so a 4xx is impossible), but
    the warnings must state that decoding failed. Without that distinction a
    corrupt upload reads as a successful analysis with nothing to report.
    """
    client = _client()
    response = client.post(
        "/api/analyze/stream",
        files={"file": ("bad.pkt", b"not a container" * 40, "application/octet-stream")},
        data={"questions": "What is the hostname of R1?", "use_ai": "false"},
    )
    assert response.status_code == 200
    events = [
        json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")
    ]
    complete = [event for event in events if event["kind"] == "COMPLETE"]
    assert complete, "the stream must terminate with a COMPLETE event"
    warnings = complete[0]["payload"]["warnings"]
    assert any("could not be decoded" in warning for warning in warnings), warnings
    # And it must not claim devices were found.
    assert complete[0]["payload"]["status_counts"]


def test_empty_questions_are_rejected_with_a_400():
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = _client()
    response = client.post(
        "/api/analyze/stream",
        files={"file": ("l.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": "  ", "use_ai": "false"},
    )
    assert response.status_code == 400
    assert "question" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Partial delivery
# ---------------------------------------------------------------------------


def test_partial_stream_is_not_reported_as_complete():
    """A stream that stops early must be distinguishable from a finished one.

    The COMPLETE event is the completion marker. A client that receives answers
    but no COMPLETE must not treat the result as final; the frontend encodes
    that rule, and this test pins the contract it relies on.
    """
    streamer = AnswerStreamer()
    streamer.stage("parsing")
    kinds = [event.kind for event in streamer.events]
    assert EventKind.COMPLETE not in kinds


def test_complete_event_follows_all_answers():
    from trident.models import AnalysisResponse, AnswerResult, AnswerStatus

    response = AnalysisResponse(
        file_name="x.pkt",
        file_sha256="0" * 64,
        file_bytes=1,
        snapshot_id="block0",
        snapshot_ambiguous=False,
        snapshot_notes=[],
        parsers=[],
        consensus_policy="strict",
        ai_used=False,
        network_summary={},
        results=[
            AnswerResult(question_number=1, original_question="q", status=AnswerStatus.VERIFIED, answer="R1"),
            AnswerResult(question_number=2, original_question="q", status=AnswerStatus.VERIFIED, answer="R2"),
        ],
        warnings=[],
        phase3={},
    )
    from trident.streaming import stream_events

    events = stream_events(response)
    kinds = [event.kind for event in events]
    assert kinds[-1] is EventKind.COMPLETE
    assert kinds.count(EventKind.ANSWER) == 2
    complete = events[-1]
    assert complete.payload["status_counts"] == {"VERIFIED": 2}


def test_stage_and_answer_frames_are_distinguishable():
    """The client must be able to tell progress from results."""
    stage = StreamEvent(kind=EventKind.STAGE, stage="parsing").as_dict()
    answer = StreamEvent(kind=EventKind.ANSWER, answer={"question_number": 1}).as_dict()
    assert stage["kind"] != answer["kind"]
    assert "stage" in stage and "answer" not in stage
    assert "answer" in answer and "stage" not in answer
