"""Streaming resilience: failures in-band, honest completion summaries.

A stream has already committed to HTTP 200 by the time the first frame leaves,
so every later failure has to be an event rather than an exception. These tests
pin three properties:

* a mid-stream exception becomes a structured ERROR and then ends the stream;
* a bad answer cannot abort the whole stream;
* a file the engines could not read says "could not be decoded" instead of
  looking like a successful analysis of an empty network.
"""

from __future__ import annotations

import asyncio
import json

from trident import streaming
from trident.models import (
    AnalysisResponse,
    AnswerResult,
    AnswerStatus,
    ParserReport,
    ParserState,
)
from trident.streaming import (
    AnswerStreamer,
    EventKind,
    completion_warnings,
    stream_analysis,
    stream_events,
)


def _response(*results: AnswerResult) -> AnalysisResponse:
    return AnalysisResponse(
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
        results=list(results),
        warnings=[],
        phase3={},
    )


def _answer(number: int = 1) -> AnswerResult:
    return AnswerResult(
        question_number=number,
        original_question="q",
        status=AnswerStatus.VERIFIED,
        answer="R1",
    )


def _frames_to_events(frames: list[str]) -> list[dict]:
    return [json.loads(frame[len("data: ") :].rstrip("\n")) for frame in frames]


async def _collect(iterator):
    return [frame async for frame in iterator]


# ---------------------------------------------------------------------------
# Mid-stream failure
# ---------------------------------------------------------------------------


def test_an_exception_mid_stream_emits_an_error_and_stops(monkeypatch):
    """Headers are already sent, so the failure must be an in-band ERROR event.

    It must also *end* the stream: an ERROR followed by a COMPLETE would tell
    the client the run finished successfully.
    """

    def explode(_result):
        raise RuntimeError("deliberate serialisation failure")

    monkeypatch.setattr(streaming, "_answer_dict", explode)
    response = _response(_answer(1), _answer(2))

    frames = asyncio.run(_collect(stream_analysis(response)))
    events = _frames_to_events(frames)

    assert events[-1]["kind"] == EventKind.ERROR.value
    assert "could not be serialised" in events[-1]["detail"]
    assert "RuntimeError" in events[-1]["detail"]
    assert all(event["kind"] != EventKind.COMPLETE.value for event in events)


def test_an_exception_inside_the_generator_is_reported_in_band(monkeypatch):
    """An error raised by the generator itself must not escape as a traceback."""

    def explode(self, _name):
        raise RuntimeError("deliberate stage failure")

    monkeypatch.setattr(streaming.AnswerStreamer, "stage", explode)

    frames = asyncio.run(_collect(stream_analysis(_response(_answer()))))
    events = _frames_to_events(frames)

    assert len(events) == 1
    assert events[0]["kind"] == EventKind.ERROR.value
    assert "stream failed" in events[0]["detail"]


def test_a_malformed_answer_becomes_an_error_event_not_an_exception(monkeypatch):
    """``AnswerStreamer.answer`` is called from the endpoint loop.

    If it raised, the endpoint's generator would die with a traceback. It must
    return an ERROR event so the loop can keep going.
    """

    def explode(_result):
        raise ValueError("bad answer")

    monkeypatch.setattr(streaming, "_answer_dict", explode)
    streamer = AnswerStreamer()
    event = streamer.answer(_answer())

    assert event.kind is EventKind.ERROR
    assert "could not be serialised" in event.detail


def test_stream_events_never_raises_on_a_bad_result(monkeypatch):
    def explode(_result):
        raise ValueError("bad answer")

    monkeypatch.setattr(streaming, "_answer_dict", explode)
    events = stream_events(_response(_answer()))

    assert events[-1].kind is EventKind.ERROR
    assert any(event.kind is EventKind.ERROR for event in events)


# ---------------------------------------------------------------------------
# Honest completion summary
# ---------------------------------------------------------------------------


def _corrupt_response() -> AnalysisResponse:
    """The shape the engines produce for a file whose container is unreadable."""
    return AnalysisResponse(
        file_name="bad.pkt",
        file_sha256="0" * 64,
        file_bytes=1,
        snapshot_id="",
        snapshot_ambiguous=True,
        snapshot_notes=[],
        parsers=[
            ParserReport(engine="engine_a", state=ParserState.ERROR),
            ParserReport(
                engine="engine_b",
                state=ParserState.OK,
                device_count=0,
                notes=["snapshot could not be determined (IntegrityError); abstaining"],
            ),
            ParserReport(engine="engine_c", state=ParserState.UNAVAILABLE),
        ],
        consensus_policy="strict",
        ai_used=False,
        network_summary={"devices": 0},
        results=[_answer(1)],
        warnings=[
            ("No devices were extracted. If this is a .pka, its snapshot blocks may "
            "be empty or the file may not contain network configuration.")
        ],
        phase3={},
    )


def test_completion_summary_says_the_file_could_not_be_decoded():
    warnings = completion_warnings(_corrupt_response())

    assert any("could not be decoded" in warning for warning in warnings), warnings
    joined = " ".join(warnings)
    assert "engine_a" in joined and "engine_b" in joined


def test_a_clean_but_empty_file_is_not_called_undecodable():
    """A decodable file that holds no network is a different situation."""
    response = _response()
    response.parsers = [ParserReport(engine="engine_a", state=ParserState.OK, device_count=0)]
    response.network_summary = {}
    response.warnings = ["No devices were extracted."]

    warnings = completion_warnings(response)
    assert not any("could not be decoded" in warning for warning in warnings)


def test_a_populated_network_is_never_called_undecodable():
    response = _response()
    response.parsers = [ParserReport(engine="engine_a", state=ParserState.ERROR)]
    response.network_summary = {"devices": 3}

    assert not any("could not be decoded" in warning for warning in completion_warnings(response))


def test_the_complete_event_carries_the_decode_verdict():
    events = stream_events(_corrupt_response())
    complete = events[-1]

    assert complete.kind is EventKind.COMPLETE
    assert any("could not be decoded" in warning for warning in complete.payload["warnings"])


def test_the_error_frame_stays_on_one_sse_line():
    streamer = AnswerStreamer()
    streamer.error("line one\nline two")
    frame = streamer.events[-1].to_sse()

    body = frame[len("data: ") :].rstrip("\n")
    assert "\n" not in body
    json.loads(body)
