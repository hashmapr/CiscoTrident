"""Streaming events and independent verification.

The properties under test are the ones that keep these features honest:

* a stage event means a real phase, not decoration;
* an answer event carries the same data the final response does;
* the verifier never upgrades evidence, and never claims to have confirmed
  something it could not independently re-derive.
"""

from __future__ import annotations

import asyncio
import json
import pathlib

import pytest

from trident.config import settings
from trident.ingestion import ingest
from trident.models import AnswerResult, AnswerStatus, NetworkModel
from trident.pipeline import analyze
from trident.streaming import (
    AnswerStreamer,
    EventKind,
    StreamEvent,
    stream_analysis,
    stream_events,
)
from trident.verification.independent import IndependentVerifier, Verdict

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"


def _analyzed(question: str = "What is the hostname of R1?"):
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    return asyncio.run(
        analyze(
            ingest(FIXTURE.name, FIXTURE.read_bytes(), settings),
            question,
            settings,
            use_ai=False,
        )
    )


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_events_follow_the_documented_order():
    outcome = _analyzed()
    events = stream_events(outcome.response, stages=("parsing", "consensus"))
    kinds = [event.kind for event in events]
    assert kinds[0] is EventKind.STAGE
    assert kinds[-1] is EventKind.COMPLETE
    assert EventKind.ANSWER in kinds
    # Every stage comes before every answer: progress precedes results.
    last_stage = max(i for i, k in enumerate(kinds) if k is EventKind.STAGE)
    first_answer = min(i for i, k in enumerate(kinds) if k is EventKind.ANSWER)
    assert last_stage < first_answer


def test_answer_event_matches_the_final_response():
    outcome = _analyzed()
    events = stream_events(outcome.response)
    streamed = [e.answer for e in events if e.kind is EventKind.ANSWER]
    assert len(streamed) == len(outcome.response.results)
    for event_answer, result in zip(streamed, outcome.response.results):
        assert event_answer["question_number"] == result.question_number
        assert event_answer["status"] == result.status.value
        assert event_answer["answer"] == result.answer


def test_complete_event_carries_status_counts():
    outcome = _analyzed()
    events = stream_events(outcome.response)
    complete = [e for e in events if e.kind is EventKind.COMPLETE][0]
    assert "status_counts" in complete.payload
    assert sum(complete.payload["status_counts"].values()) == len(outcome.response.results)


def test_events_are_json_serialisable():
    outcome = _analyzed()
    for event in stream_events(outcome.response, stages=("parsing",)):
        json.dumps(event.as_dict())


def test_sse_framing_is_valid():
    event = StreamEvent(kind=EventKind.STAGE, stage="parsing")
    frame = event.to_sse()
    assert frame.startswith("data: ")
    assert frame.endswith("\n\n")
    assert json.loads(frame[len("data: "):].strip())["stage"] == "parsing"


def test_stage_is_only_emitted_when_called():
    """No decorative stages: the streamer emits what it is told to emit."""
    streamer = AnswerStreamer()
    assert streamer.events == []
    streamer.stage("parsing")
    assert [e.stage for e in streamer.events] == ["parsing"]


def test_error_event_is_distinct():
    streamer = AnswerStreamer()
    streamer.error("engine B failed")
    event = streamer.events[0]
    assert event.kind is EventKind.ERROR
    assert "engine B failed" in event.detail


def test_stream_analysis_yields_sse_for_every_answer():
    outcome = _analyzed()

    async def collect():
        return [frame async for frame in stream_analysis(outcome.response)]

    frames = asyncio.run(collect())
    assert len(frames) == len(outcome.response.results) + 1  # answers + COMPLETE


# ---------------------------------------------------------------------------
# Independent verification
# ---------------------------------------------------------------------------


def _answer(number: int, status: AnswerStatus, text: str | None) -> AnswerResult:
    return AnswerResult(
        question_number=number,
        original_question="q",
        status=status,
        answer=text,
    )


def _model() -> NetworkModel:
    from trident.models import DeviceInfo, InterfaceInfo

    return NetworkModel(
        devices={
            "R1": DeviceInfo(id="R1", name="R1", hostname="R1", device_type="router", configuration=[]),
        },
        interfaces={
            "R1:Gi0/0": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/0",
                canonical_name="GigabitEthernet0/0",
                ipv4_address="10.0.0.1",
                prefix_length=24,
            )
        },
    )


def test_verifier_confirms_a_named_device_that_exists():
    report = IndependentVerifier(_model()).verify([_answer(1, AnswerStatus.VERIFIED, "R1")])
    assert report.records[0].verdict is Verdict.CONFIRMED
    assert report.records[0].method == "entity-existence"


def test_verifier_disagrees_when_an_address_is_unowned():
    report = IndependentVerifier(_model()).verify(
        [_answer(1, AnswerStatus.VERIFIED, "the gateway is 10.0.0.99")]
    )
    assert report.records[0].verdict is Verdict.DISAGREES
    assert "assigns" in report.records[0].detail


def test_verifier_confirms_an_owned_address():
    report = IndependentVerifier(_model()).verify(
        [_answer(1, AnswerStatus.VERIFIED, "10.0.0.1")]
    )
    assert report.records[0].verdict is Verdict.CONFIRMED
    assert "R1" in report.records[0].detail


def test_unresolved_answers_are_not_counted_as_confirmed():
    report = IndependentVerifier(_model()).verify(
        [_answer(1, AnswerStatus.INCOMPLETE, "R1")]
    )
    assert report.records[0].verdict is Verdict.UNRESOLVED


def test_uncheckable_answers_say_so_rather_than_passing():
    """An answer with no derivation route must not be silently confirmed."""
    report = IndependentVerifier(_model()).verify(
        [_answer(1, AnswerStatus.VERIFIED, "the answer is forty-two")]
    )
    assert report.records[0].verdict is Verdict.NOT_INDEPENDENTLY_CHECKABLE
    assert report.records[0].limitations


def test_verifier_never_changes_the_answer_status():
    """Verification reports; it does not promote evidence."""
    answer = _answer(1, AnswerStatus.VERIFIED, "R1")
    before = answer.status
    IndependentVerifier(_model()).verify([answer])
    assert answer.status is before


def test_report_counts_and_serialisation():
    report = IndependentVerifier(_model()).verify(
        [
            _answer(1, AnswerStatus.VERIFIED, "R1"),
            _answer(2, AnswerStatus.VERIFIED, "10.0.0.99"),
            _answer(3, AnswerStatus.INCOMPLETE, None),
        ]
    )
    counts = report.counts()
    assert counts["total"] == 3
    assert counts["CONFIRMED"] == 1
    assert counts["DISAGREES"] == 1
    assert counts["UNRESOLVED"] == 1
    json.dumps(report.as_dict())
    assert len(report.disagreeing) == 1


def test_real_analysis_is_independently_confirmed():
    outcome = _analyzed()
    report = IndependentVerifier(outcome.model).verify(outcome.response.results)
    assert report.counts()["total"] == len(outcome.response.results)
    # Nothing that reached VERIFIED may be contradicted by an independent read.
    assert report.disagreeing == [], [r.as_dict() for r in report.disagreeing]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def test_stream_endpoint_emits_sse_frames():
    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = TestClient(app)
    response = client.post(
        "/api/analyze/stream",
        files={"file": ("s.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": "What is the hostname of R1?", "use_ai": "false"},
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    events = [
        json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")
    ]
    kinds = [event["kind"] for event in events]
    assert kinds.count("ANSWER") == 1
    assert kinds[-1] == "COMPLETE"
    assert "STAGE" in kinds


def test_verify_endpoint_returns_an_independent_report():
    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = TestClient(app)
    response = client.post(
        "/api/analyze/verify",
        files={"file": ("s.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": "What is the hostname of R1?", "use_ai": "false"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "verification" in payload
    counts = payload["verification"]["counts"]
    assert counts["total"] == len(payload["results"])
    assert counts["DISAGREES"] == 0


def test_stream_endpoint_rejects_an_empty_question_set():
    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = TestClient(app)
    response = client.post(
        "/api/analyze/stream",
        files={"file": ("s.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": "   ", "use_ai": "false"},
    )
    assert response.status_code == 400


def test_frontend_uses_the_streaming_endpoint():
    """The new capability must be reachable from the real UI, not just the API."""
    web = pathlib.Path(__file__).parents[1] / "trident" / "web" / "app.js"
    source = web.read_text()
    assert "/api/analyze/stream" in source
    assert "analyzeStreamed" in source
    assert "handleStreamEvent" in source
    # And it must still be able to fall back.
    assert '"/api/analyze"' in source
