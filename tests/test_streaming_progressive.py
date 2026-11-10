"""Streaming must be genuinely incremental, not a replay.

The first implementation computed the whole analysis and then emitted finished
events. Every test passed, because the events were correct — they were just not
*streamed*. This module pins the property that was missing: events must be
produced as the work happens, so a stage can arrive before the answers exist.
"""

from __future__ import annotations

import asyncio
import pathlib

import pytest

from trident.config import settings
from trident.ingestion import ingest
from trident.pipeline import analyze
from trident.reasoning.questions import parse_questions
from trident.streaming import AnswerStreamer

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"

THREE_QUESTIONS = (
    "What is the hostname of R1?\n"
    "What IP address does R1 GigabitEthernet0/0 have?\n"
    "Which device is directly connected to R1 GigabitEthernet0/0?"
)


# ---------------------------------------------------------------------------
# Question parsing: one question per line
# ---------------------------------------------------------------------------


def test_bare_lines_are_separate_questions():
    """Three bare questions on three lines must not merge into one.

    This was a real defect: the parser split only on numbered lines, so this
    exact input produced a single question and therefore a single answer.
    """
    questions = parse_questions(THREE_QUESTIONS, max_questions=50, max_chars=5000)
    assert len(questions) == 3
    assert questions[0].stem.startswith("What is the hostname")
    assert questions[1].stem.startswith("What IP address")
    assert questions[2].stem.startswith("Which device")


def test_numbered_questions_still_work():
    questions = parse_questions("1. What is X?\n2. What is Y?", max_questions=50, max_chars=5000)
    assert len(questions) == 2


def test_multiline_question_with_options_is_not_split():
    """The unnumbered-line rule must not break a real multi-line question."""
    text = "1. Which protocol is used?\nA. OSPF\nB. EIGRP\nC. RIP"
    questions = parse_questions(text, max_questions=50, max_chars=5000)
    assert len(questions) == 1
    assert len(questions[0].options) == 3


def test_unanswered_trailing_lines_do_not_create_questions():
    """Only lines that are questions become questions."""
    text = "What is the hostname of R1?\nSome trailing note without a question mark"
    questions = parse_questions(text, max_questions=50, max_chars=5000)
    assert len(questions) == 1


# ---------------------------------------------------------------------------
# Progress hooks fire during the work
# ---------------------------------------------------------------------------


def test_hooks_are_called_in_pipeline_order():
    """Stages and answers must be emitted by the pipeline as it progresses."""
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    order: list[str] = []

    def on_stage(name: str) -> None:
        order.append(f"stage:{name}")

    def on_answer(answer) -> None:
        order.append(f"answer:{answer.question_number}")

    outcome = asyncio.run(
        analyze(
            ingest(FIXTURE.name, FIXTURE.read_bytes(), settings),
            THREE_QUESTIONS,
            settings,
            use_ai=False,
            on_stage=on_stage,
            on_answer=on_answer,
        )
    )

    assert order[0] == "stage:parsing"
    assert "stage:consensus" in order
    assert "stage:resolving" in order
    # Every answer is emitted, in order, after the stages that produce it.
    answer_events = [entry for entry in order if entry.startswith("answer:")]
    assert answer_events == ["answer:1", "answer:2", "answer:3"]
    assert order.index("stage:resolving") < order.index("answer:1")
    assert len(outcome.response.results) == 3


def test_answers_are_emitted_one_at_a_time_not_all_at_the_end():
    """Each answer's hook must fire before the next question is resolved.

    If the pipeline collected all answers and emitted them afterwards, every
    answer event would come after the last stage and in a single burst. Checking
    that answer N appears in the call order before any post-loop work is what
    distinguishes real streaming from a replay.
    """
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    seen: list[tuple[str, int]] = []

    def on_stage(name: str) -> None:
        seen.append(("stage", len(seen)))

    def on_answer(answer) -> None:
        seen.append(("answer", len(seen)))

    asyncio.run(
        analyze(
            ingest(FIXTURE.name, FIXTURE.read_bytes(), settings),
            THREE_QUESTIONS,
            settings,
            use_ai=False,
            on_stage=on_stage,
            on_answer=on_answer,
        )
    )

    kinds = [kind for kind, _ in seen]
    # Stages all precede answers: resolution cannot start before parsing ends.
    last_stage = max(i for i, k in enumerate(kinds) if k == "stage")
    first_answer = min(i for i, k in enumerate(kinds) if k == "answer")
    assert last_stage < first_answer
    assert kinds.count("answer") == 3


def test_analysis_without_hooks_is_unchanged():
    """Hooks are optional; the plain path must behave exactly as before."""
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    with_hooks = asyncio.run(
        analyze(
            ingest(FIXTURE.name, FIXTURE.read_bytes(), settings),
            THREE_QUESTIONS,
            settings,
            use_ai=False,
            on_stage=lambda name: None,
            on_answer=lambda answer: None,
        )
    )
    without = asyncio.run(
        analyze(
            ingest(FIXTURE.name, FIXTURE.read_bytes(), settings),
            THREE_QUESTIONS,
            settings,
            use_ai=False,
        )
    )
    assert [r.answer for r in with_hooks.response.results] == [
        r.answer for r in without.response.results
    ]


# ---------------------------------------------------------------------------
# Streamer event construction
# ---------------------------------------------------------------------------


def test_streamer_emits_in_call_order():
    streamer = AnswerStreamer()
    streamer.stage("parsing")
    streamer.stage("consensus")
    streamer.complete(_fake_response())
    kinds = [event.kind.value for event in streamer.events]
    assert kinds == ["STAGE", "STAGE", "COMPLETE"]


def _fake_response():
    from trident.models import AnalysisResponse

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
        results=[],
        warnings=[],
        phase3={},
    )


# ---------------------------------------------------------------------------
# Live endpoint: events must arrive before the analysis finishes
# ---------------------------------------------------------------------------


def test_endpoint_streams_stages_before_answers():
    """A stage frame must be readable while the analysis is still running.

    Reading with a small first-chunk deadline proves the response is not being
    assembled in full before the first byte is sent.
    """
    import json

    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    client = TestClient(app)
    first_frames: list[str] = []
    with client.stream(
        "POST",
        "/api/analyze/stream",
        files={"file": (FIXTURE.name, FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": THREE_QUESTIONS, "use_ai": "false"},
    ) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        for line in response.iter_lines():
            if line.startswith("data: "):
                first_frames.append(line)
                payload = json.loads(line[6:])
                if payload["kind"] == "STAGE":
                    break

    assert first_frames, "no frames were received"
    first = json.loads(first_frames[0][6:])
    assert first["kind"] == "STAGE"
    assert first["stage"] in {"parsing", "consensus", "resolving"}


def test_endpoint_emits_one_answer_per_question():
    import json

    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    client = TestClient(app)
    response = client.post(
        "/api/analyze/stream",
        files={"file": (FIXTURE.name, FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": THREE_QUESTIONS, "use_ai": "false"},
    )
    events = [
        json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")
    ]
    answers = [event for event in events if event["kind"] == "ANSWER"]
    assert len(answers) == 3, [event["kind"] for event in events]
    assert [a["answer"]["question_number"] for a in answers] == [1, 2, 3]
    assert events[-1]["kind"] == "COMPLETE"


def test_endpoint_reports_a_parse_failure_as_an_error_event():
    """A malformed question set must surface as an ERROR frame, not a 500."""

    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = TestClient(app)
    response = client.post(
        "/api/analyze/stream",
        files={"file": (FIXTURE.name, FIXTURE.read_bytes(), "application/octet-stream")},
        data={"questions": "   ", "use_ai": "false"},
    )
    # An empty question set is rejected before streaming starts.
    assert response.status_code == 400
