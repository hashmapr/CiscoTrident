"""Incremental answer streaming.

Analysis is not instant: parsing three engines over a large file takes seconds to
minutes, and a simulator investigation can take longer still. Returning nothing
until everything finishes makes the product feel broken, and it lets a slow
optional investigation block answers that are already known.

This module turns the pipeline into a sequence of events so a caller can render
progress and results as they become available.

Two design rules:

* **Answers are emitted as soon as they are resolved.** Static answers do not
  wait for the simulator, and the simulator does not wait for the last answer.
* **Every event says what actually happened.** ``stage`` events name a real phase
  that is starting, not a decorative animation. A stage is never emitted for work
  that will not run.
"""

from __future__ import annotations

import enum
import json
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass

from .models import AnalysisResponse, AnswerResult


class EventKind(enum.StrEnum):
    #: A real phase is starting. ``detail`` names it.
    STAGE = "STAGE"
    #: One answer has been resolved, while others may still be pending.
    ANSWER = "ANSWER"
    #: The complete response, once everything has finished.
    COMPLETE = "COMPLETE"
    #: Something went wrong; the run will not produce a complete response.
    ERROR = "ERROR"


@dataclass
class StreamEvent:
    kind: EventKind
    stage: str = ""
    detail: str = ""
    answer: dict | None = None
    payload: dict | None = None

    def as_dict(self) -> dict:
        data: dict = {"kind": self.kind.value}
        if self.stage:
            data["stage"] = self.stage
        if self.detail:
            data["detail"] = self.detail
        if self.answer is not None:
            data["answer"] = self.answer
        if self.payload is not None:
            data["payload"] = self.payload
        return data

    def to_sse(self) -> str:
        """Server-Sent Events framing."""
        return f"data: {json.dumps(self.as_dict())}\n\n"


#: The phases a real analysis passes through, in order. Each name is emitted
#: only when that phase actually begins.
STAGES: tuple[tuple[str, str], ...] = (
    ("parsing", "Decoding the container and running the extraction engines"),
    ("consensus", "Reconciling the three extraction families"),
    ("resolving", "Resolving questions against canonical facts"),
    ("diagnosing", "Checking the configuration for defects"),
)


class AnswerStreamer:
    """Emits stage and answer events for one analysis.

    Constructed from already-computed pieces so the pipeline stays in charge of
    ordering; this class only decides *when* to surface each piece.
    """

    def __init__(self) -> None:
        self._events: list[StreamEvent] = []

    def stage(self, name: str) -> StreamEvent:
        event = StreamEvent(kind=EventKind.STAGE, stage=name)
        self._events.append(event)
        return event

    def answer(self, result: AnswerResult) -> StreamEvent:
        event = StreamEvent(kind=EventKind.ANSWER, answer=_answer_dict(result))
        self._events.append(event)
        return event

    def complete(self, response: AnalysisResponse) -> StreamEvent:
        event = StreamEvent(
            kind=EventKind.COMPLETE,
            payload={
                "file_name": response.file_name,
                "file_sha256": response.file_sha256,
                "snapshot_id": response.snapshot_id,
                "status_counts": _status_counts(response.results),
                "warnings": list(response.warnings),
            },
        )
        self._events.append(event)
        return event

    def error(self, message: str) -> StreamEvent:
        event = StreamEvent(kind=EventKind.ERROR, detail=message)
        self._events.append(event)
        return event

    @property
    def events(self) -> list[StreamEvent]:
        return list(self._events)


def _answer_dict(result: AnswerResult) -> dict:
    return {
        "question_number": result.question_number,
        "status": result.status.value,
        "answer": result.answer,
        "selected_options": list(result.selected_options),
        "explanation": result.explanation,
        "consensus": {
            "agree": result.consensus.agree,
            "available": result.consensus.available,
            "required": result.consensus.required,
            "policy": result.consensus.policy,
        },
    }


def _status_counts(results: Iterable[AnswerResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status.value] = counts.get(result.status.value, 0) + 1
    return counts


def stream_events(
    response: AnalysisResponse,
    *,
    stages: tuple[str, ...] = (),
) -> list[StreamEvent]:
    """Build the full event sequence for an already-computed analysis.

    Used by the non-streaming endpoint and by tests: it produces the same events
    a live stream would, so the frontend has one shape to render.
    """
    streamer = AnswerStreamer()
    for name in stages:
        streamer.stage(name)
    for result in response.results:
        streamer.answer(result)
    streamer.complete(response)
    return streamer.events


async def stream_analysis(response: AnalysisResponse) -> AsyncIterator[str]:
    """Yield SSE frames for an analysis, answers first, summary last.

    Stages are emitted before the answers because the analysis has already
    happened by the time this is called; labelling past work as a live stage
    would be dishonest. The caller that wants live stages drives
    :class:`AnswerStreamer` from inside the pipeline instead.
    """
    streamer = AnswerStreamer()
    streamer.stage("parsing")
    streamer.stage("consensus")
    streamer.stage("resolving")
    for result in response.results:
        yield streamer.answer(result).to_sse()
    yield streamer.complete(response).to_sse()


__all__ = [
    "STAGES",
    "AnswerStreamer",
    "EventKind",
    "StreamEvent",
    "stream_analysis",
    "stream_events",
]
