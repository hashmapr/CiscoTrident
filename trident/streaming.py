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

from .models import AnalysisResponse, AnswerResult, ParserState


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
        # Serialising one answer must never kill the stream: a malformed result
        # becomes a structured ERROR event, and the caller's loop keeps running.
        try:
            event = StreamEvent(kind=EventKind.ANSWER, answer=_answer_dict(result))
        except Exception as exc:  # noqa: BLE001 - reported, not hidden
            return self.error(
                f"answer could not be serialised: {type(exc).__name__}: {exc}"
            )
        self._events.append(event)
        return event

    def complete(self, response: AnalysisResponse) -> StreamEvent:
        try:
            payload = {
                "file_name": response.file_name,
                "file_sha256": response.file_sha256,
                "snapshot_id": response.snapshot_id,
                "status_counts": _status_counts(response.results),
                "warnings": completion_warnings(response),
            }
        except Exception as exc:  # noqa: BLE001 - reported, not hidden
            return self.error(
                f"completion summary could not be built: {type(exc).__name__}: {exc}"
            )
        event = StreamEvent(kind=EventKind.COMPLETE, payload=payload)
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


def _decode_evidence(response: AnalysisResponse) -> tuple[list[str], list[str]] | None:
    """Engines that errored or abstained, when nothing at all was extracted.

    Returns ``(failed, abstained)`` only when no device was extracted *and* the
    engines themselves show a decoding problem. A file that decodes cleanly but
    genuinely holds no network has neither an errored engine nor an abstention,
    so it is not reported as undecodable.
    """
    summary = response.network_summary or {}
    if summary.get("devices"):
        return None
    failed = [report.engine for report in response.parsers if report.state is ParserState.ERROR]
    abstained = [
        report.engine
        for report in response.parsers
        if report.state is ParserState.OK and report.device_count == 0 and report.notes
    ]
    if not failed and not abstained:
        return None
    return failed, abstained


def completion_warnings(response: AnalysisResponse) -> list[str]:
    """Warnings for the COMPLETE event, including an honest decode verdict.

    The pipeline reports the generic "No devices were extracted" gap. When the
    engine reports themselves show that decoding failed (one errored, another
    abstained on a container integrity error), the summary must say the file
    could not be decoded. "Empty network" and "unreadable file" call for
    different user action, so they must not look identical in the stream.
    """
    warnings = list(response.warnings)
    if any("could not be decoded" in text for text in warnings):
        return warnings
    evidence = _decode_evidence(response)
    if evidence is None:
        return warnings
    failed, abstained = evidence
    engines = sorted({*failed, *abstained})
    warnings.append(
        "This file could not be decoded by the extraction engines "
        f"({', '.join(engines)} produced no network data). It is probably corrupt, "
        "truncated, or not a Packet Tracer save."
    )
    return warnings


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
    try:
        for name in stages:
            streamer.stage(name)
        for result in response.results:
            event = streamer.answer(result)
            if event.kind is EventKind.ERROR:
                # An answer that could not be serialised means the result set is
                # incomplete; a COMPLETE event afterwards would be a lie.
                return streamer.events
        streamer.complete(response)
    except Exception as exc:  # noqa: BLE001 - reported in-band, never raised
        streamer.error(f"event stream failed: {type(exc).__name__}: {exc}")
    return streamer.events


async def stream_analysis(response: AnalysisResponse) -> AsyncIterator[str]:
    """Yield SSE frames for an analysis, answers first, summary last.

    Stages are emitted before the answers because the analysis has already
    happened by the time this is called; labelling past work as a live stage
    would be dishonest. The caller that wants live stages drives
    :class:`AnswerStreamer` from inside the pipeline instead.

    A failure part-way through is reported as an in-band ERROR frame and the
    generator then ends. Once the response has started a traceback cannot become
    a status code, and a truncated stream with no terminal event is the worst
    outcome: the client cannot tell it from a slow one.
    """
    streamer = AnswerStreamer()
    try:
        streamer.stage("parsing")
        streamer.stage("consensus")
        streamer.stage("resolving")
        for result in response.results:
            event = streamer.answer(result)
            yield event.to_sse()
            if event.kind is EventKind.ERROR:
                # An answer that could not be serialised leaves the result set
                # incomplete; emitting COMPLETE next would misreport the run.
                return
        yield streamer.complete(response).to_sse()
    except Exception as exc:  # noqa: BLE001 - reported in-band, then terminate
        yield streamer.error(f"stream failed: {type(exc).__name__}: {exc}").to_sse()


__all__ = [
    "STAGES",
    "AnswerStreamer",
    "EventKind",
    "StreamEvent",
    "completion_warnings",
    "stream_analysis",
    "stream_events",
]
