"""TRIDENT EVOLVE: an evidence-backed failure and regression registry.

The purpose is narrow and deliberate. When TRIDENT gets something wrong, the
correction is worth more than the fix itself: it is a record of an assumption
that proved false, with the smallest input that demonstrates it. This module
stores those records so future planning can consult them.

Hard boundaries, encoded in the types rather than left to discipline:

* A record is only ``VALIDATED`` when the corrected outcome was established by a
  **live simulator observation** or by **consensus across extraction families**.
  A static suspicion can be recorded but can never become ground truth.
* Nothing here modifies behaviour on its own. There is no "apply lesson"
  function, because a registry that silently rewrites production logic is how
  systems drift. Lessons are *read* by planners; changes are made by a human.
* A record without a reproducible counterexample is stored as ``INCOMPLETE`` and
  is excluded from planning queries.

Storage is a JSON Lines file so appends are atomic and the history is auditable
by eye.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_REGISTRY = Path.home() / ".local" / "share" / "trident" / "evolve" / "registry.jsonl"


class EvidenceStrength(enum.StrEnum):
    """How the corrected result was established."""

    #: A live simulator produced the observed result.
    SIMULATOR_OBSERVED = "SIMULATOR_OBSERVED"
    #: Extraction families agreed on the corrected fact.
    CONSENSUS = "CONSENSUS"
    #: A human or an independent tool established it.
    EXTERNALLY_VERIFIED = "EXTERNALLY_VERIFIED"
    #: Reproduced from the source file alone. Valid for structural facts.
    STATIC_REPRODUCED = "STATIC_REPRODUCED"
    #: Not established. Recorded for follow-up, never usable as ground truth.
    UNVERIFIED = "UNVERIFIED"


class RecordState(enum.StrEnum):
    INCOMPLETE = "INCOMPLETE"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"


class RootCause(enum.StrEnum):
    """Coarse classification so records can be grouped."""

    DETECTOR_FALSE_POSITIVE = "DETECTOR_FALSE_POSITIVE"
    DETECTOR_FALSE_NEGATIVE = "DETECTOR_FALSE_NEGATIVE"
    PARSER_MISPARSE = "PARSER_MISPARSE"
    PARSER_TIMEOUT = "PARSER_TIMEOUT"
    EVIDENCE_CONFUSION = "EVIDENCE_CONFUSION"
    IDENTITY_ERROR = "IDENTITY_ERROR"
    REASONING_ERROR = "REASONING_ERROR"
    ENVIRONMENT = "ENVIRONMENT"
    OTHER = "OTHER"


#: Weakest-first ordering used to decide whether a record may be trusted.
_STRENGTH_ORDER = {
    EvidenceStrength.UNVERIFIED: 0,
    EvidenceStrength.STATIC_REPRODUCED: 1,
    EvidenceStrength.CONSENSUS: 2,
    EvidenceStrength.EXTERNALLY_VERIFIED: 3,
    EvidenceStrength.SIMULATOR_OBSERVED: 4,
}

#: The strength a corrected result needs before it can be treated as truth.
MIN_TRUSTED = EvidenceStrength.CONSENSUS


@dataclass
class Lesson:
    """One recorded mistake, with the smallest case that demonstrates it."""

    lesson_id: str
    input_identity: str
    question: str
    predicted: str
    actual: str
    incorrect_assumption: str
    root_cause: RootCause
    counterexample: str
    evidence: EvidenceStrength
    state: RecordState = RecordState.INCOMPLETE
    regression_test: str = ""
    proposed_fix: str = ""
    validation: str = ""
    created_at: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def trusted(self) -> bool:
        """Whether planning may rely on this record."""
        if self.state is not RecordState.VALIDATED:
            return False
        if _STRENGTH_ORDER[self.evidence] < _STRENGTH_ORDER[MIN_TRUSTED]:
            return False
        return bool(self.counterexample.strip())

    def as_dict(self) -> dict:
        return {
            "lesson_id": self.lesson_id,
            "input_identity": self.input_identity,
            "question": self.question,
            "predicted": self.predicted,
            "actual": self.actual,
            "incorrect_assumption": self.incorrect_assumption,
            "root_cause": self.root_cause.value,
            "counterexample": self.counterexample,
            "evidence": self.evidence.value,
            "state": self.state.value,
            "regression_test": self.regression_test,
            "proposed_fix": self.proposed_fix,
            "validation": self.validation,
            "created_at": self.created_at,
            "tags": list(self.tags),
            "trusted": self.trusted,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Lesson:
        return cls(
            lesson_id=data["lesson_id"],
            input_identity=data.get("input_identity", ""),
            question=data.get("question", ""),
            predicted=data.get("predicted", ""),
            actual=data.get("actual", ""),
            incorrect_assumption=data.get("incorrect_assumption", ""),
            root_cause=RootCause(data.get("root_cause", "OTHER")),
            counterexample=data.get("counterexample", ""),
            evidence=EvidenceStrength(data.get("evidence", "UNVERIFIED")),
            state=RecordState(data.get("state", "INCOMPLETE")),
            regression_test=data.get("regression_test", ""),
            proposed_fix=data.get("proposed_fix", ""),
            validation=data.get("validation", ""),
            created_at=data.get("created_at", ""),
            tags=list(data.get("tags", [])),
        )


def identity_of(data: bytes) -> str:
    """Stable identity for an input network."""
    return hashlib.sha256(data).hexdigest()


class Registry:
    """Append-only lesson store."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = (path or DEFAULT_REGISTRY).expanduser()

    # -- writes ------------------------------------------------------------

    def record(self, lesson: Lesson) -> Lesson:
        """Append a lesson. The record decides its own trustworthiness."""
        if not lesson.created_at:
            lesson.created_at = datetime.now(UTC).isoformat()
        if not lesson.lesson_id:
            lesson.lesson_id = uuid.uuid4().hex
        # A lesson with no counterexample cannot be validated: there would be
        # nothing to reproduce against.
        if not lesson.counterexample.strip() and lesson.state is RecordState.VALIDATED:
            lesson.state = RecordState.INCOMPLETE
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(lesson.as_dict()) + "\n")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return lesson

    def add(self, **kwargs) -> Lesson:
        """Convenience wrapper: build and append in one call."""
        kwargs.setdefault("lesson_id", "")
        return self.record(Lesson(**kwargs))

    # -- reads -------------------------------------------------------------

    def all(self) -> list[Lesson]:
        if not self.path.is_file():
            return []
        lessons: list[Lesson] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                lessons.append(Lesson.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, ValueError):
                # A corrupt line must not hide the rest of the history.
                continue
        return lessons

    def trusted(self) -> list[Lesson]:
        """Lessons planning may rely on."""
        return [lesson for lesson in self.all() if lesson.trusted]

    def for_input(self, identity: str) -> list[Lesson]:
        return [lesson for lesson in self.all() if lesson.input_identity == identity]

    def by_root_cause(self, cause: RootCause) -> list[Lesson]:
        return [lesson for lesson in self.all() if lesson.root_cause is cause]

    def relevant(self, tags: list[str], limit: int = 10) -> list[Lesson]:
        """Trusted lessons matching any tag, most recent first.

        This is the query a planner uses before proposing an experiment.
        """
        wanted = {tag.lower() for tag in tags if tag.strip()}
        if not wanted:
            return []
        matches = [
            lesson
            for lesson in self.trusted()
            if wanted & {tag.lower() for tag in lesson.tags}
        ]
        matches.sort(key=lambda lesson: lesson.created_at, reverse=True)
        return matches[:limit]

    def summary(self) -> dict:
        lessons = self.all()
        by_state: dict[str, int] = {}
        by_cause: dict[str, int] = {}
        for lesson in lessons:
            by_state[lesson.state.value] = by_state.get(lesson.state.value, 0) + 1
            by_cause[lesson.root_cause.value] = by_cause.get(lesson.root_cause.value, 0) + 1
        return {
            "total": len(lessons),
            "trusted": len([lesson for lesson in lessons if lesson.trusted]),
            "by_state": by_state,
            "by_root_cause": by_cause,
        }


__all__ = [
    "DEFAULT_REGISTRY",
    "EvidenceStrength",
    "Lesson",
    "RecordState",
    "Registry",
    "RootCause",
    "identity_of",
]
