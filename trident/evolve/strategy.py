"""EVOLVE strategy advice: let validated mistakes change what we test next.

The registry records what went wrong. This module turns those records into a
*planning input*, which is the only way a lesson has any effect.

Two constraints keep this from becoming an uncontrolled self-modifying loop:

* **Advice, not action.** :func:`advise` returns a suggested experiment ordering
  and the lessons that justify it. It does not execute anything, and a caller is
  free to ignore it.
* **Trusted lessons only.** :meth:`Registry.relevant` already filters to records
  whose corrected outcome was established by consensus or live observation *and*
  which carry a reproducible counterexample. A hypothesis someone wrote down is
  not advice.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..evolve.registry import Lesson, Registry, RootCause


class Preference(enum.StrEnum):
    """What the planner should do differently because of a lesson."""

    #: Run this check first instead of the default ordering.
    PREFER = "PREFER"
    #: Do not run this check until something else has been established.
    DEFER = "DEFER"
    #: Never trust this conclusion without an independent check.
    REQUIRE_EVIDENCE = "REQUIRE_EVIDENCE"


@dataclass
class Advice:
    """One suggestion, with the lessons that justify it."""

    preference: Preference
    target: str
    reason: str
    lessons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "preference": self.preference.value,
            "target": self.target,
            "reason": self.reason,
            "lessons": list(self.lessons),
        }


#: Which checks a root cause suggests reordering, and in which direction.
#: A false-positive detector means "establish this before concluding the other".
_CAUSE_STRATEGY: dict[RootCause, tuple[Preference, str]] = {
    RootCause.DETECTOR_FALSE_POSITIVE: (
        Preference.DEFER,
        (
            "this detector produced a confirmed false positive; require "
            "corroboration before acting on it"
        ),
    ),
    RootCause.DETECTOR_FALSE_NEGATIVE: (
        Preference.REQUIRE_EVIDENCE,
        "this check missed a real defect; do not accept its silence as proof",
    ),
    RootCause.REASONING_ERROR: (
        Preference.REQUIRE_EVIDENCE,
        (
            "a reasoning step produced a wrong conclusion; confirm with an "
            "operational experiment before reporting reachability"
        ),
    ),
    RootCause.PARSER_MISPARSE: (
        Preference.REQUIRE_EVIDENCE,
        "a parser produced wrong facts; cross-check against another family",
    ),
    RootCause.PARSER_TIMEOUT: (
        Preference.DEFER,
        (
            "this parser timed out on a real file; do not let its absence count "
            "as agreement"
        ),
    ),
    RootCause.EVIDENCE_CONFUSION: (
        Preference.REQUIRE_EVIDENCE,
        (
            "evidence categories were confused once; keep prediction and "
            "observation separate"
        ),
    ),
    RootCause.IDENTITY_ERROR: (
        Preference.DEFER,
        "device identity was wrong; resolve the device before reasoning about it",
    ),
}


def advise(
    registry: Registry,
    tags: list[str],
    limit: int = 5,
) -> list[Advice]:
    """Turn trusted lessons matching ``tags`` into planning advice.

    Returns one advice per distinct (preference, target) pair, newest lesson
    first. An empty list means no validated lesson applies — which is the normal
    case and means "behave as before", not "nothing is known".
    """
    lessons: list[Lesson] = registry.relevant(tags, limit=limit)
    if not lessons:
        return []

    seen: dict[tuple[Preference, str], Advice] = {}
    for lesson in lessons:
        strategy = _CAUSE_STRATEGY.get(lesson.root_cause)
        if strategy is None:
            continue
        preference, reason = strategy
        target = ",".join(sorted(tag.lower() for tag in lesson.tags)) or lesson.root_cause.value
        key = (preference, target)
        if key in seen:
            seen[key].lessons.append(lesson.lesson_id)
            continue
        seen[key] = Advice(
            preference=preference,
            target=target,
            reason=reason,
            lessons=[lesson.lesson_id],
        )
    return list(seen.values())


def reorder_experiments(candidates: list[str], advice: list[Advice]) -> list[str]:
    """Apply :class:`Preference.PREFER` advice to an experiment ordering.

    ``DEFER`` and ``REQUIRE_EVIDENCE`` are advisory notes, not reorderings: there
    is nothing sensible to move them to. Only an explicit PREFER changes order,
    which keeps the effect on behaviour small and auditable.
    """
    preferred = [
        item.target
        for item in advice
        if item.preference is Preference.PREFER
    ]
    if not preferred:
        return list(candidates)

    def rank(name: str) -> tuple[int, int]:
        lowered = name.lower()
        for index, target in enumerate(preferred):
            if target in lowered or lowered in target:
                return (0, index)
        return (1, 0)

    return sorted(candidates, key=rank)


__all__ = ["Advice", "Preference", "advise", "reorder_experiments"]
