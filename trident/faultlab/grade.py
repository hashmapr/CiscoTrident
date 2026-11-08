"""Kind-level grading of a diagnostic report against a scenario's answer key.

Scoring
-------

Let ``found`` be the number of manifest fault kinds the report named,
``missed`` the number of manifest kinds it did not name, and ``spurious`` the
number of kinds it named that are not in the manifest (including kinds outside
the taxonomy). Then::

    score = found / (found + missed + spurious)

Consequences:

* a perfect report scores exactly ``1.0``;
* an empty report scores ``0.0`` and never raises;
* every missed fault and every invented fault costs exactly one unit of the
  denominator, so a wrong guess is as expensive as a blind spot;
* a report that names everything in the taxonomy cannot game the score, because
  every wrong name lands in ``spurious``.

``exact_match`` is true only when at least one fault was expected and nothing
was missed, nothing was spurious, and no unknown kind was reported.
"""

from __future__ import annotations

from .types import FaultKind, Grade, Scenario

_UNKNOWN = object()


def _resolve(raw: object) -> FaultKind | object:
    """Map a report's ``kind`` value onto the taxonomy, or ``_UNKNOWN``."""
    if isinstance(raw, FaultKind):
        return raw
    text = str(raw or "").strip()
    if not text:
        return _UNKNOWN
    for candidate in (text, text.upper(), text.replace(" ", "_").upper()):
        try:
            return FaultKind(candidate)
        except ValueError:
            continue
    return _UNKNOWN


def grade(scenario: Scenario, reported: list[dict]) -> Grade:
    """Grade ``reported`` against ``scenario.faults``.

    ``reported`` is the shape a diagnostics engine emits, for example::

        [{"kind": "WRONG_VLAN", "device": "SW2", "interface": "Fa0/1",
          "confidence": "high"}]

    Only ``kind`` is graded; device and interface are advisory context for a
    human reviewer. Unknown or unrecognised kinds are treated as spurious.
    """
    present = {fault.kind for fault in scenario.faults}

    reported_kinds: set[FaultKind] = set()
    unknown_count = 0
    for entry in reported or []:
        kind = _resolve((entry or {}).get("kind"))
        if kind is _UNKNOWN:
            unknown_count += 1
        else:
            reported_kinds.add(kind)  # type: ignore[arg-type]

    found = sorted(reported_kinds & present, key=lambda kind: kind.value)
    missed = sorted(present - reported_kinds, key=lambda kind: kind.value)
    spurious = sorted(reported_kinds - present, key=lambda kind: kind.value)

    denominator = len(found) + len(missed) + len(spurious) + unknown_count
    score = len(found) / denominator if denominator else 0.0

    exact_match = (
        bool(present)
        and not missed
        and not spurious
        and unknown_count == 0
        and len(found) == len(present)
    )

    return Grade(
        scenario=scenario.name,
        found_kinds=tuple(found),
        missed_kinds=tuple(missed),
        spurious_kinds=tuple(spurious),
        exact_match=exact_match,
        score=score,
    )
