"""``trident practice`` — a scored CyberPatriot-style practice runner.

The student-facing flow is deliberately one-directional:

    analyse a lab  ->  see the objectives  ->  get progressive hints  ->  submit

The **answer key never enters the analysis context**. The lab is analysed as an
ordinary ``.pkt``; findings are matched against the instructor manifest only
*after* a submission, and only to score. That separation is the whole point: a
practice system that leaks the key teaches a student to read the key.

Everything here is bounded. No loop polls, every simulator call has a timeout,
and the session is closed in a ``finally``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .labgen.spec import FaultCategory, FaultSpec, Severity, TargetKind, TopologySpec


class PracticeError(RuntimeError):
    """A practice run could not proceed, with a reason a student can act on."""


#: How precisely a diagnosis must be stated. This is what difficulty changes.
#:
#: It must NOT scale the total: an earlier version multiplied the awarded points
#: by 0.6/0.8, so a student who found all 15 faults scored 60 or 80 out of 100
#: and could never reach full marks. Difficulty changes what counts as a
#: complete diagnosis, not how much a lab is worth.
PRECISION: dict[Literal["beginner", "intermediate", "advanced"], str] = {
    "beginner": "device",        # naming the right device is enough
    "intermediate": "interface",  # interface needed, half credit without
    "advanced": "interface",      # interface required, no half credit
}


@dataclass(frozen=True)
class Objective:
    """One thing the student must achieve, without revealing how.

    ``objective_id`` is a slug a student can type back; it does not encode the
    answer. ``title`` states the goal in outcome language.
    """

    objective_id: str
    title: str
    category: FaultCategory
    points: int


@dataclass(frozen=True)
class Hint:
    """A progressive hint. Costs points, never reveals the fix outright."""

    fault_id: str
    level: int
    text: str
    penalty: int


#: Where hit progression persists between CLI invocations.
HINT_STATE_FILE = Path.home() / ".local" / "state" / "trident" / "practice_hints.json"


def load_hint_state(lab: str) -> dict[str, int]:
    """Hints already taken for a lab, so a second invocation advances.

    A ``trident practice --hint`` call is a fresh process. Without this the
    "next" hint was always hint 1, which made progressive hints impossible from
    the shell.
    """
    try:
        data = json.loads(HINT_STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}
    entry = data.get(lab)
    return dict(entry) if isinstance(entry, dict) else {}


def save_hint_state(lab: str, state: dict[str, int]) -> None:
    try:
        HINT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(HINT_STATE_FILE.read_text())
        except (OSError, ValueError):
            data = {}
        data[lab] = state
        HINT_STATE_FILE.write_text(json.dumps(data, indent=2))
    except OSError:
        # Progress is a convenience; a read-only home must not break scoring.
        return


@dataclass
class PracticeSession:
    """One student attempt against one lab.

    Holds the objectives and the hint budget. The manifest is present but the
    student-facing methods never return it: :meth:`objectives` returns goals,
    :meth:`hint` returns a single progressive line.
    """

    spec: TopologySpec
    difficulty: Literal["beginner", "intermediate", "advanced"] = "intermediate"
    hints_used: dict[str, int] = field(default_factory=dict)
    submitted: bool = False

    def __post_init__(self) -> None:
        if not self.hints_used:
            self.hints_used = load_hint_state(self.spec.name)

    # -- student-facing surface --------------------------------------------

    def objectives(self) -> list[Objective]:
        """The goals, grouped in a stable order and stripped of the answer."""
        return [
            Objective(
                objective_id=_objective_id(fault),
                title=_objective_title(fault),
                category=fault.category,
                points=fault.points,
            )
            for fault in self.spec.faults
        ]

    def hint(self, objective_id: str) -> Hint:
        """The next hint for one objective.

        Hints are strictly ordered: level 1 is a direction, level 2 narrows it.
        Asking twice for the same objective advances the level rather than
        repeating itself, and the penalty is charged once per hint given.
        """
        fault = self._fault_for(objective_id)
        used = self.hints_used.get(objective_id, 0)
        if used >= 2:
            raise PracticeError(
                f"no further hints for {objective_id}; both are already shown"
            )
        level = used + 1
        text = fault.hint_1 if level == 1 else fault.hint_2
        self.hints_used[objective_id] = level
        save_hint_state(self.spec.name, self.hints_used)
        penalty = max(1, fault.points // max(1, len(self.spec.faults)) // 2) if level == 2 else 0
        return Hint(fault_id=fault.fault_id, level=level, text=text, penalty=penalty)

    def hint_penalty(self) -> int:
        """Total points lost to hints so far."""
        total = 0
        for objective_id, level in self.hints_used.items():
            if level >= 2:
                fault = self._fault_for(objective_id)
                total += max(1, fault.points // max(1, len(self.spec.faults)) // 2)
        return total

    def _fault_for(self, objective_id: str) -> FaultSpec:
        for fault in self.spec.faults:
            if _objective_id(fault) == objective_id:
                return fault
        raise PracticeError(f"unknown objective {objective_id!r}")

    # -- instructor-facing surface -----------------------------------------

    def answer_key(self) -> dict:
        """The full key, including expected and actual configuration.

        Never call this from a student-facing path. It is here so the CLI can
        write the instructor file explicitly, on request.
        """
        return {
            "lab": self.spec.name,
            "title": self.spec.title,
            "point_total": self.spec.point_total(),
            "faults": [
                {
                    "fault_id": f.fault_id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "device": f.device,
                    "interface": f.interface,
                    "expected": f.expected,
                    "actual": f.actual,
                    "description": f.description,
                    "symptom": f.symptom,
                    "points": f.points,
                    "hint_1": f.hint_1,
                    "hint_2": f.hint_2,
                }
                for f in self.spec.faults
            ],
        }


def _objective_id(fault: FaultSpec) -> str:
    """A stable, unique, non-revealing slug for an objective.

    Derived from the fault id rather than its last token: ``obj-vlan-wrong``
    was produced twice for two different VLAN faults, so a hint request for it
    resolved to whichever fault happened to come first.
    """
    return f"obj-{fault.fault_id}"


def _objective_title(fault: FaultSpec) -> str:
    """Outcome language: what must be true, not what is broken.

    Derived from the category rather than the fault text, because the fault text
    names the defect and the objective must not.
    """
    titles = {
        FaultCategory.ADDRESSING: "Device addressing is correct for its subnet",
        FaultCategory.VLAN: "VLAN membership matches the department plan",
        FaultCategory.TRUNK: "The trunk carries every VLAN with one native VLAN",
        FaultCategory.ROUTING: "Routing reaches every required destination",
        FaultCategory.GATEWAY: "Every host has a reachable default gateway",
        FaultCategory.DHCP: "DHCP serves each department correctly",
        FaultCategory.DNS: "Name resolution is configured for every pool",
        FaultCategory.INTERFACE: "Every required interface is operational",
        FaultCategory.SECURITY: "Management access requires authentication",
        FaultCategory.ACCESS: "Access control permits required traffic",
    }
    return titles.get(fault.category, "Configuration matches the brief")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """What the student's submission claims is wrong."""

    device: str
    category: str | None = None
    interface: str | None = None
    fault_id: str | None = None


@dataclass
class ScoreLine:
    fault_id: str
    category: str
    device: str
    points_possible: int
    points_awarded: int
    correct: bool
    reason: str
    expected: str
    actual: str
    evidence_hint: str


@dataclass
class Score:
    lab: str
    difficulty: str
    total_possible: int
    raw_score: int
    hint_penalty: int
    final_score: int
    lines: list[ScoreLine]
    missed: list[str]
    spurious: list[Finding]

    def as_dict(self, *, include_key: bool = False) -> dict:
        """Student-facing score by default; the full key only on request.

        ``expected``/``actual`` are omitted for *missed* faults unless
        ``include_key`` is set. They were present in the first version, so
        ``--json`` handed the student the answer for everything they got wrong —
        which is the same leak as printing the key, one field at a time.
        """
        lines = []
        for line in self.lines:
            entry = dict(line.__dict__)
            if not include_key and not line.correct:
                entry.pop("expected", None)
                entry.pop("actual", None)
            lines.append(entry)
        return {
            "lab": self.lab,
            "difficulty": self.difficulty,
            "total_possible": self.total_possible,
            "raw_score": self.raw_score,
            "hint_penalty": self.hint_penalty,
            "final_score": self.final_score,
            "lines": lines,
            "missed": self.missed,
            "spurious": [f.__dict__ for f in self.spurious],
        }


def score_submission(
    session: PracticeSession, findings: list[Finding]
) -> Score:
    """Score a submission against the manifest.

    Matching rules, in order of credit:

    * right device **and** right interface (when the fault has one) — full points
    * right device, wrong or missing interface — half points at
      ``intermediate``/``advanced``, full at ``beginner``
    * wrong device — no credit, and the claim is recorded as spurious

    Difficulty scales how precise a diagnosis must be, which is the only thing
    it is allowed to change: the fault set and the point total stay the same so
    two students on different difficulties are practising the same lab.
    """
    precision = PRECISION.get(session.difficulty, "interface")
    lines: list[ScoreLine] = []
    missed: list[str] = []
    used: set[int] = set()

    for fault in session.spec.faults:
        # Match specificity, best first. Each pass is a complete scan so a
        # vague finding can never consume a specific one.
        #
        #   1. explicit fault_id
        #   2. device + interface + category (when all three are stated)
        #   3. device + interface
        #   4. device + category
        #   5. device only, and only for a fault with no interface/category to
        #      disambiguate it
        #
        # An earlier single-pass version let `R1 DHCP` match the routing fault:
        # both were "R1", and the first unmatched finding on that device won.
        def _norm(text: str | None) -> str:
            return (text or "").strip().lower()

        def _passes(predicate) -> int | None:
            for index, finding in enumerate(findings):
                if index in used:
                    continue
                if predicate(finding):
                    return index
            return None

        match_index = _passes(
            lambda f, _fault=fault: bool(f.fault_id) and f.fault_id == _fault.fault_id
        )
        if match_index is None:
            match_index = _passes(
                lambda f, _fault=fault: _norm(f.device) == _norm(_fault.device)
                and _fault.interface is not None
                and _norm(f.interface) == _norm(_fault.interface)
                and bool(f.category)
                and _norm(f.category) == _norm(_fault.category.value)
            )
        if match_index is None:
            match_index = _passes(
                lambda f, _fault=fault: _norm(f.device) == _norm(_fault.device)
                and _fault.interface is not None
                and _norm(f.interface) == _norm(_fault.interface)
            )
        if match_index is None:
            match_index = _passes(
                lambda f, _fault=fault: _norm(f.device) == _norm(_fault.device)
                and bool(f.category)
                and _norm(f.category) == _norm(_fault.category.value)
            )
        if match_index is None and fault.interface is None:
            match_index = _passes(
                lambda f, _fault=fault: _norm(f.device) == _norm(_fault.device)
                and not f.interface
                and not f.category
            )
        if match_index is None:
            missed.append(fault.fault_id)
            lines.append(
                ScoreLine(
                    fault_id=fault.fault_id,
                    category=fault.category.value,
                    device=fault.device,
                    points_possible=fault.points,
                    points_awarded=0,
                    correct=False,
                    reason="not identified",
                    expected=fault.expected,
                    actual=fault.actual,
                    evidence_hint=fault.symptom,
                )
            )
            continue

        used.add(match_index)
        finding = findings[match_index]
        precise = bool(
            fault.interface
            and finding.interface
            and finding.interface.strip().lower() == fault.interface.strip().lower()
        )
        # Precision is only meaningful where the defect lives on an interface a
        # student can name. An end-host NIC or a VLAN-database entry has no such
        # interface: requiring one made a complete diagnosis score 90/100.
        interface_fault = fault.target in {
            TargetKind.INTERFACE_LINE,
            TargetKind.CONTEXT_LINE,
        }
        award = fault.points
        reason = "correct"
        if interface_fault and fault.interface and not precise:
            if precision == "device":
                reason = "correct device; interface not required at this difficulty"
            elif precision == "interface" and session.difficulty == "intermediate":
                award = fault.points // 2
                reason = (
                    "right device, but the interface was not identified; "
                    "half credit at intermediate difficulty"
                )
            else:
                award = 0
                reason = (
                    "right device, but the interface was not identified; "
                    f"{session.difficulty} difficulty requires it"
                )
        lines.append(
            ScoreLine(
                fault_id=fault.fault_id,
                category=fault.category.value,
                device=fault.device,
                points_possible=fault.points,
                points_awarded=award,
                correct=True,
                reason=reason,
                expected=fault.expected,
                actual=fault.actual,
                evidence_hint=fault.symptom,
            )
        )

    spurious = [f for index, f in enumerate(findings) if index not in used]
    raw = sum(line.points_awarded for line in lines)
    penalty = session.hint_penalty()
    return Score(
        lab=session.spec.name,
        difficulty=session.difficulty,
        total_possible=session.spec.point_total(),
        raw_score=raw,
        hint_penalty=penalty,
        final_score=max(0, raw - penalty),
        lines=lines,
        missed=missed,
        spurious=spurious,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_markdown(score: Score) -> str:
    """A student-readable report. Contains no expected/actual for missed items.

    The instructor key is a separate document. A student report that lists the
    configuration they should have written is a key with extra steps.
    """
    lines = [
        f"# Practice report — {score.lab}",
        "",
        f"- Difficulty: **{score.difficulty}**",
        f"- Score: **{score.final_score} / {score.total_possible}**",
        f"- Raw: {score.raw_score} (hint penalty {score.hint_penalty})",
        (
            f"- Faults found: {sum(1 for line in score.lines if line.correct)}"
            f" / {len(score.lines)}"
        ),
        "",
        "## Found",
        "",
    ]
    found = [line for line in score.lines if line.correct]
    if not found:
        lines.append("_Nothing identified._")
    for line in found:
        lines.append(
            f"- **{line.device}** — {line.category}: {line.points_awarded}"
            f"/{line.points_possible} ({line.reason})"
        )
    lines += ["", "## Missed", ""]
    missed = [line for line in score.lines if not line.correct]
    if not missed:
        lines.append("_Nothing missed._")
    for line in missed:
        lines.append(
            f"- **{line.device}** — {line.category} "
            f"({line.points_possible} points): {line.evidence_hint}"
        )
    if score.spurious:
        lines += ["", "## Reported but not a fault", ""]
        for finding in score.spurious:
            target = f"{finding.device}"
            if finding.interface:
                target += f" {finding.interface}"
            lines.append(f"- {target}: no fault here")
    return "\n".join(lines) + "\n"


def render_instructor_markdown(session: PracticeSession, score: Score) -> str:
    """The answer key plus the student's result. Never given to a student."""
    lines = [
        f"# Instructor key — {session.spec.title}",
        "",
        f"Lab: `{session.spec.name}`  |  difficulty: {session.difficulty}",
        f"Student score: {score.final_score}/{score.total_possible}",
        "",
        "## Faults",
        "",
        "| id | device | interface | category | pts | expected | actual |",
        "|---|---|---|---|---|---|---|",
    ]
    for fault in session.spec.faults:
        lines.append(
            f"| {fault.fault_id} | {fault.device} | {fault.interface or '—'} | "
            f"{fault.category.value} | {fault.points} | `{fault.expected}` | "
            f"`{fault.actual}` |"
        )
    lines += ["", "## Why each fault breaks something", ""]
    for fault in session.spec.faults:
        lines += [
            f"### {fault.fault_id} ({fault.severity.value})",
            "",
            fault.description,
            "",
            f"**Symptom:** {fault.symptom}",
            "",
        ]
    return "\n".join(lines) + "\n"


def write_reports(
    session: PracticeSession, score: Score, out_dir: Path
) -> dict[str, Path]:
    """Write student and instructor artefacts to separate files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    student_md = out_dir / "practice_report.md"
    student_json = out_dir / "practice_score.json"
    student_md.write_text(render_markdown(score))
    student_json.write_text(json.dumps(score.as_dict(), indent=2))
    return {"markdown": student_md, "json": student_json}


def write_answer_key(session: PracticeSession, path: Path) -> Path:
    """Write the instructor key. A separate, explicit act."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(session.answer_key(), indent=2))
    return path


def parse_findings(raw: str) -> list[Finding]:
    """Parse a submission.

    Accepts the simple ``device [interface] [category]`` line format, because
    that is what a student can type quickly:

        R1
        SW-ACCESS Fa0/3 VLAN
        PC-ADMIN-1
    """
    findings: list[Finding] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        parts = text.split()
        if len(parts) > 3:
            raise PracticeError(
                f"line {number}: expected 'device [interface] [category]', got {text!r}"
            )
        device = parts[0]
        interface = None
        category = None
        for extra in parts[1:]:
            if _looks_like_interface(extra):
                interface = extra
            else:
                category = extra
        findings.append(Finding(device=device, interface=interface, category=category))
    return findings


#: Categories the parser understands, so a category word is never mistaken for
#: an interface. Without this, `SW-DIST VLAN` parsed "VLAN" as an interface
#: name and `R1 SECURITY` parsed "SECURITY" as one (it starts with "se").
_CATEGORY_WORDS = frozenset(c.value.lower() for c in FaultCategory)


def _looks_like_interface(token: str) -> bool:
    """Whether ``token`` is an IOS interface name rather than a category.

    Interface names always carry a slot: ``Fa0/1``, ``GigabitEthernet0/0.30``,
    ``Vlan99``. Requiring a digit is what separates ``Vlan99`` (interface) from
    ``VLAN`` (category).
    """
    lowered = token.lower()
    if lowered in _CATEGORY_WORDS:
        return False
    if not any(ch.isdigit() for ch in lowered):
        return False
    return any(
        lowered.startswith(prefix)
        for prefix in ("fa", "gi", "eth", "se", "serial", "vl", "loopback", "tunnel")
    )


def severity_order(fault: FaultSpec) -> tuple[int, int]:
    """Sort key: critical first, then by points. Used for display ordering."""
    rank = {Severity.CRITICAL: 0, Severity.MAJOR: 1, Severity.MINOR: 2}
    return rank.get(fault.severity, 3), -fault.points
