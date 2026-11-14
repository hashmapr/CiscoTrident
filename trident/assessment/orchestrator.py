"""Autonomous network assessment: recon → requirements → diagnosis → verify → remediate → report.

The workflow exists to answer one question end to end:

    given a practice lab and its visible instructions, what is wrong with it,
    what should be changed, and can that be proven?

The design constraint that shapes every phase is **evidence separation**. Six
kinds of claim flow through this module and they must never be confused:

    extracted fact     parsed from the file, provenance recorded
    requirement        quoted from the lab's own instructions
    finding            a requirement is not met, with the deciding hop named
    verification       an independent re-derivation confirmed or rejected it
    live observation   the simulator actually behaved this way
    remediation        what to change, and whether changing it helped

The failure this prevents is the tempting one: taking a static prediction,
running it through a second copy of the same reasoning, and calling the
agreement "verification". A single agent agreeing with itself is not evidence.

Read-only by default. Modifying a lab requires ``authorize_changes=True``, and
even then it happens on a copy whose source hash is checked before and after.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from ..engined.intent import NetworkIntent
from ..engined.verify import Status, verify_intent

# Optional sub-layers. Each is built by a separate agent and may be absent in a
# partial checkout; the workflow degrades with a recorded limitation rather than
# failing to import.
try:  # pragma: no cover - import shape
    from .forensics import reconstruct
except Exception:  # noqa: BLE001
    reconstruct = None  # type: ignore[assignment]
try:  # pragma: no cover
    from .requirements import coverage as requirement_coverage
    from .requirements import parse_requirements, to_intent
except Exception:  # noqa: BLE001
    parse_requirements = None  # type: ignore[assignment]
    to_intent = None  # type: ignore[assignment]
    requirement_coverage = None  # type: ignore[assignment]
try:  # pragma: no cover
    from .diagnose import diagnose as diagnose_assessment
except Exception:  # noqa: BLE001
    diagnose_assessment = None  # type: ignore[assignment]
try:  # pragma: no cover
    from .remediation import apply_to_copy, read_only_plan, verify_remediation
    from .remediation import plan as plan_remediation
except Exception:  # noqa: BLE001
    apply_to_copy = None  # type: ignore[assignment]
    plan_remediation = None  # type: ignore[assignment]
    read_only_plan = None  # type: ignore[assignment]
    verify_remediation = None  # type: ignore[assignment]
try:  # pragma: no cover
    from .verify_independent import challenge
except Exception:  # noqa: BLE001
    challenge = None  # type: ignore[assignment]


class Phase(StrEnum):
    """The six phases, in order. Used for progress and for the report."""

    RECONNAISSANCE = "reconnaissance"
    REQUIREMENTS = "requirements"
    DIAGNOSIS = "diagnosis"
    VERIFICATION = "verification"
    REMEDIATION = "remediation"
    FINAL = "final"


@dataclass
class PhaseResult:
    """What one phase produced, including what it could not do."""

    phase: Phase
    ok: bool
    summary: str
    limitations: list[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)


@dataclass
class AssessmentConfig:
    """Inputs and authorizations for one assessment run.

    ``authorize_changes`` defaults to False because the safe outcome must be the
    default. A caller that wants remediation applied has to say so, which makes
    the decision visible in the call site instead of buried in a flag file.
    """

    lab_path: Path
    requirements_text: str = ""
    authorize_changes: bool = False
    workdir: Path | None = None
    #: Explicit requirements, bypassing text parsing (used by tests and by a CLI
    #: that already knows the intent).
    intent: NetworkIntent | None = None


@dataclass
class AssessmentReport:
    """The complete, evidence-backed result of a run."""

    lab: str
    source_sha256: str
    phases: list[PhaseResult] = field(default_factory=list)
    inventory: dict = field(default_factory=dict)
    requirements: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    verification: dict = field(default_factory=dict)
    remediation: dict = field(default_factory=dict)
    unresolved: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    compliance: str = "UNKNOWN"

    def phase(self, phase: Phase) -> PhaseResult | None:
        for result in self.phases:
            if result.phase is phase:
                return result
        return None

    def as_dict(self) -> dict:
        return {
            "lab": self.lab,
            "source_sha256": self.source_sha256,
            "compliance": self.compliance,
            "inventory": self.inventory,
            "requirements": self.requirements,
            "findings": self.findings,
            "verification": self.verification,
            "remediation": self.remediation,
            "unresolved": self.unresolved,
            "unsupported": self.unsupported,
            "phases": [
                {
                    "phase": p.phase.value,
                    "ok": p.ok,
                    "summary": p.summary,
                    "limitations": p.limitations,
                }
                for p in self.phases
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2)

    def to_markdown(self) -> str:
        return render_markdown(self)


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_assessment(config: AssessmentConfig) -> AssessmentReport:
    """Run the six phases and return the report.

    Every phase records its limitations rather than swallowing them. A phase
    that cannot run (because a sub-layer is absent) is reported as not-ok with
    the reason, and the workflow continues — a partial assessment that says what
    it could not do is more useful than a crash.
    """
    source = Path(config.lab_path)
    if not source.is_file():
        raise FileNotFoundError(f"lab not found: {source}")
    sha_before = _sha256(source)

    report = AssessmentReport(lab=source.name, source_sha256=sha_before)

    # -- Phase 1: reconnaissance -------------------------------------------
    evidence = None
    if reconstruct is None:
        report.phases.append(
            PhaseResult(
                Phase.RECONNAISSANCE, False,
                "forensics layer unavailable",
                ["trident.assessment.forensics could not be imported"],
            )
        )
    else:
        try:
            evidence = reconstruct(source)
            report.inventory = {
                "devices": len(evidence.devices),
                "links": len(evidence.links),
                "vlans": len(evidence.vlans),
                "routes": len(evidence.routes),
                "acls": len(evidence.acls),
                "engines": evidence.engines,
            }
            limitations = []
            if evidence.discrepancies:
                limitations.append(
                    f"{len(evidence.discrepancies)} field(s) where engines disagree"
                )
            if evidence.unsupported:
                report.unsupported.extend(
                    f"{item.capability}: {item.reason}" for item in evidence.unsupported
                )
            report.phases.append(
                PhaseResult(
                    Phase.RECONNAISSANCE, True,
                    f"{len(evidence.devices)} devices, {len(evidence.links)} links",
                    limitations,
                )
            )
        except Exception as exc:  # noqa: BLE001 - reported, never hidden
            report.phases.append(
                PhaseResult(
                    Phase.RECONNAISSANCE, False,
                    f"reconstruction failed: {type(exc).__name__}",
                    [str(exc)],
                )
            )

    if evidence is None:
        report.compliance = "UNKNOWN"
        report.unresolved.append("no network model: assessment cannot proceed")
        return report

    model = evidence.model

    # -- Phase 2: requirement decomposition --------------------------------
    intent = config.intent
    parsed = []
    if intent is None:
        if parse_requirements is None or to_intent is None:
            report.phases.append(
                PhaseResult(
                    Phase.REQUIREMENTS, False,
                    "requirement parser unavailable",
                    ["trident.assessment.requirements could not be imported"],
                )
            )
            report.unresolved.append("no requirements were supplied or parsed")
            return report
        try:
            parsed = parse_requirements(
                config.requirements_text.splitlines() if config.requirements_text else []
            )
            # ``to_intent`` resolves ONE requirement at a time: a single line may
            # expand to several (an isolation statement names many subnet pairs)
            # or to none (an unparseable line). Composing them here keeps the
            # per-line provenance the coverage report depends on.
            intent = NetworkIntent(name="assessment")
            for item in parsed:
                resolved = to_intent(item, model)
                intent.requirements.extend(resolved.requirements)
                intent.isolated_pairs.extend(resolved.isolated_pairs)
            cov = requirement_coverage(parsed, model) if requirement_coverage else {}
            report.requirements = [
                {
                    "raw": getattr(p, "raw", ""),
                    "parsed": bool(getattr(p, "parsed", False)),
                    "assertion": getattr(p, "assertion", None),
                }
                for p in parsed
            ]
            limitations = []
            unparsed = cov.get("unparsed", 0)
            if unparsed:
                limitations.append(f"{unparsed} instruction line(s) could not be parsed")
                report.unresolved.extend(
                    f"unparsed requirement: {getattr(p, 'raw', '')}"
                    for p in parsed
                    if not getattr(p, "parsed", False)
                )
            report.phases.append(
                PhaseResult(
                    Phase.REQUIREMENTS, True,
                    f"{len(report.requirements)} requirement(s)",
                    limitations,
                )
            )
        except Exception as exc:  # noqa: BLE001
            report.phases.append(
                PhaseResult(
                    Phase.REQUIREMENTS, False,
                    f"requirement parsing failed: {type(exc).__name__}",
                    [str(exc)],
                )
            )
            return report
    else:
        report.phases.append(
            PhaseResult(
                Phase.REQUIREMENTS, True,
                f"{len(intent.expand(model))} explicit requirement(s)",
            )
        )

    # -- Phase 3: diagnosis -------------------------------------------------
    report_obj = verify_intent(model, intent)
    verdicts = report_obj.verdicts
    counts = {status.value: 0 for status in Status}
    for verdict in verdicts:
        counts[verdict.status.value] += 1

    findings = []
    for fault in report_obj.localize_faults():
        findings.append(
            {
                "device": fault.device,
                "interface": fault.interface,
                "category": fault.kind,
                "detail": fault.detail,
                "affected": list(fault.affected),
            }
        )
    report.findings = findings

    inconclusive = [v for v in verdicts if v.status is Status.INCONCLUSIVE]
    unsupported_verdicts = [v for v in verdicts if v.status is Status.UNSUPPORTED]
    for verdict in inconclusive:
        report.unresolved.append(
            f"{verdict.requirement.description}: INCONCLUSIVE "
            f"({'; '.join(verdict.missing) or 'insufficient evidence'})"
        )
    for verdict in unsupported_verdicts:
        report.unsupported.append(
            f"{verdict.requirement.description}: UNSUPPORTED "
            f"({'; '.join(verdict.missing) or 'not modelled'})"
        )

    report.phases.append(
        PhaseResult(
            Phase.DIAGNOSIS,
            True,
            f"{len(findings)} fault(s), {counts['DERIVED'] + counts['VERIFIED']} decided",
            [f"{counts['INCONCLUSIVE']} inconclusive"] if inconclusive else [],
            counts,
        )
    )

    # -- Phase 4: independent verification ----------------------------------
    if challenge is None:
        report.phases.append(
            PhaseResult(
                Phase.VERIFICATION, False,
                "independent verifier unavailable",
                ["trident.assessment.verify_independent could not be imported"],
            )
        )
        report.verification = {"error": "verifier unavailable"}
    else:
        try:
            verification = challenge(model, intent, findings)
            report.verification = verification.as_dict()
            report.phases.append(
                PhaseResult(
                    Phase.VERIFICATION, True,
                    (
                        f"{len(verification.confirmed)} confirmed, "
                        f"{len(verification.rejected)} rejected, "
                        f"{len(verification.missed)} missed"
                    ),
                    [],
                )
            )
        except Exception as exc:  # noqa: BLE001
            report.phases.append(
                PhaseResult(
                    Phase.VERIFICATION, False,
                    f"verification failed: {type(exc).__name__}",
                    [str(exc)],
                )
            )

    # -- Phase 5: remediation ----------------------------------------------
    if plan_remediation is None:
        report.phases.append(
            PhaseResult(
                Phase.REMEDIATION, False,
                "remediation layer unavailable",
                ["trident.assessment.remediation could not be imported"],
            )
        )
    elif not config.authorize_changes:
        plan_text = read_only_plan(findings) if read_only_plan else ""
        report.remediation = {
            "mode": "read-only",
            "plan": plan_text,
            "note": (
                "modification not authorized; no file was changed. Pass "
                "authorize_changes=True to apply on an isolated copy."
            ),
        }
        report.phases.append(
            PhaseResult(Phase.REMEDIATION, True, "read-only plan produced")
        )
    else:
        try:
            changes = plan_remediation(findings)
            workdir = Path(config.workdir or tempfile.mkdtemp(prefix="trident-assess-"))
            copy_path, log = apply_to_copy(
                None, changes, workdir / f"{source.stem}-remediated{source.suffix}"
            )
            report.remediation = {
                "mode": "applied",
                "copy": str(copy_path),
                "changes": len(changes),
                "log": log.as_dict() if hasattr(log, "as_dict") else str(log),
                "source_unchanged": _sha256(source) == sha_before,
            }
            report.phases.append(
                PhaseResult(
                    Phase.REMEDIATION, True,
                    f"{len(changes)} change(s) applied to an isolated copy",
                )
            )
        except Exception as exc:  # noqa: BLE001
            report.phases.append(
                PhaseResult(
                    Phase.REMEDIATION, False,
                    f"remediation failed: {type(exc).__name__}",
                    [str(exc)],
                )
            )

    # -- Phase 6: final assessment -----------------------------------------
    if _sha256(source) != sha_before:  # pragma: no cover - guarded invariant
        report.unresolved.append("SOURCE FILE CHANGED — this is a defect, not a result")

    decided = counts["DERIVED"] + counts["VERIFIED"]
    if findings:
        report.compliance = "NON-COMPLIANT"
    elif decided and not inconclusive and not unsupported_verdicts:
        report.compliance = "COMPLIANT"
    else:
        # Requirements exist but some could not be decided: it would be wrong to
        # call that compliant.
        report.compliance = "INCOMPLETE"

    report.phases.append(
        PhaseResult(
            Phase.FINAL, True,
            f"compliance: {report.compliance}",
            [],
            {"counts": counts},
        )
    )
    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_markdown(report: AssessmentReport) -> str:
    """A complete assessment report, with every unproven thing called out."""
    lines = [
        f"# Assessment — {report.lab}",
        "",
        f"- Source SHA-256: `{report.source_sha256}`",
        f"- **Compliance: {report.compliance}**",
        "",
        "## 1. Network inventory",
        "",
    ]
    if report.inventory:
        for name in ("devices", "links", "vlans", "routes", "acls"):
            lines.append(f"- {name}: {report.inventory.get(name, 0)}")
        engines = report.inventory.get("engines") or {}
        if engines:
            lines.append("- engines:")
            for engine, state in engines.items():
                lines.append(f"  - {engine}: {state}")
    else:
        lines.append("_No inventory: reconstruction did not run._")

    lines += ["", "## 2. Requirements", ""]
    if report.requirements:
        for item in report.requirements:
            mark = "parsed" if item.get("parsed") else "**UNPARSED**"
            lines.append(f"- {item.get('raw', '')} — {mark}")
    else:
        lines.append("_None supplied._")

    lines += ["", "## 3. Detected faults", ""]
    if report.findings:
        lines.append("| Device | Interface | Category | Affected |")
        lines.append("|---|---|---|---|")
        for finding in report.findings:
            lines.append(
                f"| {finding['device']} | {finding.get('interface') or '—'} | "
                f"{finding['category']} | {len(finding.get('affected', []))} |"
            )
    else:
        lines.append("_None._")

    lines += ["", "## 4. Verification", ""]
    if report.verification:
        for key in ("confirmed", "rejected", "missed", "alternative_explanations"):
            value = report.verification.get(key)
            if isinstance(value, list):
                lines.append(f"- {key}: {len(value)}")
    else:
        lines.append("_Not run._")

    lines += ["", "## 5. Remediation", ""]
    if report.remediation:
        mode = report.remediation.get("mode", "unknown")
        lines.append(f"- mode: **{mode}**")
        if report.remediation.get("note"):
            lines.append(f"- {report.remediation['note']}")
        if report.remediation.get("changes") is not None:
            lines.append(f"- changes applied: {report.remediation['changes']}")
        if report.remediation.get("source_unchanged") is not None:
            lines.append(
                f"- source unchanged: {report.remediation['source_unchanged']}"
            )
        if mode == "read-only" and report.remediation.get("plan"):
            lines += ["", "```", report.remediation["plan"].strip(), "```"]
    else:
        lines.append("_Not run._")

    lines += ["", "## 6. Unresolved requirements", ""]
    lines += [f"- {item}" for item in report.unresolved] or ["_None._"]

    lines += ["", "## 7. Unsupported checks", ""]
    lines += [f"- {item}" for item in report.unsupported] or ["_None._"]

    lines += ["", "## 8. Phase log", ""]
    for phase in report.phases:
        status = "ok" if phase.ok else "**not ok**"
        lines.append(f"- {phase.phase.value}: {status} — {phase.summary}")
        for limitation in phase.limitations:
            lines.append(f"  - limitation: {limitation}")

    return "\n".join(lines) + "\n"
