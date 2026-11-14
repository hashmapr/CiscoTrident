"""Independent scoring of the gauntlet: blind predictions vs verified ground truth.

This module exists to keep one promise: **the diagnosis never sees the key**.

The separation is enforced structurally, not by good intentions:

1. Agent B writes predictions to ``BLIND_PREDICTIONS.json`` and never reads a key.
2. Agent A independently opens each lab in Packet Tracer and records which faults
   are *actually present*, to ``VERIFIED_GROUND_TRUTH.md``.
3. This module computes a SHA-256 of the predictions file and records it, then
   joins the two. That hash is what makes "the predictions were finalised before
   scoring" checkable rather than asserted.

Two rules decide whether a number is honest:

* **Only verified faults count.** A fault the key lists but Packet Tracer does not
  contain is not ground truth, and scoring against it would punish the engine for
  being right. Ground truth is intersected with "PRESENT" before any metric.
* **Matching is strict.** A finding must name the right device *and* be a kind
  that can explain the fault. Naming a real problem on the wrong device is a
  false positive, not a hit.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

#: Which diagnostic finding kinds can legitimately explain which fault kinds.
#:
#: Derived from the fault vocabulary in the gauntlet keys, not tuned to any
#: particular run. A fault kind absent here cannot be credited, which is the
#: honest outcome: if the engine has no concept of it, it did not find it.
#: Keys are the fault *kind strings that actually appear in the gauntlet answer
#: keys*, read from `instructor_only/*.json` rather than guessed. The full set is
#: exactly eight kinds; an earlier draft invented names like "duplicate_ip" and
#: "trunk", which would have silently scored those faults as undetectable.
KIND_MAP: dict[str, frozenset[str]] = {
    "shutdown_interface": frozenset({"SHUTDOWN_INTERFACE"}),
    "wrong_default_gateway": frozenset({"WRONG_GATEWAY"}),
    "wrong_subnet_mask": frozenset({"INVALID_MASK"}),
    "wrong_access_vlan": frozenset({"WRONG_VLAN"}),
    "trunk_allowed_vlan": frozenset({"TRUNK_MISMATCH"}),
    "missing_static_route": frozenset({"MISSING_STATIC_ROUTE", "UNREACHABLE_NEXT_HOP"}),
    "duplicate_ipv4": frozenset({"DUPLICATE_IP"}),
    "acl_denies_required_icmp": frozenset({"ACL_BLOCK"}),
}

#: Fault kinds the engine has no detector for at all. Recorded explicitly so the
#: report can say "unsupported" instead of quietly counting them as misses.
UNSUPPORTED_KINDS: frozenset[str] = frozenset(
    kind for kind, detectors in KIND_MAP.items() if not detectors
)


@dataclass
class FaultOutcome:
    """One ground-truth fault and how the blind run did against it."""

    level: str
    fault_id: str
    device: str
    kind: str
    verified: bool
    detected: bool
    matched_kind: str | None = None
    note: str = ""


@dataclass
class LevelScore:
    level: str
    devices_found: int
    devices_expected: int
    links_found: int
    links_expected: int
    seconds: float
    faults: list[FaultOutcome] = field(default_factory=list)
    raw_findings: int = 0
    spurious: list[dict] = field(default_factory=list)

    @property
    def scored_faults(self) -> list[FaultOutcome]:
        return [f for f in self.faults if f.verified]

    @property
    def tp(self) -> int:
        return sum(1 for f in self.scored_faults if f.detected)

    @property
    def fn(self) -> int:
        return sum(1 for f in self.scored_faults if not f.detected)

    @property
    def fp(self) -> int:
        return len(self.spurious)

    @property
    def unverified(self) -> int:
        return sum(1 for f in self.faults if not f.verified)

    def as_row(self) -> str:
        rec_num, rec_den = self.tp, self.tp + self.fn
        pre_num, pre_den = self.tp, self.tp + self.fp
        rec = f"{100 * rec_num / rec_den:.0f}% ({rec_num}/{rec_den})" if rec_den else "n/a (0/0)"
        pre = f"{100 * pre_num / pre_den:.0f}% ({pre_num}/{pre_den})" if pre_den else "n/a (0/0)"
        return (
            f"| {self.level} | {self.devices_found}/{self.devices_expected} | "
            f"{self.links_found}/{self.links_expected} | {rec} | {pre} | "
            f"{self.fp} | {self.unverified} | {self.seconds:.1f}s |"
        )


def seal(path: Path) -> str:
    """Hash a predictions file so its content is pinned at scoring time."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _matches(fault: dict, findings: list[dict]) -> dict | None:
    """Find a finding that can explain ``fault``. Device must match exactly."""
    allowed = KIND_MAP.get(fault.get("kind", ""), frozenset())
    if not allowed:
        return None
    device = (fault.get("device") or "").strip().lower()
    for finding in findings:
        if (finding.get("device") or "").strip().lower() != device:
            continue
        if (finding.get("kind") or "") not in allowed:
            continue
        return finding
    return None


def score_level(
    level: str,
    *,
    predicted: dict,
    key: dict,
    ground_truth: dict[str, bool],
    index_row: dict,
) -> LevelScore:
    """Score one level.

    ``ground_truth`` maps ``fault_id -> PRESENT/True``. Any fault not marked
    present is excluded from the denominator and reported separately.
    """
    findings = predicted.get("predicted_faults", [])
    faults: list[FaultOutcome] = []
    for fault in key.get("faults", []):
        verified = bool(ground_truth.get(fault["id"], False))
        match = _matches(fault, findings) if verified else None
        faults.append(
            FaultOutcome(
                level=level,
                fault_id=fault["id"],
                device=fault.get("device", ""),
                kind=fault.get("kind", ""),
                verified=verified,
                detected=match is not None,
                matched_kind=match.get("kind") if match else None,
                note="" if verified else "not verified in Packet Tracer; excluded",
            )
        )

    explained = {(f.device.lower(), f.matched_kind) for f in faults if f.detected}
    spurious = [
        finding
        for finding in findings
        if ((finding.get("device") or "").lower(), finding.get("kind")) not in explained
    ]
    return LevelScore(
        level=level,
        devices_found=int(predicted.get("devices", 0)),
        devices_expected=int(index_row.get("expected_devices", 0)),
        links_found=int(predicted.get("links", 0)),
        links_expected=int(index_row.get("expected_links", 0)),
        seconds=float(predicted.get("seconds", 0.0)),
        faults=faults,
        raw_findings=len(findings),
        spurious=spurious,
    )


def render_report(scores: list[LevelScore], predictions_sha: str) -> str:
    """The scoring table. Every rate carries its numerator and denominator."""
    total_tp = sum(s.tp for s in scores)
    total_fn = sum(s.fn for s in scores)
    total_fp = sum(s.fp for s in scores)
    total_dev = sum(s.devices_found for s in scores)
    total_dev_exp = sum(s.devices_expected for s in scores)
    total_lnk = sum(s.links_found for s in scores)
    total_lnk_exp = sum(s.links_expected for s in scores)

    lines = [
        "# Baseline results — blind diagnosis vs verified ground truth",
        "",
        f"Predictions sealed at SHA-256 `{predictions_sha}`.",
        "Ground truth is intersected with Packet Tracer verification: a fault that",
        "the key lists but the simulator does not contain is excluded from the",
        "denominator, not counted as a miss.",
        "",
        "| Level | Devices | Links | Recall | Precision | FP | Unverified | Time |",
        "|---|---|---|---|---|---|---|---|",
    ]
    lines += [s.as_row() for s in scores]
    lines += [
        "",
        "## Totals",
        "",
        (
            f"- Topology: {total_dev}/{total_dev_exp} devices, "
            f"{total_lnk}/{total_lnk_exp} links"
        ),
        f"- Recall: {total_tp}/{total_tp + total_fn}",
        f"- Precision: {total_tp}/{total_tp + total_fp}",
        f"- False positives: {total_fp}",
        "",
        "## Per-fault detail",
        "",
        "| Level | Fault | Device | Kind | Verified | Detected | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    for score in scores:
        for fault in score.faults:
            lines.append(
                f"| {fault.level} | {fault.fault_id} | {fault.device} | "
                f"{fault.kind} | {'yes' if fault.verified else 'no'} | "
                f"{'yes' if fault.detected else 'no'} | {fault.note} |"
            )
    return "\n".join(lines) + "\n"


def load_ground_truth(path: Path) -> dict[str, dict[str, bool]]:
    """Read the verifier's JSON sidecar: level -> {fault_id: present}."""
    return json.loads(path.read_text())
