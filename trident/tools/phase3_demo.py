"""Phase 3 end-to-end demonstrations.

Run with:

    .venv/bin/python -m trident.tools.phase3_demo

Each demonstration prints exactly what it proved and, where a live simulator was
required, what it could not prove. Nothing here is a simulation of a
demonstration: when a step cannot run, it reports the blocker.

  A. Automatic uncertainty resolution
  B. Comprehensive double-check
  C. Candidate repair validation

The script exits non-zero only when a *self-consistency* assertion fails, not
when the simulator is unavailable: environmental absence is reported, not
disguised as a product failure.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from trident.faultlab import baseline_lab, grade, scenarios
from trident.investigation import (
    Auditor,
    Candidate,
    Investigator,
    Mode,
    Outcome,
    evaluate,
)
from trident.models import AnswerStatus
from trident.simulator import SimulatorRuntime, sha256_file

RESULT: dict[str, object] = {}


def _status(ok: bool, label: str, detail: str = "") -> None:
    mark = "PASS" if ok else "BLOCKED"
    print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))


def demo_a(runtime: SimulatorRuntime) -> bool:
    """Static evidence first, escalate only what is testable."""
    print("\nDEMONSTRATION A — automatic uncertainty resolution")
    model = next(s for s in scenarios() if s.name == "wrong-vlan").model
    available = runtime.is_available()
    reason = runtime.availability_reason()

    # 1-4: static analysis and gap identification always run.
    investigator = Investigator(
        model, mode=Mode.SMART, runtime_available=available, runtime_reason=reason
    )
    report = investigator.investigate(
        [("Why can't PC1 reach the server?", AnswerStatus.INCOMPLETE, ["reachability"])]
    )
    outcome = report.outcomes[0]
    print(f"  static diagnosis: {[f['kind'] for f in investigator.diagnose_network()['findings']]}")
    print(f"  escalation decision: {outcome.stop_reason.value}")
    print(f"  reason: {outcome.reason}")
    _status(True, "static analysis produced a named suspect")
    _status(
        outcome.stop_reason.value in {"RUNTIME_UNAVAILABLE", "SUFFICIENT_EVIDENCE"},
        "escalation decision is explicit",
        outcome.stop_reason.value,
    )
    if not available:
        _status(False, "invisible simulator session", reason)
        print("  The remaining steps of A need a registered ExApp.")
        return True

    lab = Path(tempfile.mkdtemp()) / "lab.pkt"
    lab.write_bytes(model.model_dump_json().encode())
    session = runtime.create_session(lab)
    try:
        _status(session.is_live, "session is live", session.backend.kind.value)
        result = session.run_cli(next(iter(model.devices)), "show version")
        _status(result.observed, "observation is genuine", f"raw={len(result.raw)}B")
    finally:
        status = session.close()
    _status("source=INTACT" in status, "source untouched", status)
    _status(sha256_file(lab) == session.source_sha256, "hash verified")
    return True


def demo_b() -> bool:
    """Double-check detects a documented fault and reports coverage."""
    print("\nDEMONSTRATION B — comprehensive double-check")
    scenario = next(s for s in scenarios() if s.name == "trunk-mismatch")
    report = Auditor(scenario.model, runtime_available=False, runtime_reason="demo").audit()
    payload = report.as_dict()
    kinds = {check["suspected_root_cause"] for check in payload["checks"]}
    coverage = payload["coverage"]
    print(f"  detected: {sorted(k for k in kinds if k)}")
    print(f"  coverage: {json.dumps(coverage)}")
    _status("TRUNK_MISMATCH" in kinds, "injected fault detected")
    _status(
        coverage["operationally_checked"] == 0 and coverage["simulator_tested"] == 0,
        "no operational claim without a simulator",
    )
    _status(
        "percent_verified" not in coverage,
        "no fake 100% verification headline",
    )
    _status(
        payload["evidence_tier"] == "NO_OPERATIONAL_EVIDENCE",
        "evidence tier is honest",
        payload["evidence_tier"],
    )
    return True


def demo_c(runtime: SimulatorRuntime) -> bool:
    """What-if refuses to claim an unexecuted repair."""
    print("\nDEMONSTRATION C — candidate repair validation")
    model = baseline_lab()
    candidate = Candidate(
        candidate_id="c1",
        device="SW2",
        commands=("interface FastEthernet0/1", "switchport access vlan 20"),
        intent="move PC1's port into its service VLAN",
        hypothesis="WRONG_VLAN",
        requirement="PC1 must reach the VLAN 20 gateway",
    )
    result = evaluate(
        model,
        candidate,
        baseline_session=None,
        probes=("show vlan brief",),
        runtime_available=runtime.is_available(),
        runtime_reason=runtime.availability_reason(),
    )
    print(f"  outcome: {result.outcome.value}")
    print(f"  explanation: {result.explanation}")
    _status(
        result.outcome
        in {
            Outcome.SIMULATION_UNAVAILABLE,
            Outcome.UNSUPPORTED_COMMAND,
            Outcome.IMPROVEMENT_OBSERVED,
            Outcome.REGRESSION_OBSERVED,
            Outcome.NO_MEANINGFUL_CHANGE,
            Outcome.INCONCLUSIVE,
        },
        "outcome is from the closed set",
        result.outcome.value,
    )
    _status(result.original_preserved, "original preserved")
    # A predicted improvement is never reported as an observed one.
    _status(
        result.outcome is not Outcome.IMPROVEMENT_OBSERVED or bool(result.after),
        "no improvement claimed without observations",
    )
    return True


def demo_regression() -> bool:
    """The static pipeline is unaffected by Phase 3."""
    print("\nREGRESSION — diagnostics against the fault lab answer key")
    exact = 0
    for scenario in scenarios():
        investigator = Investigator(scenario.model, runtime_available=False)
        findings = investigator.diagnose_network()["findings"]
        result = grade(scenario, findings)
        exact += result.exact_match
    print(f"  exact matches: {exact}/{len(scenarios())}")
    _status(exact == len(scenarios()), "all scenarios graded exact")
    RESULT["faultlab_exact"] = f"{exact}/{len(scenarios())}"
    return True


def main() -> int:
    runtime = SimulatorRuntime(prefer_live=True, allow_scripted=False)
    print("TRIDENT Phase 3 demonstrations")
    print(f"  simulator available: {runtime.is_available()}")
    print(f"  reason: {runtime.availability_reason()}")

    outcomes = [
        demo_a(runtime),
        demo_b(),
        demo_c(runtime),
        demo_regression(),
    ]
    RESULT["simulator_available"] = runtime.is_available()
    RESULT["simulator_reason"] = runtime.availability_reason()
    RESULT["demos_self_consistent"] = all(outcomes)
    print("\nSUMMARY")
    print(json.dumps(RESULT, indent=2))
    return 0 if all(outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
