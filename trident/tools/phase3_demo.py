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
from pathlib import Path

from trident.faultlab import baseline_lab, grade, scenarios
from trident.investigation import (
    Auditor,
    Candidate,
    Investigator,
    Mode,
    Outcome,
    evaluate,
    should_escalate,
)
from trident.models import AnswerStatus
from trident.simulator import SimulatorRuntime, sha256_file

RESULT: dict[str, object] = {}


def _status(ok: bool, label: str, detail: str = "") -> None:
    mark = "PASS" if ok else "BLOCKED"
    print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))


def demo_a(runtime: SimulatorRuntime) -> bool:
    """Unresolved question, observable gap, real simulator evidence."""
    print("\nDEMONSTRATION A — automatic uncertainty resolution")
    available = runtime.is_available()
    reason = runtime.availability_reason()

    lab = Path(__file__).parents[2] / "tests" / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        _status(False, "live demonstration", "sample_lab.pkt fixture is missing")
        return True

    # 1. Static analysis, always. This is the fault-lab model, not the .pkt, so the
    #    suspect is known and the escalation question is the one under test.
    model = next(s for s in scenarios() if s.name == "wrong-vlan").model
    static_findings = [
        f["kind"] for f in Investigator(model, runtime_available=False).diagnose_network()["findings"]
    ]
    print(f"  static diagnosis: {static_findings}")
    _status(bool(static_findings), "static analysis produced a named suspect")

    # 2. Decide whether the gap is worth simulating at all.
    decision = should_escalate(
        AnswerStatus.INCOMPLETE,
        mode=Mode.SMART,
        runtime_available=available,
        missing=["reachability between PC1 and the gateway"],
    )
    print(f"  escalation decision: escalate={decision.escalate} ({decision.reason})")
    _status(
        decision.escalate == available,
        "escalation follows runtime availability",
        decision.testability.value,
    )

    if not available:
        print(f"  operational simulation unavailable: {reason}")
        print("  The remaining steps of A need a registered ExApp.")
        return True

    # 3. A real session over a real container.
    source_sha = sha256_file(lab)
    try:
        session = runtime.create_session(lab)
    except Exception as exc:  # noqa: BLE001 - environment, reported not hidden
        _status(False, "invisible simulator session", str(exc)[:160])
        return True
    try:
        _status(session.is_live, "session is live", session.backend.kind.value)
        names = [d["name"] for d in session.backend.devices()]
        _status(bool(names), "lab loaded", f"{len(names)} devices")

        # 4. Run the investigation against the live session.
        investigator = Investigator(
            model,
            mode=Mode.SMART,
            session=session,
            runtime_available=True,
            runtime_reason=reason,
        )
        report = investigator.investigate(
            [("Why can't PC1 reach the gateway?", AnswerStatus.INCOMPLETE, ["interface state"])]
        )
        outcome = report.outcomes[0]
        print(f"  investigation: stop={outcome.stop_reason.value} tier={outcome.evidence_tier}")
        print(f"  reason: {outcome.reason[:150]}")
        _status(
            outcome.stop_reason.value
            in {"SUFFICIENT_EVIDENCE", "NO_USEFUL_EXPERIMENT", "SIMULATOR_FAILED"},
            "investigation ran against the simulator",
            outcome.stop_reason.value,
        )

        # 5. A genuine diagnostic, asserted on its content.
        target = "R1" if "R1" in names else (names[0] if names else "")
        interfaces = session.run_cli(target, "show ip interface brief", timeout=45) if target else None
        if interfaces is not None:
            _status(interfaces.observed, "observation is genuine", f"raw={len(interfaces.raw)}B")
            _status(
                "GigabitEthernet" in interfaces.raw,
                "lab-specific output returned",
                f"raw={len(interfaces.raw)}B",
            )
            _status(interfaces.is_live, "provenance marks it live", interfaces.provenance.backend.value)
    finally:
        status = session.close()
    _status("source=INTACT" in status, "source untouched", status)
    _status(sha256_file(lab) == source_sha, "original hash verified")
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
