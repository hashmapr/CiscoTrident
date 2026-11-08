"""The Phase 3 demonstrations must stay self-consistent.

This test runs the demo runner and asserts the properties the demonstrations
claim, so a regression in honesty rules fails CI rather than quietly shipping.
It never asserts that a live simulator is present — absence is an environment
fact, reported as such.
"""

from __future__ import annotations

import subprocess
import sys

from trident.faultlab import baseline_lab, scenarios
from trident.investigation import Auditor, Mode
from trident.models import AnswerStatus
from trident.phase3_api import investigate_payload


def test_demo_runner_completes_and_is_self_consistent():
    completed = subprocess.run(
        [sys.executable, "-m", "trident.tools.phase3_demo"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert '"demos_self_consistent": true' in completed.stdout
    assert "12/12" in completed.stdout


def test_double_check_reports_zero_operational_claims_without_simulator():
    model = next(s for s in scenarios() if s.name == "trunk-mismatch").model
    payload = Auditor(model, runtime_available=False).audit().as_dict()
    assert payload["coverage"]["operationally_checked"] == 0
    assert payload["coverage"]["simulator_tested"] == 0
    assert payload["evidence_tier"] == "NO_OPERATIONAL_EVIDENCE"


def test_escalation_reason_names_the_environment_blocker():
    payload = investigate_payload(
        baseline_lab(),
        [("Why can't PC1 reach SRV1?", AnswerStatus.INCOMPLETE, ["reachability"])],
        mode=Mode.SMART,
        runtime_available=False,
        runtime_reason="Packet Tracer is not registered",
    )
    reason = payload["outcomes"][0]["reason"]
    assert "unavailable" in reason
    assert "Packet Tracer is not registered" in reason
