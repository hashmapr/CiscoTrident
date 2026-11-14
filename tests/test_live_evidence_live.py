"""Live simulator evidence, opt-in twice.

Running this file starts Cisco Packet Tracer, so it requires both:

* ``TRIDENT_ALLOW_LIVE_SIMULATOR=1`` — the runtime's launch consent, and
* ``TRIDENT_RUN_LIVE_EVIDENCE=1`` — explicit opt-in for this evidence test.

Missing either is a skip, never a pass. The test uses the generated student lab
and asserts two things that only a real simulator can establish:

* ``show vlan brief`` on ``SW-DIST`` does **not** contain VLAN 10, and
* the source ``.pkt`` hash is byte-for-byte unchanged afterwards.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

LAB = (
    Path(__file__).parents[1]
    / "test-labs"
    / "broken_campus"
    / "broken_campus_student.pkt"
)


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip() not in {"", "0", "false", "no"}


pytestmark = [
    pytest.mark.live_simulator,
    pytest.mark.skipif(
        not (_enabled("TRIDENT_ALLOW_LIVE_SIMULATOR") and _enabled("TRIDENT_RUN_LIVE_EVIDENCE")),
        reason=(
            "live evidence tests need TRIDENT_ALLOW_LIVE_SIMULATOR=1 and "
            "TRIDENT_RUN_LIVE_EVIDENCE=1"
        ),
    ),
]


@pytest.fixture
def lab_path() -> Path:
    if not LAB.is_file():
        pytest.skip(f"{LAB} is not present; generate the broken-campus lab first")
    from trident.simulator.backends import credentials_from_env, find_packet_tracer

    if find_packet_tracer() is None:
        pytest.skip("Packet Tracer is not installed in a searchable location")
    if credentials_from_env() is None:
        pytest.skip("no registered ExApp: configure TRIDENT_PT_APP_ID / TRIDENT_PT_SECRET")
    return LAB


def test_student_sw_dist_lacks_vlan_10_and_the_source_is_untouched(lab_path: Path) -> None:
    from trident.deepcore.live_evidence import (
        Conclusion,
        EvidenceBudget,
        EvidenceSource,
        Expectation,
        ExpectationKind,
        LiveEvidenceSession,
        compare,
    )
    from trident.simulator import SimulatorRuntime, sha256_file

    before = sha256_file(lab_path)
    runtime = SimulatorRuntime(prefer_live=True, allow_scripted=False)
    session = runtime.create_session(lab_path)
    try:
        with LiveEvidenceSession(
            session.backend,
            lab_path,
            close=session.close,
            budget=EvidenceBudget(command_timeout_s=70.0, overall_budget_s=180.0),
        ) as live:
            # Fail clearly if the device is not in this lab, before any command.
            session.resolve_device("SW-DIST")
            result = live.collect_vlan_brief("SW-DIST", timeout=70.0)
            comparison = compare(
                Expectation(
                    ExpectationKind.VLAN_EXISTS,
                    "SW-DIST",
                    vlan_id=10,
                    description="SW-DIST has the ADMIN VLAN",
                ),
                result,
            )
    finally:
        # LiveEvidenceSession closes too; Session.close is idempotent and this
        # covers a failure while creating the backend.
        session.close()

    assert result.evidence.is_live is True, result.evidence.as_dict()
    assert result.evidence.source is EvidenceSource.LIVE_SIMULATOR
    assert result.evidence.raw.strip(), "show vlan brief returned no text"
    assert "VLAN" in result.evidence.raw.upper()

    assert comparison.conclusion is Conclusion.CONTRADICTED, comparison.as_dict()
    assert "VLAN 10" in comparison.detail
    evidence_observations = comparison.contradicting_observations()
    assert evidence_observations, "a contradiction must carry its evidence"
    assert evidence_observations[0].source == EvidenceSource.LIVE_SIMULATOR.value

    # Source preservation is proven by hashes, not asserted in prose.
    assert live.source_intact is True
    assert "source=INTACT" in live.cleanup_status
    assert sha256_file(lab_path) == before
