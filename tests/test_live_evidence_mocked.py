"""Mocked tests for live-evidence wiring. No Packet Tracer is started.

A fake backend implements the same small surface :class:`LiveEvidenceSession`
needs (``run_cli``, ``close``, ``kind``, ``version``), so every honesty rule can
be exercised without a simulator: success, failure, timeout, contradiction,
source-hash preservation, cleanup on exception, and the static-vs-live label.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trident.deepcore.live_evidence import (
    CollectorResult,
    Conclusion,
    EvidenceBudget,
    EvidenceSource,
    Expectation,
    ExpectationKind,
    LiveEvidenceSession,
    compare,
    compare_many,
    parse_interfaces_status,
    static_observation,
)
from trident.evidence.bundle import EvidenceBundle
from trident.evidence.types import EvidenceKind
from trident.simulator.contracts import (
    BackendKind,
    ObservationKind,
    OperationResult,
    Provenance,
    utcnow,
)
from trident.simulator.isolation import sha256_file

# ---------------------------------------------------------------------------
# Fake backend and canned outputs
# ---------------------------------------------------------------------------

VLAN_BRIEF_WITH_10 = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2
10   ADMIN                            active    Fa0/3
20   STUDENT                          active
30   FACULTY                          active
99   MANAGEMENT                       active
"""

VLAN_BRIEF_WITHOUT_10 = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- ---------------
1    default                          active    Fa0/1, Fa0/2
20   STUDENT                          active
30   FACULTY                          active
99   MANAGEMENT                       active
"""

IP_INT_BRIEF_UP = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     192.168.10.1    YES manual up                    up
"""

IP_INT_BRIEF_DOWN = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     unassigned      YES unset  administratively down down
"""

INTERFACES_TRUNK = """\
Port        Mode             Encapsulation  Status        Native vlan
Gi0/2       on               802.1q         trunking      99

Port        Vlans allowed on trunk
Gi0/2       10,20,30,99

Port        Vlans allowed and active in management domain
Gi0/2       10,20,30,99
"""

IP_ROUTE = """\
Codes: L - local, C - connected, S - static

Gateway of last resort is 192.168.99.1 to network 0.0.0.0

     192.168.10.0/24 is variably subnetted, 2 subnets, 2 masks
C       192.168.10.0/24 is directly connected, Vlan10
"""

RUNNING_CONFIG = """\
Building configuration...

Current configuration : 1234 bytes
!
hostname SW-DIST
!
interface GigabitEthernet0/2
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,99
!
end
"""

INTERFACES_STATUS = """\
Port      Name               Status    Vlan      Duplex  Speed Type
Fa0/1                        connected 10        a-full  a-100 10/100BaseTX
Fa0/2     Uplink             connected trunk     a-full  a-100 10/100BaseTX
Fa0/3                        disabled  10        auto    auto  10/100BaseTX
"""


class FakeBackend:
    """The smallest possible peer: canned text, explicit failure, or a timeout."""

    def __init__(
        self,
        outputs: dict[str, str] | None = None,
        *,
        fail: str | None = None,
        timeout: bool = False,
        scripted: bool = False,
    ) -> None:
        self.outputs = outputs or {}
        self.fail = fail
        self.timeout = timeout
        self.kind = BackendKind.SCRIPTED if scripted else BackendKind.SIMULATOR_LIVE
        self.version = "fake-9.0.1"
        self.closed = 0
        self.calls: list[tuple[str, str, float]] = []
        self._scripted = scripted

    def run_cli(self, device: str, command: str, timeout: float) -> OperationResult:
        self.calls.append((device, command, timeout))
        if self.timeout:
            raise TimeoutError("simulated command timeout")
        if self.fail is not None:
            return self._result(device, command, ok=False, raw="", error=self.fail)
        raw = self.outputs.get(" ".join(command.split()).lower(), "")
        return self._result(device, command, ok=True, raw=raw, observed=not self._scripted)

    def _result(
        self,
        device: str,
        command: str,
        *,
        ok: bool,
        raw: str,
        error: str | None = None,
        observed: bool = False,
    ) -> OperationResult:
        provenance = Provenance(
            backend=self.kind,
            simulator_version=self.version,
            session_id="fake-session",
            source_sha256="0" * 64,
            working_copy_sha256="1" * 64,
            device=device,
            interface=None,
            operation=command,
            executed_at=utcnow(),
            parsed_by="raw",
        )
        return OperationResult(
            ok=ok,
            kind=ObservationKind.CLI_OUTPUT,
            operation=command,
            device=device,
            raw=raw,
            parsed=None,
            provenance=provenance,
            error=error,
            observed=observed,
        )

    def close(self) -> str:
        self.closed += 1
        return "FAKE_CLOSED"


def _lab(tmp_path: Path) -> Path:
    path = tmp_path / "lab.pkt"
    path.write_bytes(b"\x00\x01fake-pkt-bytes\x00")
    return path


def _vlan_expectation(vlan_id: int = 10) -> Expectation:
    return Expectation(
        ExpectationKind.VLAN_EXISTS,
        "SW-DIST",
        vlan_id=vlan_id,
        description=f"VLAN {vlan_id} exists on SW-DIST",
    )


# ---------------------------------------------------------------------------
# Success, EvidenceBundle wiring, and cleanup
# ---------------------------------------------------------------------------


def test_successful_observation_is_live_and_verified(tmp_path):
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_vlan_brief("SW-DIST")

    assert result.evidence.source is EvidenceSource.LIVE_SIMULATOR
    assert result.evidence.is_live is True
    assert result.evidence.liveness == "LIVE"
    assert result.evidence.raw.strip()
    assert result.record is not None
    assert result.record.kind is EvidenceKind.VLAN_BRIEF
    assert "10" in result.findings

    bundle = EvidenceBundle()
    assert result.add_to_bundle(bundle) is True
    assert bundle.runtime_interfaces("SW-DIST") == {}  # not an interface artefact
    assert len(bundle.by_kind(EvidenceKind.VLAN_BRIEF)) == 1

    comparison = compare(_vlan_expectation(10), result)
    assert comparison.conclusion is Conclusion.VERIFIED
    assert comparison.is_conclusive is True
    assert comparison.supporting_observations()
    assert comparison.contradicting_observations() == ()
    assert comparison.as_dict()["prediction_source"] == "STATIC_ANALYSIS"

    assert backend.closed == 1
    assert live.source_intact is True
    assert live.cleanup_status.startswith("close=FAKE_CLOSED")


def test_diagnostic_observations_carry_explicit_sources(tmp_path):
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_vlan_brief("SW-DIST")

    observations = result.diagnostic_observations()
    assert observations[0].source == EvidenceSource.LIVE_SIMULATOR.value
    assert observations[0].device == "SW-DIST"
    assert observations[1].source == EvidenceSource.PARSER_DERIVED.value


# ---------------------------------------------------------------------------
# Failure and timeout must be INCONCLUSIVE, never a guess
# ---------------------------------------------------------------------------


def test_command_failure_is_inconclusive_with_the_error(tmp_path):
    backend = FakeBackend(fail="IPC call not found")
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_vlan_brief("SW-DIST")

    assert result.evidence.ok is False
    assert result.evidence.source is EvidenceSource.UNAVAILABLE
    assert result.evidence.is_live is False
    assert "IPC call not found" in (result.evidence.error or "")

    comparison = compare(_vlan_expectation(10), result)
    assert comparison.conclusion is Conclusion.INCONCLUSIVE
    assert comparison.is_conclusive is False
    assert "IPC call not found" in comparison.detail
    assert comparison.supporting_observations() == ()
    assert comparison.contradicting_observations() == ()


def test_timeout_is_inconclusive_and_poisons_the_session(tmp_path):
    backend = FakeBackend(timeout=True)
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        first = live.collect_vlan_brief("SW-DIST")
        second = live.run("SW-DIST", "show vlan brief")

    assert first.evidence.ok is False
    assert "timed out" in (first.evidence.error or "").lower()
    comparison = compare(_vlan_expectation(10), first)
    assert comparison.conclusion is Conclusion.INCONCLUSIVE
    assert "timed out" in comparison.detail.lower()

    # State after a timeout is unknown, so the session refuses more work.
    assert second.ok is False
    assert "unusable" in (second.error or "").lower()


# ---------------------------------------------------------------------------
# Contradiction
# ---------------------------------------------------------------------------


def test_contradicting_observation_is_contradicted(tmp_path):
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITHOUT_10})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_vlan_brief("SW-DIST")

    comparison = compare(_vlan_expectation(10), result)
    assert comparison.conclusion is Conclusion.CONTRADICTED
    assert "absent" in comparison.detail
    assert comparison.contradicting_observations()
    assert comparison.supporting_observations() == ()
    assert comparison.contradicting_observations()[0].source == "LIVE_SIMULATOR"


# ---------------------------------------------------------------------------
# Source preservation and cleanup on exception
# ---------------------------------------------------------------------------


def test_source_hash_is_unchanged_across_the_session(tmp_path):
    source = _lab(tmp_path)
    before = sha256_file(source)
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})

    with LiveEvidenceSession(backend, source) as live:
        live.collect_vlan_brief("SW-DIST")

    assert live.source_sha256_before == before
    assert live.source_sha256_after == before
    assert live.source_intact is True
    assert "source=INTACT" in live.cleanup_status
    assert sha256_file(source) == before


def test_cleanup_runs_even_when_the_body_raises(tmp_path):
    source = _lab(tmp_path)
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})

    with pytest.raises(RuntimeError, match="boom"), LiveEvidenceSession(backend, source) as live:
        live.collect_vlan_brief("SW-DIST")
        raise RuntimeError("boom")

    assert backend.closed == 1
    assert live.source_intact is True
    assert live.cleanup_status.startswith("close=FAKE_CLOSED")
    assert "source=INTACT" in live.cleanup_status


# ---------------------------------------------------------------------------
# Static vs live labelling
# ---------------------------------------------------------------------------


def test_static_analysis_is_never_labelled_live():
    observation = static_observation("SW-DIST", "model says VLAN 10 exists")
    assert observation.source == EvidenceSource.STATIC_ANALYSIS.value
    assert observation.source != EvidenceSource.LIVE_SIMULATOR.value

    expectation = _vlan_expectation(10)
    assert expectation.predicted_by == EvidenceSource.STATIC_ANALYSIS.value


def test_scripted_backend_is_not_live_and_cannot_verify(tmp_path):
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10}, scripted=True)
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_vlan_brief("SW-DIST")

    assert result.evidence.source is EvidenceSource.SCRIPTED_BACKEND
    assert result.evidence.is_live is False
    assert result.evidence.liveness == "NOT_LIVE"

    comparison = compare(_vlan_expectation(10), result)
    assert comparison.conclusion is Conclusion.INCONCLUSIVE
    assert "not a live simulator observation" in comparison.detail


# ---------------------------------------------------------------------------
# Bounds and command safety
# ---------------------------------------------------------------------------


def test_mutating_command_is_refused_before_reaching_the_backend(tmp_path):
    backend = FakeBackend({})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        evidence = live.run("SW-DIST", "configure terminal")

    assert evidence.ok is False
    assert "not a read-only diagnostic" in (evidence.error or "")
    assert backend.calls == []


def test_command_budget_is_enforced(tmp_path):
    budget = EvidenceBudget(command_timeout_s=5.0, overall_budget_s=60.0, max_commands=1)
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})
    with LiveEvidenceSession(backend, _lab(tmp_path), budget=budget) as live:
        first = live.run("SW-DIST", "show vlan brief")
        second = live.run("SW-DIST", "show vlan brief")

    assert first.ok is True
    assert second.ok is False
    assert "budget exhausted" in (second.error or "").lower()


def test_comparison_rejects_evidence_from_the_wrong_command(tmp_path):
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_vlan_brief("SW-DIST")

    expectation = Expectation(
        ExpectationKind.INTERFACE_UP, "SW-DIST", interface="GigabitEthernet0/1"
    )
    comparison = compare(expectation, result)
    assert comparison.conclusion is Conclusion.INCONCLUSIVE
    assert "show ip interface brief" in comparison.detail


# ---------------------------------------------------------------------------
# The other collectors and evaluators
# ---------------------------------------------------------------------------


def test_interface_up_and_down_are_verified_and_contradicted(tmp_path):
    up = FakeBackend({"show ip interface brief": IP_INT_BRIEF_UP})
    with LiveEvidenceSession(up, _lab(tmp_path)) as live:
        up_result = live.collect_ip_interface_brief("SW-DIST")

    expectation = Expectation(
        ExpectationKind.INTERFACE_UP, "SW-DIST", interface="GigabitEthernet0/1"
    )
    assert compare(expectation, up_result).conclusion is Conclusion.VERIFIED

    down = FakeBackend({"show ip interface brief": IP_INT_BRIEF_DOWN})
    with LiveEvidenceSession(down, _lab(tmp_path)) as live:
        down_result = live.collect_ip_interface_brief("SW-DIST")

    assert compare(expectation, down_result).conclusion is Conclusion.CONTRADICTED


def test_trunk_membership_is_derived_from_the_allowed_list(tmp_path):
    backend = FakeBackend({"show interfaces trunk": INTERFACES_TRUNK})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_interfaces_trunk("SW-DIST")

    allowed = Expectation(
        ExpectationKind.VLAN_ALLOWED_ON_TRUNK,
        "SW-DIST",
        interface="Gi0/2",
        vlan_id=30,
    )
    assert compare(allowed, result).conclusion is Conclusion.DERIVED

    missing = Expectation(
        ExpectationKind.VLAN_ALLOWED_ON_TRUNK,
        "SW-DIST",
        interface="Gi0/2",
        vlan_id=40,
    )
    assert compare(missing, result).conclusion is Conclusion.CONTRADICTED


def test_route_and_config_expectations(tmp_path):
    route_backend = FakeBackend({"show ip route": IP_ROUTE})
    with LiveEvidenceSession(route_backend, _lab(tmp_path)) as live:
        route_result = live.collect_ip_route("SW-DIST")
    route = Expectation(
        ExpectationKind.ROUTE_EXISTS, "SW-DIST", network="192.168.10.0", prefix_length=24
    )
    assert compare(route, route_result).conclusion is Conclusion.VERIFIED

    config_backend = FakeBackend({"show running-config": RUNNING_CONFIG})
    with LiveEvidenceSession(config_backend, _lab(tmp_path)) as live:
        config_result = live.collect_running_config("SW-DIST")
    present = Expectation(
        ExpectationKind.CONFIG_CONTAINS,
        "SW-DIST",
        config_line="switchport trunk allowed vlan 10,20,30,99",
    )
    assert compare(present, config_result).conclusion is Conclusion.VERIFIED
    absent = Expectation(
        ExpectationKind.CONFIG_CONTAINS,
        "SW-DIST",
        config_line="switchport trunk allowed vlan 10,20",
    )
    assert compare(absent, config_result).conclusion is Conclusion.CONTRADICTED


def test_interfaces_status_parser_and_comparison(tmp_path):
    rows, notes = parse_interfaces_status(INTERFACES_STATUS)
    assert notes == []
    assert rows["Fa0/1"]["status"] == "connected"
    assert rows["Fa0/2"]["name"] == "Uplink"
    assert rows["Fa0/2"]["vlan"] == "trunk"
    assert rows["Fa0/3"]["status"] == "disabled"

    backend = FakeBackend({"show interfaces status": INTERFACES_STATUS})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_interfaces_status("SW-DIST")

    assert result.evidence.is_live is True
    assert result.record is None  # no EvidenceKind exists for this command
    assert any("no EvidenceKind" in note for note in result.notes)

    expectation = Expectation(
        ExpectationKind.INTERFACE_STATUS,
        "SW-DIST",
        interface="Fa0/1",
        status="connected",
    )
    assert compare(expectation, result).conclusion is Conclusion.VERIFIED
    disabled = Expectation(
        ExpectationKind.INTERFACE_STATUS,
        "SW-DIST",
        interface="Fa0/3",
        status="connected",
    )
    assert compare(disabled, result).conclusion is Conclusion.CONTRADICTED


def test_compare_many_reports_missing_collections_as_inconclusive(tmp_path):
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        collected = (live.collect_vlan_brief("SW-DIST"),)

    expectations = (
        _vlan_expectation(10),
        Expectation(ExpectationKind.INTERFACE_UP, "SW-DIST", interface="Gi0/1"),
    )
    conclusions = compare_many(expectations, collected)
    assert conclusions[0].conclusion is Conclusion.VERIFIED
    assert conclusions[1].conclusion is Conclusion.INCONCLUSIVE
    assert "was not collected" in conclusions[1].detail


def test_collector_result_without_a_record_cannot_be_added(tmp_path):
    backend = FakeBackend({"show interfaces status": INTERFACES_STATUS})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = live.collect_interfaces_status("SW-DIST")

    bundle = EvidenceBundle()
    assert isinstance(result, CollectorResult)
    assert result.add_to_bundle(bundle) is False
    assert bundle.devices() == ()
