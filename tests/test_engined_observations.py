"""Mocked tests for Engine D's live observation layer.

No Packet Tracer is started here. A fake backend supplies canned ``show``
output, so parsing, source labelling, failure handling, bounded collection and
source-hash preservation are exercised deterministically. The single live test
is at the bottom and runs only when both opt-in environment variables are set.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from trident.deepcore.live_evidence import Conclusion, EvidenceSource
from trident.engined.observations import (
    PT_901_LIMITATIONS,
    LiveObservationSet,
    SupportStatus,
    collect,
    parse_interface_output,
    parse_route_output,
    prediction_agrees,
    runtime_state_available,
    runtime_state_note,
    support_status,
    unsupported_reason,
)
from trident.simulator.contracts import (
    BackendKind,
    ObservationKind,
    OperationResult,
    Provenance,
    utcnow,
)
from trident.simulator.isolation import sha256_file

# ---------------------------------------------------------------------------
# Canned Packet Tracer-style output
# ---------------------------------------------------------------------------

SHOW_IP_ROUTE = """\
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

Gateway of last resort is 203.0.113.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 203.0.113.1
      192.168.10.0/24 is variably subnetted, 2 subnets, 2 masks
C       192.168.10.0/24 is directly connected, GigabitEthernet0/0
C       10.0.0.0/30 is directly connected, GigabitEthernet0/1
S       10.0.1.0/30 [1/0] via 10.0.0.1
"""

SHOW_IP_INT_BRIEF = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     192.168.10.1    YES manual up                    up
GigabitEthernet0/1     10.0.0.1        YES manual up                    up
GigabitEthernet0/2     unassigned      YES unset  administratively down down
GigabitEthernet0/3     10.0.2.1        YES manual down                  down
"""


class FakeBackend:
    """The small backend surface LiveEvidenceSession needs, with canned text."""

    def __init__(
        self,
        outputs: dict[str, str] | None = None,
        *,
        fail: str | None = None,
        scripted: bool = False,
    ) -> None:
        self.outputs = {
            " ".join(command.split()).lower(): text
            for command, text in (outputs or {}).items()
        }
        self.fail = fail
        self.kind = BackendKind.SCRIPTED if scripted else BackendKind.SIMULATOR_LIVE
        self.version = "fake-9.0.1"
        self.session_id = "fake-engined-session"
        self.closed = 0
        self._scripted = scripted

    def run_cli(self, device: str, command: str, timeout: float) -> OperationResult:
        if self.fail is not None:
            return self._result(device, command, ok=False, raw="", error=self.fail)
        raw = self.outputs.get(" ".join(command.split()).lower(), "")
        return self._result(
            device, command, ok=True, raw=raw, observed=not self._scripted
        )

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
            session_id=self.session_id,
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


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_show_ip_route_structures_default_thirty_and_connected() -> None:
    routes = parse_route_output(
        SHOW_IP_ROUTE,
        device="R1",
        source=EvidenceSource.LIVE_SIMULATOR,
        observed_live=True,
    )

    assert len(routes) == 4

    default = next(route for route in routes if route.is_default)
    assert default.code == "S*"
    assert default.network == "0.0.0.0"
    assert default.prefix_length == 0
    assert default.next_hop == "203.0.113.1"
    assert default.interface is None

    thirty = next(route for route in routes if route.network == "10.0.0.0")
    assert thirty.prefix_length == 30
    assert thirty.is_directly_connected is True
    assert thirty.interface == "GigabitEthernet0/1"

    static_thirty = next(route for route in routes if route.network == "10.0.1.0")
    assert static_thirty.prefix_length == 30
    assert static_thirty.next_hop == "10.0.0.1"
    assert static_thirty.is_directly_connected is False

    connected = next(route for route in routes if route.network == "192.168.10.0")
    assert connected.prefix_length == 24
    assert connected.is_directly_connected is True

    assert all(route.source is EvidenceSource.LIVE_SIMULATOR for route in routes)
    assert all(route.derivation is EvidenceSource.PARSER_DERIVED for route in routes)
    assert all(route.observed_live is True for route in routes)


def test_parse_show_ip_interface_brief_states() -> None:
    interfaces = parse_interface_output(
        SHOW_IP_INT_BRIEF,
        device="R1",
        source=EvidenceSource.LIVE_SIMULATOR,
        observed_live=True,
    )

    assert {name: item.status for name, item in interfaces.items()} == {
        "GigabitEthernet0/0": "up",
        "GigabitEthernet0/1": "up",
        "GigabitEthernet0/2": "administratively down",
        "GigabitEthernet0/3": "down",
    }
    assert interfaces["GigabitEthernet0/0"].is_up is True
    assert interfaces["GigabitEthernet0/2"].is_administratively_down is True
    assert interfaces["GigabitEthernet0/3"].is_up is False
    assert all(item.source is EvidenceSource.LIVE_SIMULATOR for item in interfaces.values())
    assert all(item.observed_live is True for item in interfaces.values())


def test_empty_output_parses_to_nothing_rather_than_a_guess() -> None:
    assert parse_route_output("") == []
    assert parse_route_output("Codes: C - connected\n") == []
    assert parse_interface_output("") == {}
    assert parse_interface_output("Interface  IP-Address  OK? Method Status Protocol\n") == {}


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def test_collect_builds_a_live_observation_set(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    backend = FakeBackend(
        {
            "show ip route": SHOW_IP_ROUTE,
            "show ip interface brief": SHOW_IP_INT_BRIEF,
        }
    )

    observations = collect(lab, ["R1"], backend=backend, close=backend.close)

    assert observations.collection_error is None
    assert observations.source_intact is True
    assert observations.source_sha256_before == observations.source_sha256_after
    assert backend.closed == 1
    assert observations.commands_run == 6  # six bounded collectors, one device

    assert observations.command_support("R1", "show ip route") is SupportStatus.SUPPORTED
    assert runtime_state_available(observations) is True
    assert observations.has_runtime_state is True

    assert len(observations.routing_table("R1")) == 4
    assert observations.interface_states("R1")["GigabitEthernet0/0"] == "up"
    assert observations.interface_states("R1")["GigabitEthernet0/2"] == "administratively down"

    device = observations.device("R1")
    assert device is not None
    assert all(fact.source is not EvidenceSource.UNAVAILABLE for fact in device.facts)


def test_failed_command_is_unsupported_and_never_guessed(tmp_path: Path) -> None:
    error = 'IPC error from enterCommand: [\'Pc\', \'IPC call "enterCommand" not found\']'
    backend = FakeBackend(fail=error)

    observations = collect(_lab(tmp_path), ["PC1"], backend=backend, close=backend.close)

    assert observations.routing_table("PC1") == []
    assert observations.interface_states("PC1") == {}
    assert runtime_state_available(observations) is False
    assert observations.command_support("PC1", "show ip route") is SupportStatus.UNSUPPORTED

    errors = observations.device_errors()
    assert error in errors["PC1"]["show ip route"]

    # With no observation, the correlation is INCONCLUSIVE -- never a guess.
    assert prediction_agrees("PC1 can reach R1", True, None) is Conclusion.INCONCLUSIVE


def test_a_scripted_backend_is_not_runtime_state(tmp_path: Path) -> None:
    backend = FakeBackend({"show ip route": SHOW_IP_ROUTE}, scripted=True)

    observations = collect(_lab(tmp_path), ["R1"], backend=backend, close=backend.close)

    assert runtime_state_available(observations) is False
    assert observations.command_support("R1", "show ip route") is SupportStatus.UNAVAILABLE
    evidence = observations.evidence_for("R1", "show ip route")
    assert evidence is not None
    assert evidence.source is EvidenceSource.SCRIPTED_BACKEND
    assert evidence.is_live is False


def test_source_hash_is_unchanged(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    before = sha256_file(lab)
    backend = FakeBackend({"show ip route": SHOW_IP_ROUTE})

    observations = collect(lab, ["R1"], backend=backend, close=backend.close)

    assert observations.source_intact is True
    assert observations.source_sha256_before == before
    assert observations.source_sha256_after == before
    assert sha256_file(lab) == before


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("predicted", "observed", "expected"),
    [
        (True, True, Conclusion.VERIFIED),
        (True, False, Conclusion.CONTRADICTED),
        (False, True, Conclusion.CONTRADICTED),
        (False, False, Conclusion.VERIFIED),
        (True, None, Conclusion.INCONCLUSIVE),
        (False, None, Conclusion.INCONCLUSIVE),
    ],
)
def test_prediction_agrees_truth_table(
    predicted: bool, observed: bool | None, expected: Conclusion
) -> None:
    assert prediction_agrees("fact", predicted, observed) is expected


def test_static_evidence_never_yields_verified() -> None:
    assert prediction_agrees("route exists", True, None) is not Conclusion.VERIFIED
    assert prediction_agrees("route exists", False, None) is Conclusion.INCONCLUSIVE

    empty = LiveObservationSet(model_path="missing.pkt")
    assert runtime_state_available(empty) is False
    assert empty.has_runtime_state is False

    note = runtime_state_note()
    assert "File-state" in note
    assert "never yields VERIFIED" in note


# ---------------------------------------------------------------------------
# The explicit UNSUPPORTED path
# ---------------------------------------------------------------------------


def test_pt_901_limitations_are_named_with_evidence() -> None:
    assert support_status("behavioural_ping") is SupportStatus.UNSUPPORTED
    assert support_status("end_host_cli") is SupportStatus.UNSUPPORTED
    assert support_status("show_ip_route") is SupportStatus.SUPPORTED
    assert support_status("mac_table") is SupportStatus.UNKNOWN

    reason = unsupported_reason("end_host_cli")
    assert reason is not None and "enterCommand" in reason

    evidence_text = " ".join(limitation.evidence for limitation in PT_901_LIMITATIONS)
    assert 'IPC call "enterCommand" not found' in evidence_text
    assert "EXECUTION_ERROR" in evidence_text


# ---------------------------------------------------------------------------
# One opt-in live test. Never run by default; a skip is not a pass.
# ---------------------------------------------------------------------------

LAB = (
    Path(__file__).parents[1]
    / "test-labs"
    / "broken_campus"
    / "broken_campus_student.pkt"
)


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip() not in {"", "0", "false", "no"}


@pytest.mark.live_simulator
@pytest.mark.skipif(
    not (
        _enabled("TRIDENT_ALLOW_LIVE_SIMULATOR")
        and _enabled("TRIDENT_RUN_ENGINE_D_LIVE")
    ),
    reason=(
        "live Engine D observations need TRIDENT_ALLOW_LIVE_SIMULATOR=1 and "
        "TRIDENT_RUN_ENGINE_D_LIVE=1"
    ),
)
def test_live_collection_reads_runtime_state_without_mutating_the_source() -> None:
    if not LAB.is_file():
        pytest.skip(f"{LAB} is not present; generate the broken-campus lab first")
    from trident.simulator.backends import credentials_from_env, find_packet_tracer

    if find_packet_tracer() is None:
        pytest.skip("Packet Tracer is not installed in a searchable location")
    if credentials_from_env() is None:
        pytest.skip("no registered ExApp: configure TRIDENT_PT_APP_ID / TRIDENT_PT_SECRET")

    before = sha256_file(LAB)
    observations = collect(
        LAB, ["SW-DIST"], budget_seconds=150.0, command_timeout_s=70.0
    )

    assert observations.source_intact is True, observations.cleanup_status
    assert runtime_state_available(observations) is True
    probe = observations.evidence_for("SW-DIST", "show vlan brief")
    assert probe is not None and probe.is_live is True, observations.as_dict()
    assert sha256_file(LAB) == before
