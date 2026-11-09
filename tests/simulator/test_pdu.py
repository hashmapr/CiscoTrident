"""PDU execution: classification, refusal and honest outcomes.

The live tests run against a real Packet Tracer. The offline tests pin the rules
that keep a packet experiment honest, which is the part that must hold even when
no simulator is available.
"""

from __future__ import annotations

from trident.simulator.contracts import BackendKind, Capability, Provenance
from trident.simulator.pdu import (
    PDU_ERRORS,
    DeliveryStatus,
    PduExecutor,
    PduResult,
    _mentions_icmp,
    _replied,
    capability_available,
)


def _factory(device=None, interface=None, operation="addSimplePdu") -> Provenance:
    """Provenance factory matching the executor's call signature."""
    return _prov()


def _prov(backend=BackendKind.SIMULATOR_LIVE) -> Provenance:
    return Provenance(
        backend=backend,
        simulator_version="9.0.1",
        session_id="s1",
        source_sha256="a" * 64,
        working_copy_sha256="b" * 64,
        device=None,
        interface=None,
        operation="addSimplePdu",
        executed_at="2026-11-09T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# Frame-signature detection
# ---------------------------------------------------------------------------


def test_icmp_frames_are_recognised_from_decision_text():
    assert _mentions_icmp(["The Ping process starts the next ping request."])
    assert _mentions_icmp(["The Ping process creates an ICMP Echo Request message"])
    assert _mentions_icmp(["The packet is an ICMP packet."])


def test_control_plane_frames_are_not_mistaken_for_the_test():
    """STP and CDP flood continuously; they are not the ping."""
    assert not _mentions_icmp(["The STP process sends out a configuration BPDU."])
    assert not _mentions_icmp(["The CDP process constructs a CDP frame."])
    assert not _mentions_icmp(["FastEthernet0 receives the frame."])


def test_a_reply_is_recognised_only_from_answer_text():
    assert _replied(["The ICMP process received an Echo Request message."])
    assert _replied(["The ICMP process replies to the Echo Request by setting ICMP type to Echo Reply."])
    assert _replied(["The ICMP process sends an Echo Reply."])
    assert not _replied(["The Ping process creates an ICMP Echo Request message."])


def test_arrival_alone_is_not_a_reply():
    """A frame reaching a device does not mean the device answered."""
    assert not _replied(["FastEthernet0 receives the frame."])


# ---------------------------------------------------------------------------
# Error-code mapping
# ---------------------------------------------------------------------------


def test_error_codes_match_the_shipped_enum():
    assert PDU_ERRORS[0] == "NOT_HAVING_ERROR"
    assert PDU_ERRORS[2] == "NO_SUCH_SOURCE_DEVICE"
    assert PDU_ERRORS[5] == "NO_SUCH_DESTINATION_DEVICE"


def test_observed_codes_for_unknown_devices_are_classified():
    """The installed build returns 20/30 for unknown endpoints."""
    assert PDU_ERRORS[20] == "NO_SUCH_SOURCE_DEVICE"
    assert PDU_ERRORS[30] == "NO_SUCH_DESTINATION_DEVICE"


# ---------------------------------------------------------------------------
# Outcome classification without a simulator
# ---------------------------------------------------------------------------


def test_no_client_is_unsupported_not_success():
    executor = PduExecutor(None, _factory)
    result = executor.send("PC1", "PC2")
    assert result.status is DeliveryStatus.UNSUPPORTED
    assert result.observed is False
    assert result.delivered is False


def test_non_icmp_protocol_is_unsupported_not_substituted():
    executor = PduExecutor(object(), _factory)
    result = executor.send("PC1", "PC2", protocol="tcp")
    assert result.status is DeliveryStatus.UNSUPPORTED
    assert "ICMP" in " ".join(result.caveats) or "icmp" in " ".join(result.caveats).lower()


def test_submission_is_not_delivery():
    """A result only reports DELIVERED when the evidence supports it."""
    result = PduResult(
        status=DeliveryStatus.INCONCLUSIVE,
        source="A",
        destination="B",
        protocol="icmp",
        operation="addSimplePdu",
        raw="",
        provenance=_prov(),
    )
    assert result.delivered is False


def test_result_is_json_serialisable():
    import json

    result = PduResult(
        status=DeliveryStatus.DROPPED,
        source="A",
        destination="B",
        protocol="icmp",
        operation="addSimplePdu",
        raw="frame 0",
        provenance=_prov(),
        frames_seen=3,
        frames_dropped=1,
    )
    payload = result.as_dict()
    json.dumps(payload)
    assert payload["status"] == "DROPPED"
    assert payload["frames_dropped"] == 1
    assert payload["observed"] is True


def test_scripted_provenance_is_never_observed():
    result = PduResult(
        status=DeliveryStatus.DELIVERED,
        source="A",
        destination="B",
        protocol="icmp",
        operation="addSimplePdu",
        raw="",
        provenance=_prov(BackendKind.SCRIPTED),
    )
    assert result.observed is False


def test_capability_helper():
    assert capability_available(frozenset({Capability.SEND_PDU}))
    assert not capability_available(frozenset({Capability.RUN_CLI}))


def test_noise_exclusion_is_documented_in_the_result():
    """When control traffic is filtered, the result says so."""
    result = PduResult(
        status=DeliveryStatus.DELIVERED,
        source="A",
        destination="B",
        protocol="icmp",
        operation="addSimplePdu",
        raw="",
        provenance=_prov(),
        caveats=("10 of 60 frames were protocol control traffic",),
    )
    assert any("control traffic" in caveat for caveat in result.caveats)
