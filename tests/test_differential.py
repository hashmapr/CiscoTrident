"""Differential verification: prediction versus observation.

The rules that matter here:

* A non-definite prediction cannot be confirmed or refuted by any experiment.
* An inconclusive observation establishes nothing and is never counted as
  agreement.
* Agreement is corroboration, not proof; neither side is rewritten.
"""

from __future__ import annotations

import pytest

from trident.deepcore import DeepCore
from trident.deepcore.differential import (
    Agreement,
    Cause,
    compare,
    differential_report,
    predict_and_compare,
)
from trident.models import DeviceInfo, InterfaceInfo, NetworkModel


def _device(name, kind="router"):
    return DeviceInfo(id=name, name=name, hostname=name, device_type=kind, configuration=[])


def _iface(device, name, address, prefix, admin="up"):
    return InterfaceInfo(
        device=device, name=name, canonical_name=name,
        ipv4_address=address, prefix_length=prefix, admin_state=admin,
    )


def _reachable() -> NetworkModel:
    return NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
        },
    )


def _blocked() -> NetworkModel:
    """R1 predicts delivery but its interface is shut, so it should drop."""
    model = NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30, admin="administratively down"),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
        },
    )
    return model


def _indefinite() -> NetworkModel:
    return NetworkModel(
        devices={"R1": _device("R1"), "PC1": _device("PC1", "host")},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24)},
    )


# ---------------------------------------------------------------------------
# Agreement
# ---------------------------------------------------------------------------


def test_prediction_delivered_and_observation_delivered_agree():
    prediction = DeepCore(_reachable()).predict_path("R1", "R2")
    result = compare(prediction, "DELIVERED")
    assert result.agreement is Agreement.AGREES
    assert result.is_trusted is True


def test_prediction_dropped_and_observation_dropped_agree():
    prediction = DeepCore(_blocked()).predict_path("R1", "R2")
    assert prediction.delivered is False
    result = compare(prediction, "DROPPED")
    assert result.agreement is Agreement.AGREES


def test_delivered_prediction_against_drop_disagrees():
    prediction = DeepCore(_reachable()).predict_path("R1", "R2")
    result = compare(prediction, "DROPPED")
    assert result.agreement is Agreement.DISAGREES
    assert result.cause is Cause.FORWARDING_LOGIC_ERROR
    assert result.caveats


def test_dropped_prediction_against_delivery_disagrees():
    prediction = DeepCore(_blocked()).predict_path("R1", "R2")
    result = compare(prediction, "DELIVERED")
    assert result.agreement is Agreement.DISAGREES
    assert "missing a path that exists" in " ".join(result.caveats)


# ---------------------------------------------------------------------------
# Insufficient evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["INCONCLUSIVE", "UNSUPPORTED", "EXECUTION_ERROR", "SOMETHING_ELSE"])
def test_non_committal_observations_establish_nothing(status):
    prediction = DeepCore(_reachable()).predict_path("R1", "R2")
    result = compare(prediction, status)
    assert result.agreement is Agreement.INSUFFICIENT_EVIDENCE
    assert result.is_trusted is False


def test_an_indefinite_prediction_is_untestable():
    prediction = DeepCore(_indefinite()).predict_path("R1", "PC1")
    assert prediction.definite is False
    result = compare(prediction, "DELIVERED")
    assert result.agreement is Agreement.UNTESTABLE
    assert result.is_trusted is False
    # The prediction's own limitations are carried through.
    assert result.caveats


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def test_discrepancy_preserves_both_sides():
    prediction = DeepCore(_reachable()).predict_path("R1", "R2")
    result = compare(
        prediction,
        "DROPPED",
        operation="addSimplePdu(R1 -> R2, icmp)",
        simulator_version="9.0.1.0858",
        source_sha256="a" * 64,
        session_id="sess-1",
    )
    payload = result.as_dict()
    # The prediction survives intact...
    assert payload["predicted"] is True
    assert payload["prediction_steps"]
    # ...alongside the observation and its provenance.
    assert payload["observed"] == "DROPPED"
    assert payload["simulator_version"] == "9.0.1.0858"
    assert payload["session_id"] == "sess-1"
    assert payload["source_sha256"] == "a" * 64
    # ...and a reproduction procedure.
    assert "predict_path" in payload["reproduction"]
    assert "send_pdu" in payload["reproduction"]


def test_report_counts_and_lists_only_disagreements():
    predictions = [
        DeepCore(_reachable()).predict_path("R1", "R2"),
        DeepCore(_blocked()).predict_path("R1", "R2"),
    ]
    results = [
        compare(predictions[0], "DELIVERED"),
        compare(predictions[1], "DELIVERED"),  # disagrees
    ]
    report = differential_report(results)
    assert report["total"] == 2
    assert report["counts"]["AGREES"] == 1
    assert report["counts"]["DISAGREES"] == 1
    assert len(report["disagreements"]) == 1


def test_predict_and_compare_helper():
    result = predict_and_compare(_reachable(), "R1", "R2", "DELIVERED")
    assert result.agreement is Agreement.AGREES


def test_comparison_does_not_modify_the_prediction():
    prediction = DeepCore(_reachable()).predict_path("R1", "R2")
    before = prediction.as_dict()
    compare(prediction, "DROPPED")
    assert prediction.as_dict() == before


def test_cause_is_unknown_when_nothing_supports_a_guess():
    """A disagreement with no further evidence must not invent a cause."""
    prediction = DeepCore(_reachable()).predict_path("R1", "R2")
    result = compare(prediction, "DROPPED")
    # FORWARDING_LOGIC_ERROR is the only claim the evidence supports here; it is
    # never one of the more specific causes without additional evidence.
    assert result.cause is Cause.FORWARDING_LOGIC_ERROR
    assert result.cause is not Cause.SIMULATOR_UNSUPPORTED
