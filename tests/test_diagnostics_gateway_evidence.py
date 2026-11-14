"""Evidence rules for gateway diagnostics.

A gateway verdict is only as good as the evidence it cites and the honesty of
the cases it declines. These tests pin three properties:

* a defect verdict quotes the observed configuration it was formed from;
* absent evidence produces ``INSUFFICIENT_EVIDENCE`` (UNKNOWN), never a defect;
* runtime evidence is matched exactly, so one address cannot impersonate another
  by sharing a prefix.
"""

from __future__ import annotations

from trident.diagnostics import WRONG_GATEWAY, diagnose, report
from trident.diagnostics.types import HypothesisStatus
from trident.evidence import EvidenceBundle
from trident.evidence.api import parse_cli_output
from trident.faultlab import baseline_lab, scenarios
from trident.models import DeviceInfo, NetworkModel


def _gateway_hypotheses(model, bundle=None, device="PC1"):
    return [
        hypothesis
        for hypothesis in diagnose(model, bundle).hypotheses
        if hypothesis.kind == WRONG_GATEWAY and hypothesis.device == device
    ]


def test_a_confirmed_verdict_cites_the_observed_configuration():
    scenario = next(s for s in scenarios() if s.name == "wrong-gateway")
    found = _gateway_hypotheses(scenario.model)

    assert found and found[0].status is HypothesisStatus.CONFIRMED_DEFECT
    detail = found[0].supporting[0].detail
    assert "observed configuration" in detail
    assert "10.10.20.254" in detail
    assert "10.10.20.0/24" in detail, detail


def test_missing_interface_evidence_is_unknown_not_a_defect():
    """A configured gateway with no interface facts cannot be judged."""
    model = NetworkModel(
        devices={"SW1": DeviceInfo(id="SW1", name="SW1", configuration=[])},
        interfaces={},
    )
    model.settings.default_gateways["SW1"] = "10.0.0.1"

    found = _gateway_hypotheses(model, device="SW1")

    assert found
    hypothesis = found[0]
    assert hypothesis.status is HypothesisStatus.INSUFFICIENT_EVIDENCE
    assert "interface addresses and masks on SW1" in hypothesis.missing_evidence
    assert "observed configuration" in hypothesis.suspected_cause
    # An UNKNOWN verdict is not a finding and must not be reported as one.
    assert report(diagnose(model)) == []


def test_an_unparseable_gateway_is_unknown_not_a_fabricated_failure():
    model = baseline_lab()
    model.settings.default_gateways["PC1"] = "not-an-address"

    found = _gateway_hypotheses(model)

    assert found
    assert found[0].status is HypothesisStatus.INSUFFICIENT_EVIDENCE
    assert "IPv4 address" in " ".join(found[0].missing_evidence)
    assert "not-an-address" in found[0].suspected_cause


def test_runtime_evidence_is_matched_exactly_not_by_prefix():
    """``10.10.20.2`` must not be contradicted by an interface holding ``10.10.20.25``."""
    model = baseline_lab()
    model.settings.default_gateways["PC1"] = "10.10.20.2"

    bundle = EvidenceBundle()
    bundle.add(
        parse_cli_output(
            "R2# show ip interface brief\n"
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/1     10.10.20.25     YES manual up                    up\n",
            captured_at="2026-11-08T00:00:00Z",
        )
    )

    found = _gateway_hypotheses(model, bundle)
    assert found
    assert found[0].status is HypothesisStatus.CONFIRMED_DEFECT, found[0].contradicting


def test_runtime_evidence_holding_the_exact_address_contradicts_the_claim():
    model = baseline_lab()
    model.settings.default_gateways["PC1"] = "10.10.20.2"

    bundle = EvidenceBundle()
    bundle.add(
        parse_cli_output(
            "R2# show ip interface brief\n"
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet0/1     10.10.20.2      YES manual up                    up\n",
            captured_at="2026-11-08T00:00:00Z",
        )
    )

    found = _gateway_hypotheses(model, bundle)
    assert found
    assert found[0].status is HypothesisStatus.SUSPECTED
    assert any(observation.source == "RUNTIME_STATE" for observation in found[0].contradicting)


def test_a_healthy_gateway_produces_no_hypothesis_at_all():
    model = baseline_lab()
    assert _gateway_hypotheses(model) == []
