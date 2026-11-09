"""When is an administratively-shut interface actually a fault?

Shutdown is a configuration *choice*, so it is only a defect when the interface
is demonstrably needed. These cases pin the boundary in both directions: the
false positives that made every switch in every lab look broken, and the real
faults that must still be caught.
"""

from __future__ import annotations

from trident.diagnostics import SHUTDOWN_INTERFACE, diagnose, report
from trident.diagnostics.types import HypothesisStatus
from trident.models import InterfaceInfo, LinkInfo, NetworkModel


def _iface(device: str, name: str, ip=None, prefix=None, admin="up", vlans=None, mode="access"):
    return InterfaceInfo(
        device=device,
        name=name,
        canonical_name=name,
        ipv4_address=ip,
        prefix_length=prefix,
        admin_state=admin,
        operational_state=admin,
        vlan_assignments=vlans or [],
        access_mode=mode,
    )


def _model():
    return NetworkModel(
        devices={
            "SW1": None,
            "R1": None,
        }
    )


def _base() -> NetworkModel:
    from trident.models import DeviceInfo

    return NetworkModel(
        devices={
            "SW1": DeviceInfo(id="SW1", name="SW1", hostname="SW1", device_type="switch", configuration=[]),
            "R1": DeviceInfo(id="R1", name="R1", hostname="R1", device_type="router", configuration=[]),
            "PC1": DeviceInfo(id="PC1", name="PC1", hostname="PC1", device_type="host", configuration=[]),
        },
        interfaces={
            "SW1:Gi0/1": _iface("SW1", "GigabitEthernet0/1", "10.0.0.2", 24, vlans=["10"]),
            "SW1:Fa0/1": _iface("SW1", "FastEthernet0/1", vlans=["10"]),
            "PC1:Fa0": _iface("PC1", "FastEthernet0", "10.0.0.10", 24, mode=None),
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24),
        },
        links=[
            LinkInfo(device_a="SW1", interface_a="FastEthernet0/1", device_b="PC1", interface_b="FastEthernet0"),
            LinkInfo(device_a="SW1", interface_a="GigabitEthernet0/1", device_b="R1", interface_b="GigabitEthernet0/0"),
        ],
    )


def _shutdown_findings(model: NetworkModel):
    return [h for h in diagnose(model).hypotheses if h.kind == SHUTDOWN_INTERFACE]


# ---------------------------------------------------------------------------
# Must NOT be reported
# ---------------------------------------------------------------------------


def test_healthy_network_is_silent():
    assert _shutdown_findings(_base()) == []


def test_management_svi_down_is_not_a_fault():
    """An SVI follows its member ports; its state is derived, not configured."""
    model = _base()
    model.interfaces["SW1:Vlan1"] = _iface(
        "SW1", "Vlan1", "10.0.0.2", 24, admin="administratively down", mode=None
    )
    assert _shutdown_findings(model) == []


def test_management_svi_with_address_is_not_a_fault():
    """Even addressed, an SVI being down is normal when no port is up."""
    model = _base()
    model.interfaces["SW1:Vlan99"] = _iface(
        "SW1", "Vlan99", "192.168.99.2", 24, admin="administratively down", mode=None
    )
    assert _shutdown_findings(model) == []


def test_unused_port_with_no_address_or_vlan_is_not_a_fault():
    model = _base()
    model.interfaces["SW1:Fa0/24"] = _iface(
        "SW1", "FastEthernet0/24", admin="administratively down", vlans=[], mode=None
    )
    assert _shutdown_findings(model) == []


def test_cabled_but_unconfigured_shutdown_is_not_a_fault():
    """A patch cable to a spare port does not prove the port should be up."""
    model = _base()
    model.interfaces["SW1:Fa0/20"] = _iface(
        "SW1", "FastEthernet0/20", admin="administratively down", vlans=[], mode=None
    )
    model.interfaces["PC2:Fa0"] = _iface("PC2", "FastEthernet0", mode=None)
    model.links.append(
        LinkInfo(device_a="SW1", interface_a="FastEthernet0/20", device_b="PC2", interface_b="FastEthernet0")
    )
    assert _shutdown_findings(model) == []


def test_unused_serial_port_is_not_a_fault():
    model = _base()
    model.interfaces["R1:Se0/0/0"] = _iface(
        "R1", "Serial0/0/0", admin="administratively down", vlans=[], mode=None
    )
    assert _shutdown_findings(model) == []


def test_spare_router_entirely_shut_is_not_a_fault():
    from trident.models import DeviceInfo

    model = _base()
    model.devices["Spare"] = DeviceInfo(
        id="Spare", name="Spare", hostname="Spare", device_type="router", configuration=[]
    )
    model.interfaces["Spare:Gi0/0"] = _iface("Spare", "GigabitEthernet0/0", admin="administratively down", mode=None)
    model.interfaces["Spare:Gi0/1"] = _iface("Spare", "GigabitEthernet0/1", admin="administratively down", mode=None)
    assert _shutdown_findings(model) == []


# ---------------------------------------------------------------------------
# MUST still be reported
# ---------------------------------------------------------------------------


def test_access_port_in_a_service_vlan_shut_is_a_fault():
    """Someone configured this port for a VLAN, then disabled it."""
    model = _base()
    model.interfaces["SW1:Fa0/1"].admin_state = "administratively down"
    findings = _shutdown_findings(model)
    assert findings, "a VLAN-assigned access port that is shut must be reported"
    assert findings[0].status is HypothesisStatus.CONFIRMED_DEFECT
    assert findings[0].interface == "FastEthernet0/1"


def test_trunk_shut_is_a_fault():
    model = _base()
    model.interfaces["SW1:Gi0/1"].admin_state = "administratively down"
    model.interfaces["SW1:Gi0/1"].access_mode = "trunk"
    findings = _shutdown_findings(model)
    assert findings
    assert findings[0].interface == "GigabitEthernet0/1"


def test_addressed_routed_port_shut_is_a_fault():
    model = _base()
    model.interfaces["R1:Gi0/0"].admin_state = "administratively down"
    findings = _shutdown_findings(model)
    assert findings
    assert findings[0].interface == "GigabitEthernet0/0"


def test_multiple_plausible_faults_report_only_the_real_ones():
    """Noise and a genuine fault in one network."""
    model = _base()
    model.interfaces["SW1:Vlan1"] = _iface("SW1", "Vlan1", admin="administratively down", mode=None)
    model.interfaces["SW1:Fa0/24"] = _iface("SW1", "FastEthernet0/24", admin="administratively down", mode=None)
    model.interfaces["SW1:Fa0/1"].admin_state = "administratively down"
    findings = _shutdown_findings(model)
    interfaces = {h.interface for h in findings}
    assert interfaces == {"FastEthernet0/1"}, interfaces


def test_report_includes_the_reason():
    model = _base()
    model.interfaces["SW1:Fa0/1"].admin_state = "administratively down"
    entry = report(diagnose(model))[0]
    assert entry["kind"] == SHUTDOWN_INTERFACE
    assert entry["device"] == "SW1"
    assert entry["confidence"] in {"HIGH", "MEDIUM", "LOW"}


def test_runtime_up_contradicts_static_shutdown():
    """Static says shut, runtime says up: suspicion, not a confirmed defect."""
    from trident.evidence import EvidenceBundle
    from trident.evidence.api import parse_cli_output

    model = _base()
    model.interfaces["SW1:Fa0/1"].admin_state = "administratively down"
    bundle = EvidenceBundle()
    bundle.add(
        parse_cli_output(
            "SW1# show ip interface brief\n"
            "Interface              IP-Address      OK? Method Status    Protocol\n"
            "FastEthernet0/1        unassigned      YES unset  up        up\n",
            device="SW1",
            captured_at="2026-11-09T00:00:00Z",
        )
    )
    findings = [
        h
        for h in diagnose(model, bundle).hypotheses
        if h.kind == SHUTDOWN_INTERFACE
    ]
    assert findings
    assert findings[0].status is HypothesisStatus.SUSPECTED
    assert findings[0].contradicting
