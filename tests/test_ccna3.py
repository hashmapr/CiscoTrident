"""The CCNA-3 extension labs must contain exactly what their answer keys claim.

These labs add routed internetworks to the gauntlet: three-router static chains,
route selection with a floating static, an extended ACL policy, and an
asymmetric flow whose return path is the broken half. The dangerous failure for
a scored lab is not "generation crashed" — it is that generation succeeds, the
fault silently does not land, and the answer key names a defect no amount of
correct analysis can earn.

Every test here is offline. Packet Tracer is never started; the generation tests
skip when ``pkt_core`` is missing. What they cannot prove is stated in
``docs/gauntlet/CCNA3_EXTENSION_RESULTS.md``: that Packet Tracer 9.0.1 opens the
file, brings the links up, and that the routing and ACL behaviour is what IOS
does at runtime.
"""

from __future__ import annotations

import dataclasses

import pytest

from trident.diagnostics import diagnose, report
from trident.labgen import available
from trident.labgen.ccna3 import (
    LAB_NAMES,
    build_network_model,
    clean_control,
    end_host_gateway_support,
    end_hosts_for,
    lab,
    labs,
    probes_for,
)
from trident.labgen.faults import faulted_configs, intended_configs
from trident.labgen.spec import DeviceRole, FaultCategory, TargetKind

_PKT_OK, _PKT_REASON = available()

#: Building a ``NetworkModel`` runs the production normaliser over the spec's
#: config text, which is the slow part of this file. The specs are deterministic,
#: so each model is built once and shared.
_MODEL_CACHE: dict[tuple[str, bool], object] = {}

_FINDING_STATUSES = {"CONFIRMED_DEFECT", "SUSPECTED"}


def _model(name: str, *, apply_faults: bool = False):
    key = (name, apply_faults)
    if key not in _MODEL_CACHE:
        _MODEL_CACHE[key] = build_network_model(lab(name), apply_faults=apply_faults)
    return _MODEL_CACHE[key]


def _findings(name: str, *, apply_faults: bool = False) -> list[dict]:
    return report(diagnose(_model(name, apply_faults=apply_faults)))


def _interface_block(config: list[str], iface: str) -> list[str]:
    """The lines under ``interface <iface>``, body indentation included.

    Interface bodies in this module are written with a leading space and
    top-level lines are not, so the block ends at the next unindented line. That
    matters for ``no shutdown``: a device has one per interface, so the
    assertion has to be scoped to the interface the fault names.
    """
    header = f"interface {iface}".lower()
    start = None
    for index, line in enumerate(config):
        if line.strip().lower() == header:
            start = index + 1
            break
    if start is None:
        raise AssertionError(f"no {header!r} block in config")
    body: list[str] = []
    for line in config[start:]:
        if line and not line.startswith((" ", "\t")):
            break
        body.append(line)
    return body


def _scoped_lines(name: str, fault, configs: dict[str, list[str]]) -> list[str]:
    """The exact config lines a fault claims to have edited."""
    if fault.target is TargetKind.INTERFACE_LINE:
        return _interface_block(configs[fault.device], fault.interface)
    return configs[fault.device]


# ---------------------------------------------------------------------------
# Spec shape
# ---------------------------------------------------------------------------


def test_all_four_labs_exist() -> None:
    assert LAB_NAMES == (
        "ccna3-static-chains",
        "ccna3-route-selection",
        "ccna3-acl-policy",
        "ccna3-asymmetric",
    )
    assert set(labs()) == set(LAB_NAMES)


def test_unknown_lab_names_are_rejected_with_the_choices() -> None:
    with pytest.raises(KeyError, match="ccna3-static-chains"):
        lab("ccna3-does-not-exist")
    with pytest.raises(KeyError, match="ccna3-static-chains"):
        probes_for("ccna3-does-not-exist")


@pytest.mark.parametrize("name", LAB_NAMES)
def test_lab_validates(name: str) -> None:
    assert lab(name).validate() == []


@pytest.mark.parametrize("name", LAB_NAMES)
def test_lab_totals_exactly_one_hundred_points(name: str) -> None:
    spec = lab(name)
    assert spec.point_total() == 100
    assert all(fault.points > 0 for fault in spec.faults)


@pytest.mark.parametrize("name", LAB_NAMES)
def test_lab_carries_the_required_fault_vocabulary(name: str) -> None:
    """Every lab must cover routing, addressing and an interface fault.

    A static-routing lab with no addressing fault would let a student pass by
    reading only the routing table; the point of the set is that the four
    failure modes are always present.
    """
    categories = {fault.category for fault in lab(name).faults}
    assert FaultCategory.ROUTING in categories
    assert FaultCategory.ADDRESSING in categories
    assert FaultCategory.INTERFACE in categories


@pytest.mark.parametrize("name", LAB_NAMES)
def test_every_lab_has_a_missing_route_and_a_wrong_next_hop(name: str) -> None:
    """The two routing faults a CCNA-3 lab cannot omit."""
    faults = lab(name).faults
    missing = [f for f in faults if f.actual.strip().startswith("! ip route")]
    wrong_hop = [f for f in faults if not f.actual.strip().startswith("!") and "ip route" in f.actual]
    assert missing, "no missing-route fault"
    assert wrong_hop, "no wrong-next-hop fault"


def test_the_acl_lab_covers_security_and_carries_a_deny_all_fault() -> None:
    spec = lab("ccna3-acl-policy")
    assert FaultCategory.SECURITY in {fault.category for fault in spec.faults}
    deny_all = [
        fault for fault in spec.faults if fault.actual.strip().lower() == "access-list 100 deny ip any any"
    ]
    assert len(deny_all) == 1
    # The intended line it replaces must be a permit: the fault is the accident,
    # not the policy.
    assert deny_all[0].expected.strip().lower().startswith("access-list 100 permit ip")


@pytest.mark.parametrize("name", LAB_NAMES)
def test_every_device_is_cabled_and_no_port_is_used_twice(name: str) -> None:
    spec = lab(name)
    linked = {link.a for link in spec.links} | {link.b for link in spec.links}
    assert {device.name for device in spec.devices} - linked == set()
    ports = [(link.a, link.a_port) for link in spec.links] + [(link.b, link.b_port) for link in spec.links]
    assert len(ports) == len(set(ports))


@pytest.mark.parametrize("name", LAB_NAMES)
def test_every_interfacespec_names_a_cabled_port(name: str) -> None:
    """A configured interface that no cable reaches is a route IOS would drop.

    This is the "always cable both ends before writing a route" rule encoded as
    a test: the config may not address an interface that has no link.
    """
    spec = lab(name)
    cabled: set[tuple[str, str]] = set()
    for link in spec.links:
        cabled.add((link.a, link.a_port))
        cabled.add((link.b, link.b_port))
    configured = {(device.name, iface.name) for device in spec.devices for iface in device.interfaces}
    assert configured <= cabled


@pytest.mark.parametrize("name", LAB_NAMES)
def test_every_fault_has_progressive_hints(name: str) -> None:
    for fault in lab(name).faults:
        assert fault.hint_1, fault.fault_id
        assert fault.hint_2, fault.fault_id
        assert fault.hint_1 != fault.hint_2, fault.fault_id
        assert fault.symptom, fault.fault_id


# ---------------------------------------------------------------------------
# Fault application: the answer key must match the config text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", LAB_NAMES)
def test_faulted_configs_applies_every_fault_without_error(name: str) -> None:
    spec = lab(name)
    _configs, applied = faulted_configs(spec)
    assert {change.fault_id for change in applied} == {fault.fault_id for fault in spec.faults}


@pytest.mark.parametrize("name", LAB_NAMES)
def test_every_fault_is_a_router_running_config_edit(name: str) -> None:
    """No end-host CLI, no VLAN database, no block deletion.

    Packet Tracer 9.0.1 rejects ``enterCommand`` on PC-PT/Server-PT, so a fault
    on an end host could never be verified live; and these labs have no VLAN
    layer for a ``VLAN_DB`` fault to sit in.
    """
    spec = lab(name)
    for fault in spec.faults:
        assert spec.device(fault.device).role is DeviceRole.ROUTER, fault.fault_id
        assert fault.target in {TargetKind.INTERFACE_LINE, TargetKind.GLOBAL_LINE}, fault.fault_id


@pytest.mark.parametrize("name", LAB_NAMES)
def test_each_fault_text_lands_in_its_device_block(name: str) -> None:
    """The answer key describes the bytes: actual present, expected gone."""
    spec = lab(name)
    configs, _applied = faulted_configs(spec)
    for fault in spec.faults:
        lines = {line.strip() for line in _scoped_lines(name, fault, configs)}
        actual = fault.actual.strip()
        expected = fault.expected.strip()
        if actual.startswith("!"):
            # A removal fault proves itself by its expected line being absent.
            assert expected not in lines, (
                f"fault {fault.fault_id}: {expected!r} should have been removed from {fault.device}"
            )
            continue
        assert actual in lines, f"fault {fault.fault_id}: {actual!r} is not in the config of {fault.device}"
        assert expected not in lines, (
            f"fault {fault.fault_id}: the intended line {expected!r} survived on {fault.device}"
        )


@pytest.mark.parametrize("name", LAB_NAMES)
def test_the_reference_build_has_none_of_the_faults(name: str) -> None:
    """``apply_faults=False`` must not contain any fault's written value."""
    spec = lab(name)
    intended = intended_configs(spec)
    for fault in spec.faults:
        if fault.actual.strip().startswith("!"):
            continue
        lines = {line.strip() for line in _scoped_lines(name, fault, intended)}
        assert fault.actual.strip() not in lines, (
            f"fault {fault.fault_id}: the intended build already contains {fault.actual!r}"
        )


@pytest.mark.parametrize("name", LAB_NAMES)
def test_the_intended_build_differs_from_the_student_build(name: str) -> None:
    spec = lab(name)
    intended = intended_configs(spec)
    student = faulted_configs(spec)[0]
    assert {device for device in intended if intended[device] != student[device]}


# ---------------------------------------------------------------------------
# Clean control: the false-positive guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", LAB_NAMES)
def test_clean_control_has_no_faults_and_none_of_the_answer_key(name: str) -> None:
    clean = clean_control(name)
    assert clean.faults == []
    assert clean.point_total() == 0
    assert clean.validate() == []
    assert clean.name == lab(name).name


@pytest.mark.parametrize("name", LAB_NAMES)
def test_clean_control_produces_zero_findings(name: str) -> None:
    """The most important test in this file.

    If a healthy network reports a defect, every genuine finding on the faulted
    build is suspect: the student cannot tell the lab's faults from the engine's
    false positives. The intended configuration is the fixed point.
    """
    findings = _findings(name, apply_faults=False)
    assert findings == [], f"{name}: a healthy network produced {len(findings)} finding(s): " + "; ".join(
        f"{f['kind']} on {f['device']} ({f['suspected_cause']})" for f in findings
    )


@pytest.mark.parametrize("name", LAB_NAMES)
def test_clean_control_confirms_no_defect(name: str) -> None:
    diagnosis = diagnose(_model(name, apply_faults=False))
    confirmed = [
        hypothesis for hypothesis in diagnosis.hypotheses if hypothesis.status.value in _FINDING_STATUSES
    ]
    assert confirmed == []


@pytest.mark.parametrize("name", LAB_NAMES)
def test_clean_control_next_hops_are_all_reachable(name: str) -> None:
    """No static route in the intended build is a black hole.

    IOS silently rejects a route whose next hop is not on a connected subnet, so
    the reference build must not contain one. ``UNREACHABLE_NEXT_HOP`` is the
    engine's statement of the same invariant.
    """
    assert "UNREACHABLE_NEXT_HOP" not in {finding["kind"] for finding in _findings(name)}


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", LAB_NAMES)
def test_every_fault_declares_exactly_one_probe(name: str) -> None:
    spec = lab(name)
    probes = probes_for(name)
    assert [probe.fault_id for probe in probes] == [fault.fault_id for fault in spec.faults]


@pytest.mark.parametrize("name", LAB_NAMES)
def test_probes_name_real_devices_and_are_read_only(name: str) -> None:
    spec = lab(name)
    names = {device.name for device in spec.devices}
    for probe in probes_for(name):
        assert probe.device in names, probe.fault_id
        assert probe.command.startswith("show "), f"{probe.fault_id}: {probe.command!r} is not read-only"
        assert "\n" not in probe.command


@pytest.mark.parametrize("name", LAB_NAMES)
def test_probes_target_the_faulted_device(name: str) -> None:
    spec = lab(name)
    for probe in probes_for(name):
        assert probe.device == spec.fault(probe.fault_id).device


# ---------------------------------------------------------------------------
# Detectability: the declared hypothesis must actually be formed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", LAB_NAMES)
def test_each_declared_kind_is_formed_by_the_engine(name: str) -> None:
    """Every probe's ``expected_kind`` is a claim; prove it fault by fault.

    Each fault is applied *alone* so a second fault cannot mask or manufacture
    the finding, and the engine is asked for the kinds it reports. A fault whose
    probe declares no kind must produce no finding at all — inventing a
    detector claim for a silently absent static route would be a false claim in
    the answer key.
    """
    spec = lab(name)
    for probe in probes_for(name):
        fault = spec.fault(probe.fault_id)
        single = dataclasses.replace(spec, faults=[dataclasses.replace(fault)])
        kinds = {
            finding["kind"] for finding in report(diagnose(build_network_model(single, apply_faults=True)))
        }
        if probe.expected_kind is None:
            assert kinds == set(), f"{name}/{fault.fault_id}: expected silence, engine said {kinds}"
        else:
            assert probe.expected_kind in kinds, (
                f"{name}/{fault.fault_id}: expected {probe.expected_kind}, engine said {kinds}"
            )


def test_acl_policy_is_permit_only_in_the_clean_build_and_deny_in_the_student_build() -> None:
    """The ACL lab's policy is expressed by permit + implicit deny.

    An explicit ``deny`` bound to an interface is indistinguishable from a broken
    ACL to the engine (``ACL_BLOCK``), so the clean build may not contain one;
    the fault is precisely the explicit deny that swallows the permit.
    """
    clean = _model("ccna3-acl-policy", apply_faults=False)
    assert [acl.acl_id for acl in clean.acls] == ["100"]
    assert {acl.action for acl in clean.acls} == {"permit"}
    assert {acl.applied_interface for acl in clean.acls} == {"GigabitEthernet0/1"}
    assert {acl.direction for acl in clean.acls} == {"out"}

    student = _model("ccna3-acl-policy", apply_faults=True)
    assert {(acl.action, acl.applied_interface) for acl in student.acls} >= {("deny", "GigabitEthernet0/1")}


# ---------------------------------------------------------------------------
# Generation (skipped when pkt_core is unavailable)
# ---------------------------------------------------------------------------

_NEEDS_PKT = pytest.mark.skipif(not _PKT_OK, reason=_PKT_REASON)


@_NEEDS_PKT
@pytest.mark.parametrize("name", LAB_NAMES)
def test_generate_writes_a_file_that_decodes_to_the_same_devices(name: str, tmp_path) -> None:
    from pkt_core.codec.container import decode
    from pkt_core.models import Lab

    from trident.labgen import generate

    spec = lab(name)
    result = generate(spec, tmp_path / f"{name}.pkt", apply_faults=True)
    assert result.encode_ok, result.notes
    assert result.device_count == len(spec.devices)
    assert result.link_count == len(spec.links)

    decoded = Lab.from_bytes(decode(str(result.path)).xml)
    assert {device.name for device in decoded.devices} == {device.name for device in spec.devices}
    assert len(decoded.links) == len(spec.links)


@_NEEDS_PKT
@pytest.mark.parametrize("name", LAB_NAMES)
def test_the_faulted_file_differs_from_the_reference_file(name: str, tmp_path) -> None:
    from trident.labgen import generate

    spec = lab(name)
    student = generate(spec, tmp_path / "student.pkt", apply_faults=True)
    reference = generate(spec, tmp_path / "reference.pkt", apply_faults=False)
    assert student.sha256 != reference.sha256
    assert student.configs != reference.configs


@_NEEDS_PKT
@pytest.mark.parametrize("name", LAB_NAMES)
def test_the_fault_text_is_in_the_generated_device_element(name: str, tmp_path) -> None:
    """The answer key must describe the file, not a parallel in-memory idea of it.

    The fault is checked inside the decoded ``<DEVICE>`` element for its own
    device, because the same text can legitimately appear on another router.
    """
    import re

    from pkt_core.codec.container import decode

    from trident.labgen import generate

    spec = lab(name)
    result = generate(spec, tmp_path / f"{name}.pkt", apply_faults=True)
    text = decode(str(result.path)).xml.decode("utf-8", "replace")
    blocks: dict[str, str] = {}
    for chunk in re.findall(r"<DEVICE>.*?</DEVICE>", text, re.DOTALL):
        found = re.search(r"<NAME[^>]*>(.*?)</NAME>", chunk, re.DOTALL)
        if found:
            blocks[found.group(1).strip()] = chunk

    for fault in spec.faults:
        # Compare stripped line text: an interface-line fault is written into the
        # block with one leading space, and a fault's ``actual`` is stored without
        # indentation, so an exact ``<LINE>`` match would depend on spacing.
        lines = {line.strip() for line in re.findall(r"<LINE>(.*?)</LINE>", blocks[fault.device])}
        actual = fault.actual.strip()
        expected = fault.expected.strip()
        if actual.startswith("!"):
            assert expected not in lines, fault.fault_id
            continue
        assert actual in lines, fault.fault_id


@_NEEDS_PKT
@pytest.mark.parametrize("name", LAB_NAMES)
def test_the_clean_control_can_be_generated_too(name: str, tmp_path) -> None:
    from trident.labgen import generate

    result = generate(clean_control(name), tmp_path / f"{name}-clean.pkt", apply_faults=False)
    assert result.encode_ok, result.notes


#: Packet Tracer reads a PC's gateway from ``<ENGINE><GATEWAY>``; ``pkt_core``
#: 0.2.2 (pinned in this venv) writes only ``<PORT><PORT_GATEWAY>``. That is a
#: dependency defect shared by every labgen lab, not something a lab spec can
#: fix, so it is recorded as a strict xfail: it reports as xfailed while the
#: dependency is unfixed and starts passing (with the marker inert) once it is.
_ENDHOST_GW_OK, _ENDHOST_GW_REASON = end_host_gateway_support()


@_NEEDS_PKT
@pytest.mark.xfail(not _ENDHOST_GW_OK, reason=_ENDHOST_GW_REASON, strict=True)
@pytest.mark.parametrize("name", LAB_NAMES)
def test_pc_gateways_are_written_where_packet_tracer_reads_them(name: str, tmp_path) -> None:
    import re

    from pkt_core.codec.container import decode

    from trident.labgen import generate

    spec = lab(name)
    result = generate(spec, tmp_path / f"{name}-gw.pkt", apply_faults=True)
    text = decode(str(result.path)).xml.decode("utf-8", "replace")

    expected = {device.name: device.pc_ip[2] for device in spec.devices if device.pc_ip}
    seen: dict[str, str] = {}
    for chunk in re.findall(r"<DEVICE>.*?</DEVICE>", text, re.DOTALL):
        name_match = re.search(r"<NAME[^>]*>(.*?)</NAME>", chunk, re.DOTALL)
        gateway = re.search(r"<ENGINE>.*?<GATEWAY>(.*?)</GATEWAY>", chunk, re.DOTALL)
        if name_match and gateway and name_match.group(1).strip() in expected:
            seen.setdefault(name_match.group(1).strip(), gateway.group(1).strip())

    assert seen, "no end-host <ENGINE><GATEWAY> elements found in the generated file"
    for device, gateway in expected.items():
        assert seen.get(device) == gateway, (
            f"{name}: {device} carries gateway {seen.get(device)!r} in <ENGINE><GATEWAY>, "
            f"expected {gateway!r}"
        )


# ---------------------------------------------------------------------------
# End-host facts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", LAB_NAMES)
def test_end_host_facts_match_the_spec(name: str) -> None:
    spec = lab(name)
    hosts = end_hosts_for(spec)
    expected = {device.name for device in spec.devices if device.pc_ip}
    assert set(hosts) == expected
    for device in spec.devices:
        if not device.pc_ip:
            continue
        address, mask, gateway = device.pc_ip
        assert hosts[device.name] == {"ip": address, "subnet": mask, "gateway": gateway}
