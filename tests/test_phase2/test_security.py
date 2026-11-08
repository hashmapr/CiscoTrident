"""Tests for the configuration security auditor.

Coverage is organised around the honesty contract rather than code paths:

* an explicitly bad line is a CONFIRMED_VIOLATION
* the counter-directive is COMPLIANT with that line as evidence
* a device with no recorded configuration is UNSUPPORTED for every check
* COMPLIANT is never returned without real configuration-line evidence
* the well-known 'public' SNMP community is CRITICAL
* findings are advisory: no field names an executed action
"""

from __future__ import annotations

import dataclasses

import pytest

from trident.models import DeviceInfo, InterfaceInfo, NetworkModel
from trident.security import (
    CHECK_IDS,
    AuditReport,
    Finding,
    FindingStatus,
    Severity,
    audit,
    is_absence_note,
)

BASELINE = "cisco-basic"

TELNET_CONFIG = [
    "version 15.2",
    "hostname SW-TELNET",
    "!",
    "enable secret 9 $9$hash",
    "!",
    "line vty 0 4",
    " transport input telnet",
    "!",
]

SSH_CONFIG = [
    "version 15.2",
    "hostname SW-SSH",
    "!",
    "enable secret 9 $9$hash",
    "ip ssh version 2",
    "!",
    "line vty 0 4",
    " transport input ssh",
    "!",
]


def device(name: str, config: list[str], interfaces: list[str] | None = None) -> DeviceInfo:
    return DeviceInfo(
        id=name,
        name=name,
        hostname=name,
        device_type="switch",
        configuration=list(config),
        interfaces=list(interfaces or []),
    )


def model_of(*devices: DeviceInfo) -> NetworkModel:
    return NetworkModel(devices={dev.name: dev for dev in devices}, snapshot_id="security-test")


def findings_for(report: AuditReport, check_id: str) -> list[Finding]:
    return [finding for finding in report.findings if finding.check_id == check_id]


def one(report: AuditReport, check_id: str) -> Finding:
    matches = findings_for(report, check_id)
    assert len(matches) == 1, f"expected exactly one {check_id} finding, got {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# telnet vs ssh
# ---------------------------------------------------------------------------


def test_transport_input_telnet_is_a_confirmed_violation() -> None:
    report = audit(model_of(device("SW-TELNET", TELNET_CONFIG)), baseline=BASELINE)
    finding = one(report, "telnet-enabled")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert finding.device == "SW-TELNET"
    assert finding.interface is None
    assert any("transport input telnet" in item for item in finding.evidence)
    assert finding.remediation_hint


def test_vty_without_transport_input_is_a_confirmed_violation() -> None:
    config = [
        "hostname SW-OPEN",
        "enable secret 9 $9$hash",
        "!",
        "line vty 0 4",
        " login local",
        "!",
    ]
    report = audit(model_of(device("SW-OPEN", config)), baseline=BASELINE)
    finding = one(report, "telnet-enabled")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert any("line vty 0 4" in item for item in finding.evidence)


def test_transport_input_ssh_is_compliant_with_line_evidence() -> None:
    report = audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline=BASELINE)
    finding = one(report, "telnet-enabled")
    assert finding.status is FindingStatus.COMPLIANT
    assert finding.evidence
    assert any("transport input ssh" in item for item in finding.evidence)
    assert all(not is_absence_note(item) for item in finding.evidence)


def test_transport_input_all_counts_as_telnet() -> None:
    config = [
        "hostname SW-ALL",
        "enable secret 9 $9$hash",
        "line vty 0 4",
        " transport input all",
    ]
    report = audit(model_of(device("SW-ALL", config)), baseline=BASELINE)
    assert one(report, "telnet-enabled").status is FindingStatus.CONFIRMED_VIOLATION


# ---------------------------------------------------------------------------
# ssh-missing
# ---------------------------------------------------------------------------


def test_ssh_version_absent_on_a_device_with_vty_is_a_violation() -> None:
    config = [
        "hostname SW-NO-SSH",
        "enable secret 9 $9$hash",
        "line vty 0 4",
        " transport input ssh",
    ]
    report = audit(model_of(device("SW-NO-SSH", config)), baseline=BASELINE)
    finding = one(report, "ssh-missing")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert any(is_absence_note(item) for item in finding.evidence)


def test_ssh_version_present_is_compliant() -> None:
    report = audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline=BASELINE)
    finding = one(report, "ssh-missing")
    assert finding.status is FindingStatus.COMPLIANT
    assert any("ip ssh version 2" in item for item in finding.evidence)


# ---------------------------------------------------------------------------
# enable secret / cleartext password
# ---------------------------------------------------------------------------


def test_cleartext_enable_password_is_critical() -> None:
    config = [
        "hostname SW-CLEARTEXT",
        "enable password cisco123",
        "line vty 0 4",
        " transport input ssh",
    ]
    report = audit(model_of(device("SW-CLEARTEXT", config)), baseline=BASELINE)
    finding = one(report, "password-in-config")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert finding.severity is Severity.CRITICAL
    assert any("enable password" in item for item in finding.evidence)


def test_cleartext_password_value_is_never_echoed() -> None:
    config = ["hostname SW-CLEARTEXT", "enable password cisco123"]
    report = audit(model_of(device("SW-CLEARTEXT", config)), baseline=BASELINE)
    blob = " ".join(
        item for finding in report.findings for item in finding.evidence
    )
    assert "cisco123" not in blob


def test_no_enable_secret_and_no_enable_password_is_a_violation() -> None:
    config = ["hostname SW-NOENABLE", "line vty 0 4", " transport input ssh"]
    report = audit(model_of(device("SW-NOENABLE", config)), baseline=BASELINE)
    finding = one(report, "no-enable-secret")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION


def test_enable_secret_present_is_compliant() -> None:
    config = ["hostname SW-SECRET", "enable secret 9 $9$hash", "line vty 0 4", " transport input ssh"]
    report = audit(model_of(device("SW-SECRET", config)), baseline=BASELINE)
    finding = one(report, "no-enable-secret")
    assert finding.status is FindingStatus.COMPLIANT
    assert finding.evidence


# ---------------------------------------------------------------------------
# snmp / http
# ---------------------------------------------------------------------------


def test_snmp_community_public_is_critical() -> None:
    config = [
        "hostname SW-SNMP",
        "enable secret 9 $9$hash",
        "snmp-server community public RO",
        "line vty 0 4",
        " transport input ssh",
    ]
    report = audit(model_of(device("SW-SNMP", config)), baseline=BASELINE)
    finding = one(report, "snmp-public")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert finding.severity is Severity.CRITICAL
    assert any("snmp-server community public" in item for item in finding.evidence)


def test_snmp_public_absent_is_not_a_confirmed_violation() -> None:
    report = audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline=BASELINE)
    finding = one(report, "snmp-public")
    assert finding.status is not FindingStatus.CONFIRMED_VIOLATION
    assert finding.status is FindingStatus.INDETERMINATE


def test_ip_http_server_is_a_confirmed_violation() -> None:
    config = [
        "hostname SW-WEB",
        "enable secret 9 $9$hash",
        "ip http server",
        "line vty 0 4",
        " transport input ssh",
    ]
    report = audit(model_of(device("SW-WEB", config)), baseline=BASELINE)
    finding = one(report, "http-server")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert any("ip http server" in item for item in finding.evidence)


# ---------------------------------------------------------------------------
# absence of configuration is never compliance
# ---------------------------------------------------------------------------


def test_device_without_configuration_is_unsupported_for_every_check() -> None:
    report = audit(model_of(device("SW-EMPTY", [])), baseline=BASELINE)
    assert report.checked_devices == 1
    assert report.findings
    assert {finding.check_id for finding in report.findings} == set(CHECK_IDS[BASELINE])
    for finding in report.findings:
        assert finding.status is FindingStatus.UNSUPPORTED
        assert finding.status is not FindingStatus.COMPLIANT
        assert finding.evidence
        assert all(is_absence_note(item) for item in finding.evidence)


def test_empty_device_yields_no_violations() -> None:
    report = audit(model_of(device("SW-EMPTY", [])), baseline=BASELINE)
    assert report.violations() == ()


# ---------------------------------------------------------------------------
# structural invariants
# ---------------------------------------------------------------------------


def test_every_compliant_finding_carries_real_configuration_evidence() -> None:
    model = model_of(
        device("SW-SSH", SSH_CONFIG),
        device("SW-CLEARTEXT", ["hostname SW-CLEARTEXT", "enable password cisco123"]),
        device("SW-EMPTY", []),
    )
    report = audit(model, baseline=BASELINE)
    compliant = [f for f in report.findings if f.status is FindingStatus.COMPLIANT]
    assert compliant, "the fixture must produce at least one COMPLIANT finding"
    for finding in compliant:
        assert finding.evidence
        assert any(not is_absence_note(item) for item in finding.evidence), finding.check_id
        assert all(item.startswith("running-config line ") for item in finding.evidence)


def test_absence_is_never_a_confirmed_violation_except_missing_x_checks() -> None:
    config = [
        "hostname SW-BARE",
        "enable secret 9 $9$hash",
        "line vty 0 4",
        " transport input ssh",
    ]
    report = audit(model_of(device("SW-BARE", config)), baseline=BASELINE)
    missing_x = {"ssh-missing", "no-enable-secret"}
    for finding in report.findings:
        if finding.status is not FindingStatus.CONFIRMED_VIOLATION:
            continue
        real_lines = [item for item in finding.evidence if not is_absence_note(item)]
        assert real_lines or finding.check_id in missing_x, finding.check_id


def test_findings_are_advisory_and_carry_no_execution_field() -> None:
    names = {field.name for field in dataclasses.fields(Finding)}
    assert names == {
        "check_id",
        "device",
        "interface",
        "status",
        "severity",
        "summary",
        "evidence",
        "baseline",
        "remediation_hint",
    }
    forbidden = {"execute", "apply", "command", "commands", "push", "deploy", "applied", "dry_run"}
    assert not (names & forbidden)


def test_finding_is_frozen_and_evidence_is_a_tuple() -> None:
    report = audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline=BASELINE)
    finding = report.findings[0]
    assert isinstance(finding.evidence, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.summary = "tampered"  # type: ignore[misc]


def test_compliant_claim_without_line_evidence_raises() -> None:
    with pytest.raises(ValueError):
        Finding(
            check_id="telnet-enabled",
            device="SW-X",
            interface=None,
            status=FindingStatus.COMPLIANT,
            severity=Severity.HIGH,
            summary="claims compliance",
            evidence=("not present: 'transport input telnet'",),
            baseline=BASELINE,
            remediation_hint="",
        )


def test_finding_without_evidence_raises() -> None:
    with pytest.raises(ValueError):
        Finding(
            check_id="telnet-enabled",
            device="SW-X",
            interface=None,
            status=FindingStatus.INDETERMINATE,
            severity=Severity.HIGH,
            summary="no evidence",
            evidence=(),
            baseline=BASELINE,
            remediation_hint="",
        )


# ---------------------------------------------------------------------------
# report shape
# ---------------------------------------------------------------------------


def test_by_severity_always_reports_all_four_buckets() -> None:
    report = audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline=BASELINE)
    counts = report.by_severity()
    assert set(counts) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert sum(counts.values()) == len(report.findings)


def test_violations_returns_only_confirmed_violations() -> None:
    report = audit(
        model_of(device("SW-CLEARTEXT", ["hostname SW-CLEARTEXT", "enable password cisco123"])),
        baseline=BASELINE,
    )
    violations = report.violations()
    assert violations
    assert all(f.status is FindingStatus.CONFIRMED_VIOLATION for f in violations)
    assert {f.check_id for f in violations} >= {"password-in-config"}


def test_unknown_baseline_is_rejected() -> None:
    with pytest.raises(ValueError):
        audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline="does-not-exist")


def test_checked_devices_counts_every_device_in_the_model() -> None:
    report = audit(model_of(device("A", SSH_CONFIG), device("B", [])), baseline=BASELINE)
    assert report.checked_devices == 2
    assert report.baseline == BASELINE


# ---------------------------------------------------------------------------
# interface checks
# ---------------------------------------------------------------------------


def test_open_undescribed_access_port_is_a_hardening_suggestion() -> None:
    config = [
        "hostname SW-PORTS",
        "enable secret 9 $9$hash",
        "line vty 0 4",
        " transport input ssh",
        "!",
        "interface FastEthernet0/1",
        " switchport mode access",
        " switchport access vlan 10",
        "!",
        "interface FastEthernet0/2",
        " switchport mode access",
        " description pc-a",
        "!",
        "interface FastEthernet0/3",
        " switchport mode access",
        " shutdown",
        "!",
    ]
    dev = device("SW-PORTS", config, interfaces=["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3"])
    model = NetworkModel(devices={"SW-PORTS": dev}, snapshot_id="ports")
    model.interfaces = {
        "SW-PORTS:FastEthernet0/1": InterfaceInfo(
            device="SW-PORTS", name="FastEthernet0/1", canonical_name="FastEthernet0/1",
            access_mode="access",
        ),
    }
    report = audit(model, baseline=BASELINE)

    unused = {f.interface: f for f in findings_for(report, "unused-ports-open")}
    assert unused["FastEthernet0/1"].status is FindingStatus.HARDENING_SUGGESTION
    assert unused["FastEthernet0/1"].severity is Severity.LOW
    assert unused["FastEthernet0/2"].status is FindingStatus.COMPLIANT
    assert unused["FastEthernet0/3"].status is FindingStatus.COMPLIANT


def test_access_port_without_port_security_is_a_hardening_suggestion() -> None:
    config = [
        "hostname SW-PS",
        "enable secret 9 $9$hash",
        "line vty 0 4",
        " transport input ssh",
        "!",
        "interface FastEthernet0/1",
        " switchport mode access",
        " description pc-a",
        "!",
        "interface FastEthernet0/2",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security maximum 2",
        "!",
    ]
    report = audit(model_of(device("SW-PS", config)), baseline=BASELINE)
    ps = {f.interface: f for f in findings_for(report, "port-security-missing")}
    assert ps["FastEthernet0/1"].status is FindingStatus.HARDENING_SUGGESTION
    assert ps["FastEthernet0/2"].status is FindingStatus.COMPLIANT
    assert any("switchport port-security" in item for item in ps["FastEthernet0/2"].evidence)


def test_routed_port_is_not_treated_as_an_access_port() -> None:
    config = [
        "hostname R1",
        "enable secret 9 $9$hash",
        "line vty 0 4",
        " transport input ssh",
        "!",
        "interface GigabitEthernet0/0",
        " no switchport",
        " ip address 10.0.0.1 255.255.255.0",
        "!",
    ]
    report = audit(model_of(device("R1", config)), baseline=BASELINE)
    assert findings_for(report, "port-security-missing") == []
    assert findings_for(report, "unused-ports-open") == []


# ---------------------------------------------------------------------------
# cdp
# ---------------------------------------------------------------------------


def test_cdp_not_disabled_is_a_low_hardening_suggestion() -> None:
    report = audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline=BASELINE)
    finding = one(report, "cdp-enabled-global")
    assert finding.status is FindingStatus.HARDENING_SUGGESTION
    assert finding.severity is Severity.LOW


def test_no_cdp_run_is_compliant() -> None:
    config = [
        "hostname SW-NOCDP",
        "enable secret 9 $9$hash",
        "no cdp run",
        "line vty 0 4",
        " transport input ssh",
    ]
    report = audit(model_of(device("SW-NOCDP", config)), baseline=BASELINE)
    finding = one(report, "cdp-enabled-global")
    assert finding.status is FindingStatus.COMPLIANT
    assert any("no cdp run" in item for item in finding.evidence)


# ---------------------------------------------------------------------------
# vty ACL
# ---------------------------------------------------------------------------


def test_vty_without_access_class_is_a_hardening_suggestion() -> None:
    report = audit(model_of(device("SW-SSH", SSH_CONFIG)), baseline=BASELINE)
    finding = one(report, "vty-no-acl")
    assert finding.status is FindingStatus.HARDENING_SUGGESTION
    assert any(is_absence_note(item) for item in finding.evidence)


def test_vty_with_access_class_is_compliant() -> None:
    config = [
        "hostname SW-ACL",
        "enable secret 9 $9$hash",
        "ip ssh version 2",
        "line vty 0 4",
        " access-class 10 in",
        " transport input ssh",
    ]
    report = audit(model_of(device("SW-ACL", config)), baseline=BASELINE)
    finding = one(report, "vty-no-acl")
    assert finding.status is FindingStatus.COMPLIANT
    assert any("access-class 10 in" in item for item in finding.evidence)


def test_multiple_vty_blocks_are_each_evaluated() -> None:
    config = [
        "hostname SW-MULTI",
        "enable secret 9 $9$hash",
        "ip ssh version 2",
        "line vty 0 4",
        " transport input ssh",
        "!",
        "line vty 5 15",
        " transport input telnet",
    ]
    report = audit(model_of(device("SW-MULTI", config)), baseline=BASELINE)
    finding = one(report, "telnet-enabled")
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert any("transport input telnet" in item for item in finding.evidence)


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_audit_is_deterministic() -> None:
    model = model_of(
        device("SW-B", SSH_CONFIG),
        device("SW-A", TELNET_CONFIG),
        device("SW-C", []),
    )
    first = audit(model, baseline=BASELINE)
    second = audit(model, baseline=BASELINE)
    assert first == second
    devices = [finding.device for finding in first.findings]
    assert devices == sorted(devices)
