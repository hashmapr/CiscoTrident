"""Deterministic configuration security audit for TRIDENT.

Reads the recorded running-configuration text of each device in a
``NetworkModel`` and emits evidence-based findings. Nothing here executes
anything: the auditor is a pure function of the model, every finding cites a
config line (or an explicit absence note), and the only action it offers is
advisory text.

Honesty rules, enforced here and structurally in :mod:`trident.security.types`:

* a device with no recorded configuration is ``UNSUPPORTED`` for every check,
  never ``COMPLIANT``;
* ``COMPLIANT`` requires a real configuration line as evidence;
* an explicitly bad directive is a ``CONFIRMED_VIOLATION``; the absence of a
  good practice is a ``HARDENING_SUGGESTION``, except for checks whose whole
  definition is "missing X" (``ssh-missing``, ``no-enable-secret``);
* a presence check whose bad line is absent *and* which has no counter-directive
  to cite is ``INDETERMINATE``, because the recorded text does not state the
  good state either.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import DeviceInfo, NetworkModel
from .types import AuditReport, Finding, FindingStatus, Severity

# ---------------------------------------------------------------------------
# running-config parsing
# ---------------------------------------------------------------------------

_INTERFACE_HEADER = re.compile(r"^interface\s+(\S+)$", re.IGNORECASE)
_VTY_HEADER = re.compile(r"^line\s+vty\s+(.+)$", re.IGNORECASE)

#: Text substituted for credential material so a report never echoes a secret.
REDACTED = "<redacted>"


@dataclass
class _BlockBuilder:
    kind: str
    name: str
    header: tuple[int, str]
    lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass(frozen=True)
class _Block:
    """One indented configuration block (``interface`` or ``line vty``)."""

    kind: str
    name: str
    header: tuple[int, str]
    lines: tuple[tuple[int, str], ...]


@dataclass(frozen=True)
class _ParsedConfig:
    top_level: tuple[tuple[int, str], ...]
    blocks: tuple[_Block, ...]

    def of_kind(self, kind: str) -> tuple[_Block, ...]:
        return tuple(block for block in self.blocks if block.kind == kind)


def _header(text: str) -> tuple[str, str] | None:
    match = _INTERFACE_HEADER.match(text)
    if match:
        return "interface", match.group(1)
    match = _VTY_HEADER.match(text)
    if match:
        return "vty", match.group(1)
    return None


def _parse(configuration: list[str]) -> _ParsedConfig:
    """Split a running-configuration into top-level lines and indented blocks.

    A line is part of a block only while it is indented; ``!`` and any
    non-indented directive end the current block. This tolerates configs that
    omit the ``!`` separators between blocks.
    """
    top_level: list[tuple[int, str]] = []
    builders: list[_BlockBuilder] = []
    current: _BlockBuilder | None = None

    for number, raw in enumerate(configuration, start=1):
        text = raw.strip()
        if not text:
            continue
        if text == "!":
            current = None
            continue
        if raw[:1].isspace():
            if current is not None:
                current.lines.append((number, text))
            else:
                top_level.append((number, text))
            continue
        header = _header(text)
        if header is not None:
            kind, name = header
            current = _BlockBuilder(kind=kind, name=name, header=(number, text))
            builders.append(current)
            continue
        current = None
        top_level.append((number, text))

    blocks = tuple(
        _Block(kind=b.kind, name=b.name, header=b.header, lines=tuple(b.lines))
        for b in builders
    )
    return _ParsedConfig(top_level=tuple(top_level), blocks=blocks)


# ---------------------------------------------------------------------------
# evidence helpers
# ---------------------------------------------------------------------------


def _cited(line: tuple[int, str]) -> str:
    return f"running-config line {line[0]}: {line[1]}"


def _absent(what: str) -> str:
    return f"not present: {what}"


def _global_prefix(parsed: _ParsedConfig, prefix: str) -> tuple[int, str] | None:
    target = prefix.lower()
    for number, text in parsed.top_level:
        if text.lower().startswith(target):
            return number, text
    return None


def _global_exact(parsed: _ParsedConfig, wanted: str) -> tuple[int, str] | None:
    target = wanted.lower()
    for number, text in parsed.top_level:
        if text.lower() == target:
            return number, text
    return None


def _block_prefix(block: _Block, prefix: str) -> tuple[int, str] | None:
    target = prefix.lower()
    for number, text in block.lines:
        if text.lower().startswith(target):
            return number, text
    return None


def _block_exact(block: _Block, wanted: str) -> tuple[int, str] | None:
    target = wanted.lower()
    for number, text in block.lines:
        if text.lower() == target:
            return number, text
    return None


def _header_cited(block: _Block) -> str:
    return _cited(block.header)


def _redacted(line: tuple[int, str], keyword: str) -> str:
    return f"running-config line {line[0]}: {keyword} {REDACTED}"


# ---------------------------------------------------------------------------
# finding construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Ctx:
    device: str
    baseline: str


def _finding(
    ctx: _Ctx,
    check_id: str,
    status: FindingStatus,
    severity: Severity,
    summary: str,
    evidence: list[str],
    *,
    interface: str | None = None,
    hint: str = "",
) -> Finding:
    return Finding(
        check_id=check_id,
        device=ctx.device,
        interface=interface,
        status=status,
        severity=severity,
        summary=summary,
        evidence=tuple(evidence),
        baseline=ctx.baseline,
        remediation_hint=hint,
    )


# ---------------------------------------------------------------------------
# checks — one finding per device unless the check is per-interface
# ---------------------------------------------------------------------------


def _check_telnet(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    vty = parsed.of_kind("vty")
    if not vty:
        return (_finding(
            ctx, "telnet-enabled", FindingStatus.UNSUPPORTED, Severity.HIGH,
            "no 'line vty' block is recorded, so the vty transport policy cannot be observed",
            [_absent("'line vty' block in the recorded configuration")],
        ),)

    bad: list[str] = []
    good: list[str] = []
    for block in vty:
        transport = _block_prefix(block, "transport input")
        if transport is None:
            bad.append(_header_cited(block))
            bad.append(_absent(
                f"'transport input' under '{block.header[1]}' (the IOS default permits Telnet)"
            ))
            continue
        protocols = [token.lower() for token in transport[1].split()[2:]]
        if "telnet" in protocols or "all" in protocols:
            bad.append(_cited(transport))
        else:
            good.append(_cited(transport))

    if bad:
        return (_finding(
            ctx, "telnet-enabled", FindingStatus.CONFIRMED_VIOLATION, Severity.HIGH,
            "Telnet (cleartext) remote administration is permitted on a vty line",
            bad,
            hint="Enter 'line vty 0 4' and set 'transport input ssh'.",
        ),)
    return (_finding(
        ctx, "telnet-enabled", FindingStatus.COMPLIANT, Severity.HIGH,
        "every recorded vty block restricts inbound transport away from Telnet",
        good,
    ),)


def _check_ssh_missing(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    vty = parsed.of_kind("vty")
    if not vty:
        return (_finding(
            ctx, "ssh-missing", FindingStatus.UNSUPPORTED, Severity.MEDIUM,
            "no 'line vty' block is recorded, so SSH support is not applicable",
            [_absent("'line vty' block in the recorded configuration")],
        ),)

    version = _global_exact(parsed, "ip ssh version 2")
    if version is not None:
        return (_finding(
            ctx, "ssh-missing", FindingStatus.COMPLIANT, Severity.MEDIUM,
            "SSH version 2 is explicitly configured",
            [_cited(version)],
        ),)

    negated = _global_exact(parsed, "no ip ssh version 2")
    if negated is not None:
        return (_finding(
            ctx, "ssh-missing", FindingStatus.CONFIRMED_VIOLATION, Severity.MEDIUM,
            "SSH version 2 is explicitly disabled",
            [_cited(negated)],
            hint="Enable 'ip ssh version 2' before relying on SSH.",
        ),)

    return (_finding(
        ctx, "ssh-missing", FindingStatus.CONFIRMED_VIOLATION, Severity.MEDIUM,
        "no 'ip ssh version 2' directive is recorded on a device with vty lines",
        [
            _header_cited(vty[0]),
            _absent("'ip ssh version 2' in the recorded configuration"),
        ],
        hint="Configure 'ip ssh version 2' and confirm the device has an RSA key pair.",
    ),)


def _check_enable_secret(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    secret = _global_prefix(parsed, "enable secret")
    negated = _global_exact(parsed, "no enable secret")
    password = _global_prefix(parsed, "enable password")

    if password is not None:
        return (_finding(
            ctx, "no-enable-secret", FindingStatus.HARDENING_SUGGESTION, Severity.HIGH,
            "a cleartext 'enable password' is configured alongside or instead of a hashed secret",
            [
                _redacted(password, "enable password"),
                _absent("'enable secret' in the recorded configuration")
                if secret is None else _redacted(secret, "enable secret"),
            ],
            hint="Configure 'service password-encryption' and replace the cleartext value "
                 "with 'enable secret'.",
        ),)

    if secret is not None and negated is None:
        return (_finding(
            ctx, "no-enable-secret", FindingStatus.COMPLIANT, Severity.HIGH,
            "a hashed 'enable secret' is configured",
            [_redacted(secret, "enable secret")],
        ),)

    if negated is not None:
        return (_finding(
            ctx, "no-enable-secret", FindingStatus.CONFIRMED_VIOLATION, Severity.HIGH,
            "privileged EXEC protection via 'enable secret' is explicitly disabled",
            [_cited(negated)],
            hint="Re-enable 'enable secret' with a type 9 (scrypt) or type 5 (MD5) hash.",
        ),)

    return (_finding(
        ctx, "no-enable-secret", FindingStatus.CONFIRMED_VIOLATION, Severity.HIGH,
        "neither 'enable secret' nor 'enable password' is recorded",
        [
            _absent("'enable secret' in the recorded configuration"),
            _absent("'enable password' in the recorded configuration"),
        ],
        hint="Configure 'enable secret' with a type 9 (scrypt) or type 5 (MD5) hash.",
    ),)


def _check_enable_password(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    password = _global_prefix(parsed, "enable password")
    if password is not None:
        return (_finding(
            ctx, "password-in-config", FindingStatus.CONFIRMED_VIOLATION, Severity.CRITICAL,
            "a cleartext 'enable password' is present in the recorded configuration",
            [_redacted(password, "enable password")],
            hint="Replace 'enable password' with 'enable secret'; the cleartext value should "
                 "be treated as disclosed and rotated.",
        ),)

    secret = _global_prefix(parsed, "enable secret")
    if secret is not None:
        return (_finding(
            ctx, "password-in-config", FindingStatus.COMPLIANT, Severity.CRITICAL,
            "no cleartext 'enable password' is recorded; a hashed 'enable secret' is used instead",
            [_redacted(secret, "enable secret")],
        ),)

    return (_finding(
        ctx, "password-in-config", FindingStatus.INDETERMINATE, Severity.CRITICAL,
        "no 'enable password' line is recorded, and no 'enable secret' line states the "
        "alternative; see the 'no-enable-secret' finding",
        [_absent("'enable password' and 'enable secret' in the recorded configuration")],
    ),)


def _check_vty_acl(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    vty = parsed.of_kind("vty")
    if not vty:
        return (_finding(
            ctx, "vty-no-acl", FindingStatus.UNSUPPORTED, Severity.MEDIUM,
            "no 'line vty' block is recorded, so a vty access-class cannot be checked",
            [_absent("'line vty' block in the recorded configuration")],
        ),)

    missing: list[str] = []
    present: list[str] = []
    for block in vty:
        acl = _block_prefix(block, "access-class")
        if acl is not None:
            present.append(_cited(acl))
            continue
        missing.append(_header_cited(block))
        missing.append(_absent(f"'access-class' under '{block.header[1]}'"))

    if missing:
        return (_finding(
            ctx, "vty-no-acl", FindingStatus.HARDENING_SUGGESTION, Severity.MEDIUM,
            "at least one vty block has no 'access-class' limiting management sources",
            missing,
            hint="Apply a management access list, e.g. 'line vty 0 4' then "
                 "'access-class 10 in'.",
        ),)
    return (_finding(
        ctx, "vty-no-acl", FindingStatus.COMPLIANT, Severity.MEDIUM,
        "every recorded vty block applies an inbound 'access-class'",
        present,
    ),)


def _switchport_mode(block: _Block) -> str | None:
    line = _block_prefix(block, "switchport mode")
    if line is None:
        return None
    tokens = line[1].split()
    return tokens[2].lower() if len(tokens) > 2 else ""


def _is_access_port(block: _Block) -> bool:
    """True only for a port explicitly configured ``switchport mode access``."""
    if _block_exact(block, "no switchport") is not None:
        return False
    return _switchport_mode(block) == "access"


def _check_unused_ports(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for block in parsed.of_kind("interface"):
        if not _is_access_port(block):
            continue
        description = _block_prefix(block, "description")
        shutdown = _block_exact(block, "shutdown")
        evidence = [_header_cited(block)]

        if description is None and shutdown is None:
            evidence.append(_absent(f"'description' on {block.name}"))
            evidence.append(_absent(f"'shutdown' on {block.name}"))
            findings.append(_finding(
                ctx, "unused-ports-open", FindingStatus.HARDENING_SUGGESTION, Severity.LOW,
                f"access port {block.name} is enabled and undocumented, so it may be unused "
                "while still carrying traffic",
                evidence,
                interface=block.name,
                hint="Confirm the port is in use; if not, apply 'shutdown', otherwise add a "
                     "'description'.",
            ))
            continue

        if description is not None:
            evidence.append(_cited(description))
        if shutdown is not None:
            evidence.append(_cited(shutdown))
        findings.append(_finding(
            ctx, "unused-ports-open", FindingStatus.COMPLIANT, Severity.LOW,
            f"access port {block.name} is either documented or administratively shut down",
            evidence,
            interface=block.name,
        ))
    return tuple(findings)


def _check_port_security(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for block in parsed.of_kind("interface"):
        if not _is_access_port(block):
            continue
        policy = _block_prefix(block, "switchport port-security")
        if policy is not None:
            findings.append(_finding(
                ctx, "port-security-missing", FindingStatus.COMPLIANT, Severity.LOW,
                f"access port {block.name} enables port security",
                [_header_cited(block), _cited(policy)],
                interface=block.name,
            ))
            continue
        negated = _block_exact(block, "no switchport port-security")
        if negated is not None:
            findings.append(_finding(
                ctx, "port-security-missing", FindingStatus.HARDENING_SUGGESTION, Severity.LOW,
                f"access port {block.name} explicitly disables port security",
                [_header_cited(block), _cited(negated)],
                interface=block.name,
                hint="Enable port security with a maximum MAC count, e.g. "
                     "'switchport port-security maximum 2' and "
                     "'switchport port-security violation restrict'.",
            ))
            continue
        findings.append(_finding(
            ctx, "port-security-missing", FindingStatus.HARDENING_SUGGESTION, Severity.LOW,
            f"access port {block.name} has no 'switchport port-security' configuration",
            [
                _header_cited(block),
                _absent(f"'switchport port-security' under {block.name}"),
            ],
            interface=block.name,
            hint="Enable port security with a maximum MAC count, e.g. "
                 "'switchport port-security maximum 2' and 'switchport port-security violation restrict'.",
        ))
    return tuple(findings)


def _check_cdp(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    disabled = _global_exact(parsed, "no cdp run")
    if disabled is not None:
        return (_finding(
            ctx, "cdp-enabled-global", FindingStatus.COMPLIANT, Severity.LOW,
            "CDP is globally disabled",
            [_cited(disabled)],
        ),)

    enabled = _global_exact(parsed, "cdp run")
    if enabled is not None:
        return (_finding(
            ctx, "cdp-enabled-global", FindingStatus.HARDENING_SUGGESTION, Severity.LOW,
            "CDP is explicitly enabled globally",
            [_cited(enabled)],
            hint="If CDP is not required, disable it with 'no cdp run'.",
        ),)

    return (_finding(
        ctx, "cdp-enabled-global", FindingStatus.HARDENING_SUGGESTION, Severity.LOW,
        "CDP is not disabled in the recorded configuration (IOS enables it by default)",
        [_absent("'no cdp run' in the recorded configuration")],
        hint="If CDP is not required, disable it with 'no cdp run'.",
    ),)


def _check_http(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    enabled = _global_exact(parsed, "ip http server")
    if enabled is not None:
        return (_finding(
            ctx, "http-server", FindingStatus.CONFIRMED_VIOLATION, Severity.HIGH,
            "the cleartext HTTP management server is enabled",
            [_cited(enabled)],
            hint="Disable it with 'no ip http server'; use 'ip http secure-server' if a web UI "
                 "is required.",
        ),)

    disabled = _global_exact(parsed, "no ip http server")
    if disabled is not None:
        return (_finding(
            ctx, "http-server", FindingStatus.COMPLIANT, Severity.HIGH,
            "the HTTP management server is explicitly disabled",
            [_cited(disabled)],
        ),)

    return (_finding(
        ctx, "http-server", FindingStatus.INDETERMINATE, Severity.HIGH,
        "the recorded configuration neither enables nor explicitly disables 'ip http server'; "
        "the effective default is platform-dependent",
        [_absent("'ip http server' and 'no ip http server' in the recorded configuration")],
    ),)


def _check_snmp(ctx: _Ctx, parsed: _ParsedConfig) -> tuple[Finding, ...]:
    weak: list[str] = []
    for number, text in parsed.top_level:
        tokens = text.split()
        if len(tokens) >= 3 and [t.lower() for t in tokens[:3]] == [
            "snmp-server", "community", "public",
        ]:
            weak.append(_cited((number, text)))

    if weak:
        return (_finding(
            ctx, "snmp-public", FindingStatus.CONFIRMED_VIOLATION, Severity.CRITICAL,
            "an SNMP community using the well-known string 'public' is configured",
            weak,
            hint="Remove the community with 'no snmp-server community public' and use SNMPv3 "
                 "with per-user authentication and privacy.",
        ),)

    disabled = _global_exact(parsed, "no snmp-server community public")
    if disabled is not None:
        return (_finding(
            ctx, "snmp-public", FindingStatus.COMPLIANT, Severity.CRITICAL,
            "the 'public' SNMP community is explicitly removed",
            [_cited(disabled)],
        ),)

    return (_finding(
        ctx, "snmp-public", FindingStatus.INDETERMINATE, Severity.CRITICAL,
        "no 'snmp-server community public' line is recorded; this check covers only that "
        "literal community string, so other weak strings are not ruled out",
        [_absent("'snmp-server community public' in the recorded configuration")],
    ),)


# ---------------------------------------------------------------------------
# baseline registry and public entry point
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Check:
    check_id: str
    severity: Severity
    run: Callable[[_Ctx, _ParsedConfig], tuple[Finding, ...]]


_CISCO_BASIC: tuple[_Check, ...] = (
    _Check("telnet-enabled", Severity.HIGH, _check_telnet),
    _Check("ssh-missing", Severity.MEDIUM, _check_ssh_missing),
    _Check("no-enable-secret", Severity.HIGH, _check_enable_secret),
    _Check("password-in-config", Severity.CRITICAL, _check_enable_password),
    _Check("vty-no-acl", Severity.MEDIUM, _check_vty_acl),
    _Check("unused-ports-open", Severity.LOW, _check_unused_ports),
    _Check("port-security-missing", Severity.LOW, _check_port_security),
    _Check("cdp-enabled-global", Severity.LOW, _check_cdp),
    _Check("http-server", Severity.HIGH, _check_http),
    _Check("snmp-public", Severity.CRITICAL, _check_snmp),
)

#: Named baselines a caller may select. Adding a baseline is additive.
BASELINES: dict[str, tuple[_Check, ...]] = {
    "cisco-basic": _CISCO_BASIC,
}

CHECK_IDS: dict[str, tuple[str, ...]] = {
    name: tuple(check.check_id for check in checks) for name, checks in BASELINES.items()
}


def _unsupported(ctx: _Ctx, check: _Check) -> Finding:
    return _finding(
        ctx, check.check_id, FindingStatus.UNSUPPORTED, check.severity,
        f"{check.check_id} cannot be evaluated: this snapshot records no configuration for "
        f"{ctx.device}",
        [_absent(f"running-configuration for {ctx.device} (0 lines recorded)")],
    )


def audit(model: NetworkModel, *, baseline: str = "cisco-basic") -> AuditReport:
    """Audit every device in ``model`` against one named baseline.

    Returns findings in a deterministic order: devices sorted by key, checks in
    baseline order, interface findings sorted by interface name. A device whose
    recorded configuration is empty yields one ``UNSUPPORTED`` finding per check
    — never ``COMPLIANT``.
    """
    checks = BASELINES.get(baseline)
    if checks is None:
        raise ValueError(
            f"unknown baseline {baseline!r}; available baselines: {', '.join(sorted(BASELINES))}"
        )

    findings: list[Finding] = []
    for device_key in sorted(model.devices):
        device: DeviceInfo = model.devices[device_key]
        ctx = _Ctx(device=device_key, baseline=baseline)
        parsed = _parse(device.configuration)
        for check in checks:
            if not device.configuration:
                findings.append(_unsupported(ctx, check))
                continue
            findings.extend(check.run(ctx, parsed))

    return AuditReport(
        findings=tuple(findings),
        checked_devices=len(model.devices),
        baseline=baseline,
    )
