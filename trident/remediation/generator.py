"""IOS remediation plan generation from a compliance verdict.

This module turns one ``ComplianceResult`` into an ordered, reviewable set of
Cisco IOS configuration commands. It is a *planner*, not an orchestrator:

* it never connects to a device, never opens a socket, never shells out
* it never emits a destructive verb (enforced by :func:`assert_safe_commands`)
* every plan it returns is ``advisory_only=True`` by construction of the type

Design rules, in order of precedence:

1. **Nothing to fix, nothing to say.** ``SATISFIED``, ``UNSUPPORTED`` and
   ``INDETERMINATE`` produce ``None``. There is no safe advice for a verdict
   that is already met, that the snapshot cannot speak to, or that is ambiguous.
2. **Exact inputs, exact plan.** A plan is ``HIGH`` confidence only when the
   previously observed value is fully known *and* the required value is
   unambiguous, so the rollback is an exact restoration.
3. **Unknown inputs are admitted.** When a previous value cannot be recovered
   from the verdict or its evidence, ``rollback_commands`` is empty and the
   confidence is ``LOW``. An empty rollback is the honest signal that the change
   is not automatically reversible.
"""

from __future__ import annotations

import ipaddress
import re

from ..compliance.types import ComplianceResult, ComplianceStatus
from ..normalization.values import (
    canonical_interface_name,
    normalize_ipv4,
    normalize_whitespace,
    prefix_to_mask,
)
from .types import Confidence, RemediationPlan, RemediationStep

# ---------------------------------------------------------------------------
# Safety: destructive verbs are refused at construction time
# ---------------------------------------------------------------------------

#: Verbs that may never appear in generated advice. ``reload``/``erase`` alone
#: would take a device out of service; ``format``/``delete`` destroy storage.
FORBIDDEN_VERBS: tuple[str, ...] = (
    "reload",
    "erase",
    "delete",
    "format",
    "wipe",
    "zeroize",
    "factory-reset",
)

_FORBIDDEN_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(verb) for verb in FORBIDDEN_VERBS) + r")\b",
    re.IGNORECASE,
)


def assert_safe_commands(commands: tuple[str, ...] | list[str]) -> None:
    """Raise ``ValueError`` if any command contains a destructive verb.

    Kept public so callers (and tests) can validate arbitrary command lists
    against the same blocklist this module self-checks on every plan.
    """
    for command in commands:
        hit = _FORBIDDEN_RE.search(command)
        if hit is not None:
            raise ValueError(
                f"refusing destructive command {command!r}: "
                f"the verb {hit.group(0)!r} is forbidden in remediation advice"
            )


# ---------------------------------------------------------------------------
# Small parsers over the verdict and its evidence
# ---------------------------------------------------------------------------

_ADDR_MASK_RE = re.compile(
    r"ip address\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
_ADDR_PREFIX_RE = re.compile(
    r"IPv4 address\s+(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})",
    re.IGNORECASE,
)
_HOSTNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,62}$")
_IFACE_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z\-]*\d")
_VLAN_ID_RE = re.compile(r"\d+")

_PRESENT_WORDS = {
    "enabled", "enable", "present", "yes", "true", "required", "require", "on",
    "configured", "up",
}
_ABSENT_WORDS = {
    "disabled", "disable", "absent", "no", "false", "off", "none", "removed",
    "not-configured", "down",
}


def _norm(value: str | None) -> str:
    return normalize_whitespace(value).strip().lower()


def _classful_mask(address: str) -> str | None:
    """IOS-style classful default mask, used only when no mask was supplied."""
    try:
        first = int(address.split(".", 1)[0])
    except (ValueError, IndexError):
        return None
    if 1 <= first <= 126:
        return "255.0.0.0"
    if 128 <= first <= 191:
        return "255.255.0.0"
    if 192 <= first <= 223:
        return "255.255.255.0"
    return None


def _split_expectation(text: str) -> tuple[str | None, int | None]:
    """Parse ``10.0.0.1``, ``10.0.0.1/24`` or ``10.0.0.1 255.255.255.0``."""
    cleaned = normalize_whitespace(text)
    if not cleaned:
        return None, None
    parts = cleaned.split()
    if len(parts) == 1 and "/" in parts[0]:
        address, _, suffix = parts[0].partition("/")
        prefix = int(suffix) if suffix.isdigit() and 0 <= int(suffix) <= 32 else None
        return normalize_ipv4(address), prefix
    if len(parts) == 1:
        return normalize_ipv4(parts[0]), None
    if len(parts) == 2:
        mask = parts[1]
        prefix = None
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
        except ValueError:
            prefix = None
        return normalize_ipv4(parts[0]), prefix
    return None, None


def _mask_from_expectation(text: str) -> tuple[str | None, int | None]:
    """Parse a mask expectation: ``255.255.255.0``, ``/24`` or ``24``."""
    cleaned = normalize_whitespace(text)
    if not cleaned:
        return None, None
    body = cleaned.removeprefix("/")
    if body.isdigit():
        prefix = int(body)
        return (prefix_to_mask(prefix), prefix) if 0 <= prefix <= 32 else (None, None)
    try:
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{cleaned}", strict=False).prefixlen
    except ValueError:
        return None, None
    return prefix_to_mask(prefix), prefix


def _observed_address_mask(result: ComplianceResult) -> tuple[str | None, str | None]:
    """Recover the previously configured ``ip address <ip> <mask>`` pair.

    The compliance engine records this in evidence: a prefix may appear in the
    detail text (``... IPv4 address 10.0.0.5/24``) and the verbatim running-config
    line appears in the source (``running-config line 4: ip address ...``).
    """
    address: str | None = None
    mask: str | None = None
    for item in result.evidence:
        for text in (item.detail, item.source):
            if not text:
                continue
            found = _ADDR_MASK_RE.search(text)
            if found and address is None:
                candidate = normalize_ipv4(found.group(1))
                if candidate is not None:
                    address = candidate
                    try:
                        mask = prefix_to_mask(
                            ipaddress.IPv4Network(
                                f"0.0.0.0/{found.group(2)}", strict=False
                            ).prefixlen
                        )
                    except ValueError:
                        mask = None
            prefixed = _ADDR_PREFIX_RE.search(text)
            if prefixed and mask is None:
                suffix = int(prefixed.group(2))
                if 0 <= suffix <= 32:
                    mask = prefix_to_mask(suffix)
    return address, mask


def _evidence_lines(result: ComplianceResult) -> tuple[str, ...]:
    lines: list[str] = []
    if result.reason:
        lines.append(f"verdict: {result.reason}")
    for item in result.evidence:
        detail = (item.detail or "").strip()
        source = (item.source or "").strip()
        if not detail and not source:
            continue
        line = detail
        if source:
            line = f"{detail} [{source}]" if detail else source
        if line not in lines:
            lines.append(line)
    return tuple(lines)


def _steps(*items: tuple[tuple[str, ...], str]) -> tuple[RemediationStep, ...]:
    return tuple(
        RemediationStep(order=index, commands=commands, rationale=rationale)
        for index, (commands, rationale) in enumerate(items, start=1)
    )


def _make_plan(
    result: ComplianceResult,
    *,
    interface: str | None,
    current_state: str,
    required_state: str,
    steps: tuple[RemediationStep, ...],
    verification_commands: tuple[str, ...],
    rollback_commands: tuple[str, ...],
    confidence: Confidence,
    notes: tuple[str, ...] = (),
) -> RemediationPlan:
    """Construct a plan, enforcing the safety and rollback invariants."""
    if rollback_commands and confidence is Confidence.LOW:
        raise ValueError(
            "invariant: a LOW confidence plan must carry no rollback commands"
        )
    if not rollback_commands and confidence is not Confidence.LOW:
        raise ValueError(
            "invariant: a plan without rollback commands must be LOW confidence"
        )
    every_command = tuple(
        command for step in steps for command in step.commands
    ) + tuple(verification_commands) + tuple(rollback_commands)
    assert_safe_commands(every_command)
    return RemediationPlan(
        device=result.device or "",
        interface=interface,
        current_state=current_state,
        required_state=required_state,
        steps=steps,
        verification_commands=verification_commands,
        rollback_commands=rollback_commands,
        confidence=confidence,
        evidence=_evidence_lines(result) + notes,
        advisory_only=True,
    )


# ---------------------------------------------------------------------------
# Per-kind planners
# ---------------------------------------------------------------------------


def _plan_ipv4_address(result: ComplianceResult) -> RemediationPlan | None:
    device = result.device
    interface = result.interface
    if not device or not interface:
        return None
    expected_ip, expected_prefix = _split_expectation(result.expected)
    if expected_ip is None:
        return None

    notes: list[str] = []
    if expected_prefix is not None:
        required_mask = prefix_to_mask(expected_prefix)
        confidence = Confidence.HIGH
    else:
        # Never guess a subnet mask. IOS has no "address only" form, and a
        # classful default is a guess that would silently configure a wrong
        # prefix. Abstain from generating a plan instead.
        notes.append(
            "no prefix or mask was stated in the requirement; a mask cannot be "
            "derived safely, so no remediation command is proposed"
        )
        return _make_plan(
            result,
            interface=interface,
            current_state=result.actual or "unknown",
            required_state=result.expected or "",
            steps=(),
            verification_commands=(),
            rollback_commands=(),
            confidence=Confidence.LOW,
            notes=tuple(notes),
        )

    observed_ip = normalize_ipv4(result.actual) if result.actual else None
    if observed_ip is None:
        observed_ip = result.actual
    evidence_ip, evidence_mask = _observed_address_mask(result)
    if observed_ip is None:
        observed_ip = evidence_ip
    observed_mask = evidence_mask

    steps = _steps(
        (
            (f"interface {interface}",),
            f"enter the configuration context of {interface} on {device}",
        ),
        (
            (f"ip address {expected_ip} {required_mask}",),
            (
                f"set the required address {expected_ip}/{expected_prefix or ''} "
                "on the interface"
            ),
        ),
    )
    # NOTE: no ``no shutdown`` here. Adding an address does not imply the
    # requirement asks for the interface to be enabled; silently bringing a port
    # up can change the network. Enabling is a separate requirement kind.
    verification = (
        f"show running-config interface {interface}",
        "show ip interface brief",
    )

    if result.actual is None:
        rollback = ("interface " + interface, "no ip address")
        return _make_plan(
            result,
            interface=interface,
            current_state="no IPv4 address recorded on the interface",
            required_state=f"ip address {expected_ip} {required_mask}",
            steps=steps,
            verification_commands=verification,
            rollback_commands=rollback,
            confidence=confidence,
            notes=tuple(notes),
        )

    if observed_ip and observed_mask:
        rollback = (
            f"interface {interface}",
            f"ip address {observed_ip} {observed_mask}",
        )
        rollback_confidence = confidence
    else:
        rollback = ()
        rollback_confidence = Confidence.LOW
        notes.append(
            "the previously configured subnet mask could not be recovered from the "
            "verdict or its evidence, so no exact automatic rollback is offered"
        )

    current = observed_ip or (result.actual or "unknown")
    if observed_mask:
        current = f"ip address {observed_ip} {observed_mask}"
    return _make_plan(
        result,
        interface=interface,
        current_state=current,
        required_state=f"ip address {expected_ip} {required_mask}",
        steps=steps,
        verification_commands=verification,
        rollback_commands=rollback,
        confidence=rollback_confidence,
        notes=tuple(notes),
    )


def _plan_ipv4_subnet(result: ComplianceResult) -> RemediationPlan | None:
    device = result.device
    interface = result.interface
    if not device or not interface:
        return None
    required_mask, required_prefix = _mask_from_expectation(result.expected)
    if required_mask is None:
        return None

    observed_mask = normalize_whitespace(result.actual) or None
    address, mined_mask = _observed_address_mask(result)
    if address is None:
        return _make_plan(
            result,
            interface=interface,
            current_state=f"subnet mask {observed_mask or 'unknown'}",
            required_state=f"subnet mask {required_mask} (/{required_prefix})",
            steps=(
                RemediationStep(
                    order=1,
                    commands=(),
                    rationale=(
                        "the interface address is not recorded in the verdict or its "
                        "evidence, and IOS has no mask-only command; re-issue "
                        f"'ip address <current-ip> {required_mask}' manually"
                    ),
                ),
            ),
            verification_commands=(
                f"show running-config interface {interface}",
            ),
            rollback_commands=(),
            confidence=Confidence.LOW,
        )

    steps = _steps(
        (
            (f"interface {interface}",),
            f"enter the configuration context of {interface} on {device}",
        ),
        (
            (f"ip address {address} {required_mask}",),
            (
                f"re-apply {address} with the required /{required_prefix} mask "
                "(IOS has no mask-only command)"
            ),
        ),
    )
    verification = (
        f"show running-config interface {interface}",
        "show ip interface brief",
    )

    restore_mask = observed_mask or mined_mask
    if restore_mask:
        rollback = (
            f"interface {interface}",
            f"ip address {address} {restore_mask}",
        )
        confidence = Confidence.HIGH
    else:
        rollback = ()
        confidence = Confidence.LOW

    return _make_plan(
        result,
        interface=interface,
        current_state=f"ip address {address} {observed_mask or 'mask unknown'}",
        required_state=f"ip address {address} {required_mask}",
        steps=steps,
        verification_commands=verification,
        rollback_commands=rollback,
        confidence=confidence,
    )


def _plan_hostname(result: ComplianceResult) -> RemediationPlan | None:
    device = result.device
    required = normalize_whitespace(result.expected)
    if not device or not _HOSTNAME_RE.match(required):
        return None

    observed = normalize_whitespace(result.actual) if result.actual else None
    steps = _steps(
        (
            (f"hostname {required}",),
            f"set the device hostname to {required}",
        ),
    )
    verification = ("show running-config | include ^hostname",)

    if observed and _HOSTNAME_RE.match(observed):
        rollback = (f"hostname {observed}",)
        confidence = Confidence.HIGH
    else:
        rollback = ()
        confidence = Confidence.LOW

    return _make_plan(
        result,
        interface=None,
        current_state=f"hostname {observed}" if observed else "hostname unknown",
        required_state=f"hostname {required}",
        steps=steps,
        verification_commands=verification,
        rollback_commands=rollback,
        confidence=confidence,
    )


def _route_target(value: str) -> str | None:
    """Accept an IPv4 next hop or an interface name as a static-route target."""
    cleaned = normalize_whitespace(value)
    if not cleaned:
        return None
    address = normalize_ipv4(cleaned)
    if address is not None:
        return address
    if _IFACE_TOKEN_RE.match(cleaned):
        return canonical_interface_name(cleaned)
    return None


def _plan_default_route(result: ComplianceResult) -> RemediationPlan | None:
    device = result.device
    target = _route_target(result.expected)
    if not device or target is None:
        return None

    required_command = f"ip route 0.0.0.0 0.0.0.0 {target}"
    steps = _steps(
        (
            (required_command,),
            f"install a static default route via {target}",
        ),
    )
    verification = (
        "show ip route 0.0.0.0",
        "show running-config | include ^ip route",
    )

    observed_raw = normalize_whitespace(result.actual) if result.actual else None
    observed = _route_target(observed_raw) if observed_raw else None

    if result.actual is None:
        rollback = (f"no {required_command}",)
        confidence = Confidence.HIGH
        current = "no default route present"
    elif observed and "," not in (observed_raw or ""):
        rollback = (
            f"no {required_command}",
            f"ip route 0.0.0.0 0.0.0.0 {observed}",
        )
        confidence = Confidence.HIGH
        current = f"ip route 0.0.0.0 0.0.0.0 {observed}"
    else:
        rollback = ()
        confidence = Confidence.LOW
        current = observed_raw or "default route state unknown"

    return _make_plan(
        result,
        interface=None,
        current_state=current,
        required_state=required_command,
        steps=steps,
        verification_commands=verification,
        rollback_commands=rollback,
        confidence=confidence,
    )


def _plan_vlan_assignment(result: ComplianceResult) -> RemediationPlan | None:
    device = result.device
    interface = result.interface
    if not device or not interface:
        return None

    wanted = _VLAN_ID_RE.findall(normalize_whitespace(result.expected))
    if len(wanted) != 1:
        return None
    vlan = wanted[0]
    if not 1 <= int(vlan) <= 4094:
        return None

    steps = _steps(
        (
            (f"interface {interface}",),
            f"enter the configuration context of {interface} on {device}",
        ),
        (
            ("switchport mode access",),
            "pin the port to access mode before assigning an access VLAN",
        ),
        (
            (f"switchport access vlan {vlan}",),
            f"assign the interface to VLAN {vlan}",
        ),
    )
    verification = (
        "show interfaces switchport",
        "show vlan brief",
    )
    observed = normalize_whitespace(result.actual) if result.actual else None

    return _make_plan(
        result,
        interface=interface,
        current_state=(
            f"VLAN assignment {observed}" if observed else "VLAN assignment unknown"
        ),
        required_state=f"access VLAN {vlan}",
        steps=steps,
        verification_commands=verification,
        rollback_commands=(),
        confidence=Confidence.LOW,
        notes=(
            (
                "the previously configured switchport mode (access or trunk) is not "
                "recorded in the verdict, so the mode change cannot be reversed "
                "automatically"
            ),
        ),
    )


def _plan_ssh(result: ComplianceResult) -> RemediationPlan | None:
    device = result.device
    wanted = _norm(result.expected)
    if not device:
        return None
    if wanted in _ABSENT_WORDS or wanted not in _PRESENT_WORDS:
        # Only "SSH should be enabled" has a safe, additive repair here.
        return None

    domain = "trident.local"
    steps = _steps(
        (
            (f"ip domain-name {domain}",),
            (
                "SSH key generation requires a domain name; replace trident.local "
                "with the organization's domain"
            ),
        ),
        (
            ("crypto key generate rsa modulus 2048",),
            "generate the RSA key pair SSH depends on",
        ),
        (
            ("ip ssh version 2",),
            "restrict SSH to protocol version 2",
        ),
        (
            ("line vty 0 4", "transport input ssh"),
            "allow SSH (and only SSH) on the vty lines",
        ),
    )
    verification = (
        "show ip ssh",
        "show running-config | include ^line vty|transport input",
    )

    return _make_plan(
        result,
        interface=None,
        current_state=f"SSH {(_norm(result.actual) or 'unknown')}",
        required_state="SSH enabled (version 2) on the vty lines",
        steps=steps,
        verification_commands=verification,
        rollback_commands=(),
        confidence=Confidence.LOW,
        notes=(
            (
                "the prior 'ip domain-name' and 'transport input' values are not "
                "recorded, and removing SSH would require key destruction, so no "
                "automatic rollback is offered"
            ),
        ),
    )


_PLANNERS = {
    "ipv4_address": _plan_ipv4_address,
    "ipv4_subnet": _plan_ipv4_subnet,
    "hostname": _plan_hostname,
    "default_route": _plan_default_route,
    "vlan_assignment": _plan_vlan_assignment,
    "ssh": _plan_ssh,
}

#: Requirement kinds this module can produce a plan for.
REMEDIABLE_KINDS: frozenset[str] = frozenset(_PLANNERS)

#: Statuses that already mean "no safe advice".
_TERMINAL_STATUSES = frozenset(
    {
        ComplianceStatus.SATISFIED,
        ComplianceStatus.UNSUPPORTED,
        ComplianceStatus.INDETERMINATE,
    }
)


def generate_plan(result: ComplianceResult) -> RemediationPlan | None:
    """Build an advisory remediation plan for one compliance verdict.

    Returns ``None`` when there is nothing safe to suggest: the verdict is
    already met, the snapshot cannot speak to it, it is ambiguous, the
    requirement kind has no IOS repair strategy, or the requirement text cannot
    be turned into a valid IOS command.
    """
    if result.status in _TERMINAL_STATUSES:
        return None
    planner = _PLANNERS.get(result.requirement_kind)
    if planner is None:
        return None
    if not result.device:
        return None
    return planner(result)
