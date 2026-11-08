"""Deterministic configuration compliance evaluation.

This module answers one question: *does the trusted network model satisfy this
requirement?* It is a pure function of ``NetworkModel`` — no AI, no I/O, no
dependency on ``trident.requirements`` (which may evolve independently).

Honesty rules, enforced structurally:

* a device missing from the snapshot is ``UNSUPPORTED``, never ``UNSATISFIED``
* an ambiguous device or interface is ``INDETERMINATE``, never a guess
* a recorded value that differs from the expectation is ``UNSATISFIED``
* absence that the model cannot speak to is ``INDETERMINATE``, with the missing
  evidence named in the reason
* ``SATISFIED`` is only ever returned with at least one ``Evidence`` entry

Every verdict is reproducible from the model alone and cites where each fact
came from (a numbered running-config line, or a named normalised model field).
"""

from __future__ import annotations

import ipaddress
import re

from ..models import DeviceInfo, InterfaceInfo, NetworkModel
from ..normalization.values import (
    canonical_interface_name,
    mask_to_prefix,
    normalize_ipv4,
    normalize_whitespace,
    prefix_to_mask,
)
from .types import ComplianceResult, ComplianceStatus, Evidence

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _mk(
    kind: str,
    device: str | None,
    interface: str | None,
    expected: str,
    actual: str | None,
    status: ComplianceStatus,
    evidence: list[Evidence],
    reason: str,
) -> ComplianceResult:
    return ComplianceResult(
        requirement_kind=kind,
        device=device,
        interface=interface,
        expected=expected,
        actual=actual,
        status=status,
        evidence=tuple(evidence),
        reason=reason,
    )


def _ev(device: str | None, interface: str | None, detail: str, source: str) -> Evidence:
    return Evidence(device=device, interface=interface, detail=detail, source=source)


def _finalize(result: ComplianceResult) -> ComplianceResult:
    """Structural guarantee: a SATISFIED verdict always carries evidence."""
    if result.status is ComplianceStatus.SATISFIED and not result.evidence:
        return ComplianceResult(
            requirement_kind=result.requirement_kind,
            device=result.device,
            interface=result.interface,
            expected=result.expected,
            actual=result.actual,
            status=ComplianceStatus.INDETERMINATE,
            evidence=(),
            reason=(
                "engine invariant: SATISFIED requires evidence, none was recorded; "
                "downgraded to INDETERMINATE"
            ),
        )
    return result


def _norm(value: str | None) -> str:
    return " ".join((value or "").split()).strip().lower()


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted({v for v in values if v})


# ---------------------------------------------------------------------------
# entity resolution (never guesses)
# ---------------------------------------------------------------------------


def _resolve_device(model: NetworkModel, name: str | None) -> tuple[str | None, list[str], str]:
    """Resolve a device argument to a model key.

    Returns ``(key or None, candidates, how)``. More than one candidate means the
    name is ambiguous and no key is returned.
    """
    if not name:
        return None, [], "no device named in the requirement"
    if name in model.devices:
        return name, [name], "exact key"
    target = _norm(name)
    hits = [key for key in model.devices if _norm(key) == target]
    if len(hits) == 1:
        return hits[0], hits, "key (case-insensitive)"
    if len(hits) > 1:
        return None, hits, "ambiguous device key"
    host_hits = [
        key for key, dev in model.devices.items() if dev.hostname and _norm(dev.hostname) == target
    ]
    if len(host_hits) == 1:
        return host_hits[0], host_hits, "hostname"
    if len(host_hits) > 1:
        return None, host_hits, "ambiguous hostname"
    base = target.split("_")[0]
    if base != target:
        alias_hits = [key for key in model.devices if _norm(key).split("_")[0] == base]
        if len(alias_hits) == 1:
            return alias_hits[0], alias_hits, "alias"
        if len(alias_hits) > 1:
            return None, alias_hits, "ambiguous alias"
    return None, [], "device not found"


def _interface_hits(
    model: NetworkModel, dev_key: str, iface: str
) -> list[tuple[str, InterfaceInfo]]:
    canon = canonical_interface_name(iface).lower()
    if not canon:
        return []
    hits: list[tuple[str, InterfaceInfo]] = []
    for key, info in model.interfaces.items():
        if info.device != dev_key and not key.startswith(f"{dev_key}:"):
            continue
        name = info.name or info.canonical_name or key.split(":")[-1]
        if canonical_interface_name(name).lower() == canon:
            hits.append((key, info))
    return hits


def _resolve_interface(
    model: NetworkModel, dev_key: str, iface: str | None
) -> tuple[str | None, InterfaceInfo | None, list[str], str]:
    if not iface:
        return None, None, [], "no interface named in the requirement"
    hits = _interface_hits(model, dev_key, iface)
    if len(hits) == 1:
        return hits[0][0], hits[0][1], [hits[0][0]], "canonical name"
    if len(hits) > 1:
        return None, None, [key for key, _ in hits], "ambiguous interface"
    canon = canonical_interface_name(iface)
    if canon:
        key = f"{dev_key}:{canon}"
        if key in model.interfaces:
            return key, model.interfaces[key], [key], "exact interface key"
    return None, None, [], "interface not found"


def _require_device(
    model: NetworkModel,
    kind: str,
    device: str | None,
    interface: str | None,
    expected: str,
) -> tuple[str | None, DeviceInfo | None, ComplianceResult | None]:
    dev_key, candidates, how = _resolve_device(model, device)
    if dev_key is not None:
        return dev_key, model.devices[dev_key], None
    if len(candidates) > 1:
        return None, None, _mk(
            kind, device, interface, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"device {device!r} is ambiguous ({how}: {', '.join(sorted(candidates))}); "
            "refusing to choose between them",
        )
    return None, None, _mk(
        kind, device, interface, expected, None, ComplianceStatus.UNSUPPORTED, [],
        f"device {device!r} is not present in this snapshot ({how})",
    )


def _require_interface(
    model: NetworkModel,
    kind: str,
    dev_key: str,
    device: str | None,
    interface: str | None,
    expected: str,
) -> tuple[InterfaceInfo | None, ComplianceResult | None]:
    if_key, info, candidates, how = _resolve_interface(model, dev_key, interface)
    if info is not None:
        return info, None
    if len(candidates) > 1:
        return None, _mk(
            kind, dev_key, interface, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"interface {interface!r} on {dev_key} is ambiguous ({how}: "
            f"{', '.join(sorted(candidates))}); refusing to choose between them",
        )
    if not interface:
        return None, _mk(
            kind, dev_key, interface, expected, None, ComplianceStatus.INDETERMINATE, [],
            "the requirement does not name an interface, so this kind cannot be evaluated",
        )
    return None, _mk(
        kind, dev_key, interface, expected, None, ComplianceStatus.UNSUPPORTED, [],
        f"interface {interface!r} is not present on {dev_key} in this snapshot ({how})",
    )


# ---------------------------------------------------------------------------
# running-config access (evidence, not authority)
# ---------------------------------------------------------------------------

_IFACE_HDR_RE = re.compile(r"^interface\s+(\S+)\s*$", re.IGNORECASE)


def _interface_config_lines(
    dev: DeviceInfo | None, iface_name: str
) -> list[tuple[int, str]] | None:
    """Return ``(line_number, text)`` for one interface block, or None."""
    if dev is None or not dev.configuration:
        return None
    want = canonical_interface_name(iface_name).lower()
    if not want:
        return None
    collected: list[tuple[int, str]] | None = None
    collecting = False
    for number, raw in enumerate(dev.configuration, start=1):
        text = raw.strip()
        header = _IFACE_HDR_RE.match(text)
        if header:
            collecting = canonical_interface_name(header.group(1)).lower() == want
            if collecting:
                collected = []
            continue
        if not collecting:
            continue
        if text == "!":
            collecting = False
            continue
        if text:
            collected.append((number, text))
    return collected


def _block_line(
    block: list[tuple[int, str]] | None, prefix: str
) -> tuple[int, str] | None:
    if not block:
        return None
    target = prefix.lower()
    for number, text in block:
        if text.lower().startswith(target):
            return number, text
    return None


def _config_line(dev: DeviceInfo | None, prefix: str) -> tuple[int, str] | None:
    if dev is None:
        return None
    target = prefix.lower()
    for number, raw in enumerate(dev.configuration, start=1):
        text = raw.strip()
        if text.lower().startswith(target):
            return number, text
    return None


def _source_for_line(line: tuple[int, str] | None, fallback: str) -> str:
    if line is None:
        return fallback
    return f"running-config line {line[0]}: {line[1]}"


# ---------------------------------------------------------------------------
# value parsing
# ---------------------------------------------------------------------------


def _split_ip_mask(text: str) -> tuple[str | None, int | None]:
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
        return normalize_ipv4(parts[0]), mask_to_prefix(parts[1])
    return None, None


def _prefix_from_expectation(text: str) -> int | None:
    """Parse ``/24``, ``24`` or ``255.255.255.0`` into a prefix length."""
    cleaned = normalize_whitespace(text)
    if not cleaned:
        return None
    if cleaned.startswith("/"):
        body = cleaned[1:]
        return int(body) if body.isdigit() and 0 <= int(body) <= 32 else None
    if cleaned.isdigit():
        value = int(cleaned)
        return value if 0 <= value <= 32 else None
    return mask_to_prefix(cleaned)


def _info_prefix(info: InterfaceInfo) -> int | None:
    if info.prefix_length is not None:
        return info.prefix_length
    if info.subnet_mask:
        return mask_to_prefix(info.subnet_mask)
    return None


def _info_mask(info: InterfaceInfo) -> str | None:
    if info.subnet_mask:
        return info.subnet_mask
    if info.prefix_length is not None:
        return prefix_to_mask(info.prefix_length)
    return None


_VLAN_RANGE_RE = re.compile(r"^(\d+)\s*-\s*(\d+)$")


def _vlan_set(text: str) -> set[str]:
    cleaned = re.sub(r"(?i)^vlan\s+", "", normalize_whitespace(text))
    out: set[str] = set()
    for chunk in re.split(r"[,\s]+", cleaned):
        if not chunk:
            continue
        ranged = _VLAN_RANGE_RE.match(chunk)
        if ranged:
            start, end = int(ranged.group(1)), int(ranged.group(2))
            if 0 < start <= end <= 4094 and end - start < 512:
                out.update(str(v) for v in range(start, end + 1))
            continue
        if chunk.isdigit():
            out.add(str(int(chunk)))
    return out


def _vlan_text(values: set[str]) -> str:
    return ",".join(sorted(values, key=lambda v: (len(v), v)))


_PRESENT_WORDS = {
    "enabled", "enable", "present", "yes", "true", "required", "require", "on",
    "configured", "up",
}
_ABSENT_WORDS = {
    "disabled", "disable", "absent", "no", "false", "off", "none", "removed",
    "not-configured", "down",
}
_TRUNK_WORDS = {"trunk", "trunking", "enabled", "enable", "yes", "true", "on"}
_ACCESS_WORDS = {"access", "disabled", "disable", "no", "false", "off", "not-trunk"}


def _bool_expectation(
    text: str, truthy: set[str], falsy: set[str]
) -> bool | None:
    token = _norm(text)
    if token in truthy:
        return True
    if token in falsy:
        return False
    return None


# ---------------------------------------------------------------------------
# kinds
# ---------------------------------------------------------------------------


def _eval_ipv4_address(
    model: NetworkModel, device: str | None, interface: str | None, expected: str
) -> ComplianceResult:
    kind = "ipv4_address"
    dev_key, dev, failure = _require_device(model, kind, device, interface, expected)
    if failure is not None:
        return failure
    info, failure = _require_interface(model, kind, dev_key, device, interface, expected)
    if failure is not None:
        return failure
    assert info is not None and dev_key is not None

    expected_ip, expected_prefix = _split_ip_mask(expected)
    if expected_ip is None:
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"expected value {expected!r} is neither an IPv4 address nor a CIDR address",
        )

    block = _interface_config_lines(dev, info.name)
    address_line = _block_line(block, "ip address")
    actual = info.ipv4_address
    actual_prefix = _info_prefix(info)

    if actual is None:
        negated = _block_line(block, "no ip address")
        if negated is not None:
            return _mk(
                kind, dev_key, info.name, expected, None, ComplianceStatus.UNSATISFIED,
                [_ev(dev_key, info.name, negated[1], f"running-config line {negated[0]}: {negated[1]}")],
                f"{dev_key} {info.name} explicitly has no IPv4 address",
            )
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"no IPv4 address is recorded for {dev_key} {info.name}: "
            "InterfaceInfo.ipv4_address is empty and the running-config has no "
            "'ip address' line for it",
        )

    source = _source_for_line(
        address_line, "normalized model: InterfaceInfo.ipv4_address"
    )
    evidence = [
        _ev(
            dev_key,
            info.name,
            f"{info.name} is configured with IPv4 address {actual}"
            + (f"/{actual_prefix}" if actual_prefix is not None else ""),
            source,
        )
    ]

    if normalize_ipv4(actual) != expected_ip:
        return _mk(
            kind, dev_key, info.name, expected, actual, ComplianceStatus.UNSATISFIED,
            evidence,
            f"address {actual} differs from the expected address {expected_ip}",
        )

    if expected_prefix is not None:
        if actual_prefix is None:
            return _mk(
                kind, dev_key, info.name, expected, actual,
                ComplianceStatus.PARTIALLY_SATISFIED, evidence,
                f"address matches {expected_ip} but no prefix is recorded, so the "
                f"expected /{expected_prefix} cannot be verified",
            )
        if actual_prefix != expected_prefix:
            return _mk(
                kind, dev_key, info.name, expected, actual,
                ComplianceStatus.PARTIALLY_SATISFIED, evidence,
                f"address matches {expected_ip} but the prefix is /{actual_prefix}, "
                f"not the expected /{expected_prefix}",
            )

    return _mk(
        kind, dev_key, info.name, expected, actual, ComplianceStatus.SATISFIED,
        evidence, f"{dev_key} {info.name} has the expected address {expected_ip}",
    )


def _eval_ipv4_subnet(
    model: NetworkModel, device: str | None, interface: str | None, expected: str
) -> ComplianceResult:
    kind = "ipv4_subnet"
    dev_key, dev, failure = _require_device(model, kind, device, interface, expected)
    if failure is not None:
        return failure
    info, failure = _require_interface(model, kind, dev_key, device, interface, expected)
    if failure is not None:
        return failure
    assert info is not None and dev_key is not None

    expected_prefix = _prefix_from_expectation(expected)
    if expected_prefix is None:
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"expected value {expected!r} is not a contiguous mask, a prefix length "
            "or a '/n' CIDR suffix",
        )

    block = _interface_config_lines(dev, info.name)
    address_line = _block_line(block, "ip address")
    actual_mask = _info_mask(info)
    actual_prefix = _info_prefix(info)

    if actual_prefix is None or not actual_mask:
        negated = _block_line(block, "no ip address")
        if negated is not None:
            return _mk(
                kind, dev_key, info.name, expected, None, ComplianceStatus.UNSATISFIED,
                [_ev(dev_key, info.name, negated[1], f"running-config line {negated[0]}: {negated[1]}")],
                f"{dev_key} {info.name} has no IP addressing at all, so it has no "
                f"expected /{expected_prefix} mask",
            )
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"no subnet mask is recorded for {dev_key} {info.name}: "
            "InterfaceInfo.subnet_mask and prefix_length are both empty",
        )

    source = _source_for_line(address_line, "normalized model: InterfaceInfo.subnet_mask")
    evidence = [
        _ev(
            dev_key,
            info.name,
            f"{info.name} subnet mask is {actual_mask} (/{actual_prefix})",
            source,
        )
    ]
    if actual_prefix != expected_prefix:
        return _mk(
            kind, dev_key, info.name, expected, actual_mask, ComplianceStatus.UNSATISFIED,
            evidence,
            f"mask {actual_mask} (/{actual_prefix}) differs from the expected "
            f"/{expected_prefix}",
        )
    return _mk(
        kind, dev_key, info.name, expected, actual_mask, ComplianceStatus.SATISFIED,
        evidence,
        f"{dev_key} {info.name} has the expected /{expected_prefix} mask ({actual_mask})",
    )


def _eval_hostname(
    model: NetworkModel, device: str | None, interface: str | None, expected: str
) -> ComplianceResult:
    kind = "hostname"
    dev_key, dev, failure = _require_device(model, kind, device, interface, expected)
    if failure is not None:
        return failure
    assert dev is not None and dev_key is not None

    # 1. An explicit top-level 'hostname X' line is the strongest evidence.
    config_hits: list[tuple[int, str, str]] = []
    for number, raw in enumerate(dev.configuration, start=1):
        text = raw.strip()
        if text.lower().startswith("hostname "):
            value = text.split(None, 1)[1].strip()
            if value:
                config_hits.append((number, value, text))
    distinct = _unique_sorted([value for _, value, _ in config_hits])
    if len(distinct) > 1:
        return _mk(
            kind, dev_key, None, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"conflicting 'hostname' lines in the running-config of {dev_key}: "
            f"{', '.join(distinct)}",
        )
    if distinct:
        number, value, text = config_hits[0]
        evidence = [
            _ev(dev_key, None, f"configured hostname is {value}", f"running-config line {number}: {text}")
        ]
        if _norm(value) == _norm(expected):
            return _mk(
                kind, dev_key, None, expected, value, ComplianceStatus.SATISFIED, evidence,
                f"{dev_key} has the expected hostname {value}",
            )
        return _mk(
            kind, dev_key, None, expected, value, ComplianceStatus.UNSATISFIED, evidence,
            f"configured hostname {value} differs from the expected {expected!r}",
        )

    # 2. A consensus hostname observation, when one exists.
    observed = _unique_sorted(
        [
            (ob.value or "").strip()
            for ob in model.observations
            if ob.entity_type == "device"
            and ob.entity_id == dev_key
            and ob.field == "hostname"
            and (ob.value or "").strip()
            and "[[" not in (ob.value or "")
        ]
    )
    if len(observed) > 1:
        return _mk(
            kind, dev_key, None, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"conflicting hostname observations for {dev_key}: {', '.join(observed)}",
        )
    if observed:
        value = observed[0]
        evidence = [
            _ev(
                dev_key, None, f"hostname observation is {value}",
                "normalized model: Observation(field='hostname')",
            )
        ]
        if _norm(value) == _norm(expected):
            return _mk(
                kind, dev_key, None, expected, value, ComplianceStatus.SATISFIED, evidence,
                f"{dev_key} has the expected hostname {value}",
            )
        return _mk(
            kind, dev_key, None, expected, value, ComplianceStatus.UNSATISFIED, evidence,
            f"observed hostname {value} differs from the expected {expected!r}",
        )

    # 3. DeviceInfo.hostname, but only when it is not just the display name.
    configured = (dev.hostname or "").strip()
    if configured and configured != dev.name:
        evidence = [
            _ev(
                dev_key, None, f"hostname is {configured}",
                "normalized model: DeviceInfo.hostname",
            )
        ]
        if _norm(configured) == _norm(expected):
            return _mk(
                kind, dev_key, None, expected, configured, ComplianceStatus.SATISFIED, evidence,
                f"{dev_key} has the expected hostname {configured}",
            )
        return _mk(
            kind, dev_key, None, expected, configured, ComplianceStatus.UNSATISFIED, evidence,
            f"recorded hostname {configured} differs from the expected {expected!r}",
        )

    return _mk(
        kind, dev_key, None, expected, None, ComplianceStatus.INDETERMINATE, [],
        f"no hostname is recorded for {dev_key}: the running-config has no 'hostname' "
        "line and DeviceInfo.hostname is empty or only the display name",
    )


def _is_default_destination(destination: str | None) -> bool:
    text = (destination or "").strip()
    if not text:
        return False
    if text in {"0.0.0.0", "0.0.0.0/0", "default"}:
        return True
    try:
        return ipaddress.IPv4Network(text, strict=False).prefixlen == 0
    except ValueError:
        return False


def _route_table_known(model: NetworkModel, dev_key: str, dev: DeviceInfo) -> bool:
    if any(route.device == dev_key for route in model.routes):
        return True
    for raw in dev.configuration:
        text = raw.strip().lower()
        if text.startswith(("ip route ", "ip default-gateway ")):
            return True
    return dev_key in (model.settings.default_gateways or {})


def _eval_default_route(
    model: NetworkModel, device: str | None, interface: str | None, expected: str
) -> ComplianceResult:
    kind = "default_route"
    dev_key, dev, failure = _require_device(model, kind, device, interface, expected)
    if failure is not None:
        return failure
    assert dev is not None and dev_key is not None

    routes = [
        route
        for route in model.routes
        if route.device == dev_key and _is_default_destination(route.destination)
    ]

    if not routes:
        if not _route_table_known(model, dev_key, dev):
            return _mk(
                kind, dev_key, None, expected, None, ComplianceStatus.INDETERMINATE, [],
                f"the route table of {dev_key} is not represented in this snapshot: no "
                "RouteInfo records for the device and no 'ip route' / "
                "'ip default-gateway' line in its running-config",
            )
        return _mk(
            kind, dev_key, None, expected, None, ComplianceStatus.UNSATISFIED,
            [
                _ev(
                    dev_key, None,
                    f"no default route (destination 0.0.0.0) among the route records of {dev_key}",
                    "normalized model: model.routes",
                )
            ],
            f"{dev_key} has no default route, so the requirement cannot be met",
        )

    expected_ip = normalize_ipv4(expected)
    expected_iface = canonical_interface_name(expected)
    evidence = []
    actuals: list[str] = []
    for route in routes:
        candidate = (route.next_hop or route.outgoing_interface or "").strip()
        if not candidate:
            candidate = "unknown"
        actuals.append(candidate)
        raw = (route.raw_config or "").strip()
        located = _config_line(dev, raw) if raw else None
        evidence.append(
            _ev(
                dev_key,
                route.outgoing_interface,
                f"default route {route.destination} via {candidate}"
                + (f" ({route.route_type})" if route.route_type else ""),
                _source_for_line(
                    located,
                    f"route record: destination={route.destination} next_hop={route.next_hop} "
                    f"outgoing_interface={route.outgoing_interface}",
                ),
            )
        )

    for route, candidate in zip(routes, actuals, strict=True):
        if expected_ip is not None:
            if normalize_ipv4(candidate) == expected_ip:
                return _mk(
                    kind, dev_key, route.outgoing_interface, expected, candidate,
                    ComplianceStatus.SATISFIED, evidence,
                    f"{dev_key} has a default route matching the expected next hop {expected_ip}",
                )
        elif expected_iface and candidate != "unknown":
            if canonical_interface_name(candidate).lower() == expected_iface.lower():
                return _mk(
                    kind, dev_key, route.outgoing_interface, expected, candidate,
                    ComplianceStatus.SATISFIED, evidence,
                    f"{dev_key} has a default route out of the expected interface {expected_iface}",
                )
        elif _norm(candidate) == _norm(expected):
            return _mk(
                kind, dev_key, route.outgoing_interface, expected, candidate,
                ComplianceStatus.SATISFIED, evidence,
                f"{dev_key} has a default route matching {expected!r}",
            )

    actual = ", ".join(_unique_sorted(actuals)) or None
    return _mk(
        kind, dev_key, None, expected, actual, ComplianceStatus.UNSATISFIED, evidence,
        f"{dev_key} has a default route, but not one matching {expected!r} "
        f"(recorded: {actual})",
    )


def _eval_vlan_assignment(
    model: NetworkModel, device: str | None, interface: str | None, expected: str
) -> ComplianceResult:
    kind = "vlan_assignment"
    dev_key, dev, failure = _require_device(model, kind, device, interface, expected)
    if failure is not None:
        return failure
    info, failure = _require_interface(model, kind, dev_key, device, interface, expected)
    if failure is not None:
        return failure
    assert info is not None and dev_key is not None

    wanted = _vlan_set(expected)
    if not wanted:
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"expected value {expected!r} does not name any VLAN id",
        )

    actual_set = {str(v) for v in (info.vlan_assignments or [])}
    block = _interface_config_lines(dev, info.name)
    evidence: list[Evidence] = []
    source = "normalized model: InterfaceInfo.vlan_assignments"

    if actual_set:
        evidence.append(
            _ev(
                dev_key, info.name,
                f"{info.name} VLAN assignments: {_vlan_text(actual_set)}",
                f"{source} = [{', '.join(sorted(actual_set))}]",
            )
        )
    else:
        # The normalised field is empty; a switchport line in the block is the
        # remaining authoritative place a VLAN can be recorded.
        for prefix in ("switchport access vlan ", "switchport trunk allowed vlan "):
            line = _block_line(block, prefix)
            if line is None:
                continue
            payload = line[1][len(prefix):].strip()
            if prefix.endswith("allowed vlan "):
                payload = payload.replace("add", "").replace("remove", "").strip()
            derived = _vlan_set(payload)
            if derived:
                actual_set = derived
                evidence.append(
                    _ev(
                        dev_key, info.name, f"{info.name}: {line[1]}",
                        f"running-config line {line[0]}: {line[1]}",
                    )
                )
                break

    if not actual_set:
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"no VLAN assignment is recorded for {dev_key} {info.name}: "
            "InterfaceInfo.vlan_assignments is empty and the running-config has no "
            "'switchport access vlan' or 'switchport trunk allowed vlan' line",
        )

    actual_text = _vlan_text(actual_set)
    missing = wanted - actual_set
    if not missing and wanted == actual_set:
        return _mk(
            kind, dev_key, info.name, expected, actual_text, ComplianceStatus.SATISFIED,
            evidence,
            f"{dev_key} {info.name} carries exactly the expected VLAN(s) {_vlan_text(wanted)}",
        )
    if not missing:
        extra = actual_set - wanted
        return _mk(
            kind, dev_key, info.name, expected, actual_text,
            ComplianceStatus.PARTIALLY_SATISFIED, evidence,
            f"all expected VLAN(s) {_vlan_text(wanted)} are present, but extra VLAN(s) "
            f"{_vlan_text(extra)} are also assigned",
        )
    if wanted & actual_set:
        return _mk(
            kind, dev_key, info.name, expected, actual_text,
            ComplianceStatus.PARTIALLY_SATISFIED, evidence,
            f"only some expected VLAN(s) are present: missing {_vlan_text(missing)}",
        )
    return _mk(
        kind, dev_key, info.name, expected, actual_text, ComplianceStatus.UNSATISFIED,
        evidence,
        f"{dev_key} {info.name} carries VLAN(s) {actual_text}, none of the expected "
        f"{_vlan_text(wanted)}",
    )


_SSH_LINE_RE = re.compile(
    r"^(ip ssh\b|transport input\s+(?:.*\bssh\b|all)\b)", re.IGNORECASE
)


def _eval_ssh(
    model: NetworkModel, device: str | None, interface: str | None, expected: str
) -> ComplianceResult:
    kind = "ssh"
    dev_key, dev, failure = _require_device(model, kind, device, interface, expected)
    if failure is not None:
        return failure
    assert dev is not None and dev_key is not None

    want_ssh = _bool_expectation(expected, _PRESENT_WORDS, _ABSENT_WORDS)
    if want_ssh is None:
        return _mk(
            kind, dev_key, None, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"expected value {expected!r} is neither a 'present/enabled' nor an "
            "'absent/disabled' style expectation",
        )

    if not dev.configuration:
        return _mk(
            kind, dev_key, None, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"the running-configuration of {dev_key} is not present in this snapshot, "
            "so SSH support cannot be determined",
        )

    hits: list[tuple[int, str]] = []
    for number, raw in enumerate(dev.configuration, start=1):
        text = raw.strip()
        if text and _SSH_LINE_RE.match(text):
            hits.append((number, text))

    if hits:
        evidence = [
            _ev(dev_key, None, text, f"running-config line {number}: {text}")
            for number, text in hits
        ]
        if want_ssh:
            return _mk(
                kind, dev_key, None, expected, "enabled", ComplianceStatus.SATISFIED,
                evidence,
                f"{dev_key} enables SSH via "
                + ", ".join(repr(text) for _, text in hits),
            )
        return _mk(
            kind, dev_key, None, expected, "enabled", ComplianceStatus.UNSATISFIED,
            evidence,
            f"{dev_key} has SSH enabled, but the requirement expects it to be disabled",
        )

    evidence = [
        _ev(
            dev_key, None,
            "no 'ip ssh' or 'transport input ssh' directive anywhere in the running-config",
            f"running-config: scanned {len(dev.configuration)} line(s) of {dev_key}",
        )
    ]
    if want_ssh:
        return _mk(
            kind, dev_key, None, expected, "disabled", ComplianceStatus.UNSATISFIED,
            evidence,
            f"{dev_key} has no SSH configuration ('ip ssh' or 'transport input ssh')",
        )
    return _mk(
        kind, dev_key, None, expected, "disabled", ComplianceStatus.SATISFIED, evidence,
        f"{dev_key} has no SSH configuration, matching the 'disabled' expectation",
    )


def _trunk_state(
    model: NetworkModel, dev: DeviceInfo, info: InterfaceInfo
) -> tuple[bool | None, list[Evidence]]:
    """Derive trunk state from the most authoritative available signal."""
    evidence: list[Evidence] = []

    mode = _norm(info.access_mode)
    if mode == "trunk":
        evidence.append(
            _ev(
                info.device, info.name, f"{info.name} access mode is trunk",
                "normalized model: InterfaceInfo.access_mode",
            )
        )
        return True, evidence
    if mode == "access":
        evidence.append(
            _ev(
                info.device, info.name, f"{info.name} access mode is access",
                "normalized model: InterfaceInfo.access_mode",
            )
        )
        return False, evidence
    if mode:
        evidence.append(
            _ev(
                info.device, info.name, f"{info.name} access mode is {mode!r} (negotiated)",
                "normalized model: InterfaceInfo.access_mode",
            )
        )
        return None, evidence

    block = _interface_config_lines(dev, info.name)
    mode_line = _block_line(block, "switchport mode ")
    if mode_line is not None:
        configured = _norm(mode_line[1][len("switchport mode "):])
        state = True if configured.startswith("trunk") else False if configured == "access" else None
        evidence.append(
            _ev(
                dev.id, info.name, mode_line[1],
                f"running-config line {mode_line[0]}: {mode_line[1]}",
            )
        )
        return state, evidence

    for prefix in ("switchport trunk allowed vlan ", "switchport trunk native vlan "):
        line = _block_line(block, prefix)
        if line is not None:
            evidence.append(
                _ev(
                    dev.id, info.name, line[1],
                    f"running-config line {line[0]}: {line[1]}",
                )
            )
            return True, evidence

    for vlan in model.vlans:
        if info.name in vlan.trunk_allowances:
            evidence.append(
                _ev(
                    dev.id, info.name,
                    f"VLAN {vlan.vlan_id} lists {info.name} as a trunk member",
                    "normalized model: VlanInfo.trunk_allowances",
                )
            )
            return True, evidence

    return None, evidence


def _eval_trunk(
    model: NetworkModel, device: str | None, interface: str | None, expected: str
) -> ComplianceResult:
    kind = "trunk"
    dev_key, dev, failure = _require_device(model, kind, device, interface, expected)
    if failure is not None:
        return failure
    info, failure = _require_interface(model, kind, dev_key, device, interface, expected)
    if failure is not None:
        return failure
    assert dev is not None and info is not None and dev_key is not None

    want_trunk = _bool_expectation(expected, _TRUNK_WORDS, _ACCESS_WORDS)
    if want_trunk is None:
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, [],
            f"expected value {expected!r} is neither a 'trunk' nor an 'access' expectation",
        )

    state, evidence = _trunk_state(model, dev, info)
    if state is None:
        suffix = ""
        if evidence:
            suffix = f" (only a negotiated mode was recorded: {evidence[0].detail})"
        return _mk(
            kind, dev_key, info.name, expected, None, ComplianceStatus.INDETERMINATE, evidence,
            f"trunk state of {dev_key} {info.name} is not determinable: no explicit "
            "switchport mode, trunk allowance or resolved access_mode was recorded" + suffix,
        )

    actual = "trunk" if state else "access"
    if state == want_trunk:
        return _mk(
            kind, dev_key, info.name, expected, actual, ComplianceStatus.SATISFIED,
            evidence,
            f"{dev_key} {info.name} is in {actual} mode, matching the expectation",
        )
    return _mk(
        kind, dev_key, info.name, expected, actual, ComplianceStatus.UNSATISFIED,
        evidence,
        f"{dev_key} {info.name} is in {actual} mode, not the expected "
        f"{'trunk' if want_trunk else 'access'}",
    )


_HANDLERS = {
    "ipv4_address": _eval_ipv4_address,
    "ipv4_subnet": _eval_ipv4_subnet,
    "hostname": _eval_hostname,
    "default_route": _eval_default_route,
    "vlan_assignment": _eval_vlan_assignment,
    "ssh": _eval_ssh,
    "trunk": _eval_trunk,
}

SUPPORTED_KINDS: frozenset[str] = frozenset(_HANDLERS)


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------


def evaluate(
    model: NetworkModel,
    *,
    kind: str,
    device: str | None,
    interface: str | None,
    expected: str,
) -> ComplianceResult:
    """Evaluate one requirement against the trusted network model.

    ``kind`` is an opaque string, not an import from ``trident.requirements``.
    Unknown kinds are ``UNSUPPORTED`` — the engine honestly reports that it has
    no evaluation strategy rather than inventing a verdict.
    """
    handler = _HANDLERS.get(kind)
    if handler is None:
        return _finalize(
            _mk(
                kind, device, interface, expected, None, ComplianceStatus.UNSUPPORTED, [],
                f"requirement kind {kind!r} is not supported by this engine; "
                f"supported kinds: {', '.join(sorted(SUPPORTED_KINDS))}",
            )
        )
    return _finalize(handler(model, device, interface, expected))
