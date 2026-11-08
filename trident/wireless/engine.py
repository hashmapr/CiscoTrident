"""Wireless, endpoint and service configuration analysis for TRIDENT.

Matching configuration is NOT connectivity.

This module is a pure function of ``NetworkModel``. It reads the recorded
running-configuration lines of each device and reports what those lines *say*.
It deliberately offers no function that returns "connected", "reachable",
"online", "associated" or "lease acquired": those are runtime facts that a
configuration snapshot cannot establish. A configured SSID proves an SSID
definition exists, not that a client associated with it. An ``ip helper-address``
proves a relay target is configured, not that the server answers. An address on
an endpoint proves the address is recorded, not that the host is up.

Honesty rules enforced here and structurally in :mod:`trident.wireless.types`:

* a device with no recorded configuration lines is ``UNSUPPORTED`` for wireless,
  never ``CONFIGURED`` and never ``MISSING``;
* ``MISSING`` needs positive evidence of absence: the device category makes the
  feature inapplicable (with that reason stated in the evidence) or an explicit
  negative directive is present;
* ``CONFIGURED`` needs a cited configuration line, a classified security mode for
  every recorded SSID, and an enabled radio or a controller role — otherwise the
  device is ``PARTIAL``;
* an SSID block with no encryption/key-management directive is ``UNKNOWN``, never
  ``OPEN``. ``OPEN`` requires an explicit open/no-encryption line to cite;
* PSK material is redacted before it is written into evidence;
* a DHCP *relay* (``ip helper-address``) is reported by
  :func:`analyse_dhcp_relays`, never as a DHCP *server* pool; and
* a DNS *resolver* setting (``ip name-server``) is reported by
  :func:`analyse_dns_resolvers`, never as the DNS *server* service
  (``ip dns server``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import DeviceInfo, NetworkModel
from .types import (
    ABSENT_PREFIX,
    UNOBSERVABLE_PREFIX,
    DhcpRelay,
    DnsResolver,
    EndpointConfig,
    SecurityMode,
    ServiceConfig,
    SsidConfig,
    WirelessDevice,
    WirelessStatus,
)

__all__ = [
    "analyse_dhcp_relays",
    "analyse_dns_resolvers",
    "analyse_endpoints",
    "analyse_services",
    "analyse_wireless",
]

# ---------------------------------------------------------------------------
# configuration line scanning
# ---------------------------------------------------------------------------

_INTERFACE_HEADER = re.compile(r"^interface\s+(?P<name>\S+)\s*$", re.IGNORECASE)
_DOT11_SSID_HEADER = re.compile(r"^dot11\s+ssid\s+(?P<name>.+?)\s*$", re.IGNORECASE)
_WLAN_HEADER = re.compile(
    r"^wlan\s+(?P<profile>\S+)\s+(?P<wlan_id>\d+)(?:\s+(?P<ssid>.+?))?\s*$", re.IGNORECASE
)
_SSID_HEADER = re.compile(r"^ssid\s+(?P<name>.+?)\s*$", re.IGNORECASE)
_DHCP_POOL_HEADER = re.compile(r"^ip\s+dhcp\s+pool\s+(?P<name>.+?)\s*$", re.IGNORECASE)
_RADIO_NAME = re.compile(r"^Dot11Radio\d", re.IGNORECASE)
_IP_ADDRESS = re.compile(
    r"^ip\s+address\s+(?P<addr>\d+\.\d+\.\d+\.\d+)(?:\s+(?P<mask>\d+\.\d+\.\d+\.\d+))?\s*$",
    re.IGNORECASE,
)

#: Headers that open a block this module inspects, in match order. The value is
#: the regex group that names the block: an SSID profile uses its broadcast SSID
#: when one is given, otherwise the profile name.
_HEADERS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("interface", _INTERFACE_HEADER, "name"),
    ("dot11-ssid", _DOT11_SSID_HEADER, "name"),
    ("wlan", _WLAN_HEADER, "ssid"),
    ("ssid", _SSID_HEADER, "name"),
    ("dhcp-pool", _DHCP_POOL_HEADER, "name"),
)

#: Lines that mention wireless at all. Used only to decide whether a recorded,
#: non-empty configuration speaks about wireless *at all*.
_WIRELESS_MARKERS = re.compile(
    r"^(?:dot11\b|wlan\s|ssid\s|wireless\b|radio\b|interface\s+Dot11Radio)",
    re.IGNORECASE,
)

#: Device categories for which a wireless subsystem is inapplicable by category.
_NON_WIRELESS_CATEGORIES = {
    "router",
    "switch",
    "multilayer switch",
    "hub",
    "firewall",
    "server",
    "pc",
    "laptop",
    "printer",
    "workstation",
}

#: Device categories that are wireless access infrastructure.
_AP_CATEGORIES = {"access point", "ap", "wireless access point", "lwapp", "autonomous ap"}
_WLC_CATEGORIES = {"wlc", "wireless lan controller", "controller", "wireless controller"}

#: Endpoint kind by device category, most specific first. Matched on word
#: boundaries so 'pc' never fires inside an unrelated word.
_ENDPOINT_KINDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("printer",), "printer"),
    (("laptop",), "laptop"),
    (("server",), "server"),
    (("pc", "workstation", "host", "computer", "desktop", "end device", "endpoint"), "pc"),
)

#: Key material that must never be echoed into a report.
_PSK_MARKERS = ("wpa-psk", "wpa-presharedkey", "psk", "passphrase", "set-key")


@dataclass
class _BlockBuilder:
    kind: str
    name: str
    number: int
    header: str
    lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass(frozen=True)
class _Block:
    """One indented configuration block (interface, SSID, WLAN, DHCP pool)."""

    kind: str
    name: str
    number: int
    header: str
    lines: tuple[tuple[int, str], ...]


def _blocks(configuration: list[str]) -> tuple[_Block, ...]:
    """Split a running-configuration into the indented blocks we care about.

    A block runs from a recognised header while following lines are indented.
    ``!`` and any non-indented directive end it, which tolerates configs that omit
    the ``!`` separators.
    """
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
            continue
        current = None
        for kind, pattern, name_group in _HEADERS:
            match = pattern.match(text)
            if match is None:
                continue
            name = match.group(name_group)
            if not name:
                # An AireOS-style 'wlan <profile> <id>' with no trailing SSID
                # names the block by its profile.
                name = match.groupdict().get("profile") or ""
            if not name:
                break
            current = _BlockBuilder(kind=kind, name=name, number=number, header=text)
            builders.append(current)
            break

    return tuple(
        _Block(
            kind=builder.kind,
            name=builder.name,
            number=builder.number,
            header=builder.header,
            lines=tuple(builder.lines),
        )
        for builder in builders
    )


def _cited(number: int, text: str) -> str:
    return f"running-config line {number}: {text}"


def _absent(what: str) -> str:
    return f"{ABSENT_PREFIX} {what}"


def _unobservable(why: str) -> str:
    return f"{UNOBSERVABLE_PREFIX} {why}"


def _prefix(lines: tuple[tuple[int, str], ...], prefix: str) -> tuple[int, str] | None:
    target = prefix.lower()
    for number, text in lines:
        if text.lower().startswith(target):
            return number, text
    return None


def _redact(text: str) -> str:
    """Replace PSK/passphrase material, keeping the directive readable."""
    lowered = text.lower()
    if not any(marker in lowered for marker in _PSK_MARKERS):
        return text
    for keyword in ("ascii", "hex", "set-key", "passphrase", "unencrypted"):
        index = lowered.find(keyword)
        if index != -1:
            return f"{text[:index].rstrip()} <redacted>"
    return "<redacted psk directive>"


def _category(device: DeviceInfo) -> str:
    return (device.device_type or "").strip().lower()


def _category_matches(category: str, words: tuple[str, ...]) -> bool:
    for word in words:
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", category):
            return True
    return False


# ---------------------------------------------------------------------------
# wireless
# ---------------------------------------------------------------------------

_ENTERPRISE_MARKERS = ("802.1x", "dot1x", "network-eap", "eap", "enterprise")
_WPA3_MARKERS = ("sae", "wpa3", "version 3")
_WPA2_MARKERS = ("wpa2", "version 2", "aes", "ccmp", "gcmp")
_WPA_MARKERS = ("tkip", "version 1", "wpa")
_WEP_MARKERS = ("wep", "authentication shared", "encryption key")
_OPEN_MARKERS = ("authentication open", "security open", "no security wpa", "no encryption")


def _classify_security(block: _Block) -> tuple[SecurityMode, bool, list[str]]:
    """Classify one SSID block's security, citing the deciding line(s).

    Silence yields ``UNKNOWN`` with an explicit absence note. Silence is never
    promoted to ``OPEN``: only an explicit open/no-encryption directive is.
    """
    evidence: list[str] = [_cited(block.number, block.header)]

    psk_hit = None
    for number, text in block.lines:
        if any(marker in text.lower() for marker in ("wpa-psk", "psk", "passphrase", "set-key")):
            psk_hit = (number, text)
            break
    psk = psk_hit is not None
    if psk_hit is not None:
        evidence.append(f"running-config line {psk_hit[0]}: {_redact(psk_hit[1])}")

    for mode, markers in (
        (SecurityMode.WPA3, _WPA3_MARKERS),
        (SecurityMode.ENTERPRISE, _ENTERPRISE_MARKERS),
        (SecurityMode.WPA2, _WPA2_MARKERS),
        (SecurityMode.WPA, _WPA_MARKERS),
        (SecurityMode.WEP, _WEP_MARKERS),
        (SecurityMode.OPEN, _OPEN_MARKERS),
    ):
        hit = None
        for number, text in block.lines:
            lowered = text.lower()
            # A negated directive ('no security wpa') is not a positive signal for
            # any mode except OPEN, where it is exactly the explicit statement we
            # require before reporting OPEN.
            if lowered.startswith("no ") and mode is not SecurityMode.OPEN:
                continue
            if any(marker in lowered for marker in markers):
                hit = (number, text)
                break
        if hit is None:
            continue
        lowered = hit[1].lower()
        # A bare 'wpa'/'eap' marker must not fire on a stronger mode's line.
        if mode is SecurityMode.WPA and ("wpa2" in lowered or "wpa3" in lowered):
            continue
        if mode is SecurityMode.ENTERPRISE and "wpa" in lowered and "802.1x" not in lowered:
            continue
        cite = f"running-config line {hit[0]}: {_redact(hit[1])}"
        if cite not in evidence:
            evidence.append(cite)
        return mode, psk, evidence

    evidence.append(
        _absent(
            f"any encryption or key-management directive inside '{block.header}', so the "
            "security mode is not stated by this snapshot"
        )
    )
    return SecurityMode.UNKNOWN, psk, evidence


def _wireless_device(device_key: str, device: DeviceInfo) -> WirelessDevice:
    configuration = [line for line in device.configuration if line.strip()]
    if not configuration:
        return WirelessDevice(
            device=device_key,
            is_controller=False,
            ssids=(),
            radios_enabled=0,
            status=WirelessStatus.UNSUPPORTED,
            evidence=(
                _unobservable(
                    f"{device_key} records 0 running-configuration lines, so wireless "
                    "configuration cannot be examined"
                ),
            ),
        )

    category = _category(device)
    blocks = _blocks(configuration)
    ssid_blocks = tuple(block for block in blocks if block.kind in {"dot11-ssid", "wlan", "ssid"})
    radio_blocks = tuple(
        block for block in blocks if block.kind == "interface" and _RADIO_NAME.match(block.name)
    )
    enabled_radios = sum(1 for block in radio_blocks if _prefix(block.lines, "shutdown") is None)

    evidence: list[str] = []
    for block in radio_blocks:
        evidence.append(_cited(block.number, block.header))
        shutdown = _prefix(block.lines, "shutdown")
        if shutdown is not None:
            evidence.append(_cited(shutdown[0], shutdown[1]))

    wlan_block = next((block for block in ssid_blocks if block.kind == "wlan"), None)
    if wlan_block is not None:
        evidence.append(_cited(wlan_block.number, wlan_block.header))
    is_controller = category in _WLC_CATEGORIES or wlan_block is not None

    ssids: list[SsidConfig] = []
    for block in ssid_blocks:
        mode, psk, ssid_evidence = _classify_security(block)
        ssids.append(
            SsidConfig(
                ssid=block.name,
                security_mode=mode,
                psk_configured=psk,
                evidence=tuple(ssid_evidence),
            )
        )

    if ssids:
        evidence.extend(ssid.evidence[0] for ssid in ssids)
        fully_classified = all(ssid.security_mode is not SecurityMode.UNKNOWN for ssid in ssids)
        backed_by_radio = enabled_radios > 0 or is_controller
        status = (
            WirelessStatus.CONFIGURED
            if fully_classified and backed_by_radio
            else WirelessStatus.PARTIAL
        )
        if not backed_by_radio:
            evidence.append(
                _absent(
                    "an enabled Dot11Radio interface or a controller role; the SSID "
                    "definitions are not backed by an active radio in this snapshot"
                )
            )
        unknown = [ssid.ssid for ssid in ssids if ssid.security_mode is SecurityMode.UNKNOWN]
        if unknown:
            evidence.append(
                _absent(
                    f"a security directive for SSID(s) {', '.join(unknown)}, so their mode is "
                    "UNKNOWN and the wireless configuration is incomplete"
                )
            )
        return WirelessDevice(
            device=device_key,
            is_controller=is_controller,
            ssids=tuple(ssids),
            radios_enabled=enabled_radios,
            status=status,
            evidence=tuple(dict.fromkeys(evidence)),
        )

    if radio_blocks:
        evidence.append(
            _absent(
                "any 'dot11 ssid', 'wlan' or 'ssid' definition while radio interfaces are "
                "recorded, so no SSID is configured"
            )
        )
        return WirelessDevice(
            device=device_key,
            is_controller=is_controller,
            ssids=(),
            radios_enabled=enabled_radios,
            status=WirelessStatus.PARTIAL,
            evidence=tuple(dict.fromkeys(evidence)),
        )

    if any(_WIRELESS_MARKERS.match(line.strip()) for line in configuration):
        evidence.append(
            _absent(
                "a complete SSID or radio definition; wireless directives are present but do "
                "not form a configured subsystem in this snapshot"
            )
        )
        return WirelessDevice(
            device=device_key,
            is_controller=is_controller,
            ssids=(),
            radios_enabled=0,
            status=WirelessStatus.INDETERMINATE,
            evidence=tuple(dict.fromkeys(evidence)),
        )

    if category in _AP_CATEGORIES:
        return WirelessDevice(
            device=device_key,
            is_controller=False,
            ssids=(),
            radios_enabled=0,
            status=WirelessStatus.MISSING,
            evidence=(
                _absent(
                    "any 'dot11 ssid', 'wlan', 'ssid' or Dot11Radio directive across "
                    f"{len(configuration)} recorded configuration lines, while the device "
                    f"category is {device.device_type!r}"
                ),
            ),
        )

    if category in _NON_WIRELESS_CATEGORIES:
        return WirelessDevice(
            device=device_key,
            is_controller=False,
            ssids=(),
            radios_enabled=0,
            status=WirelessStatus.MISSING,
            evidence=(
                _absent(
                    "any wireless directive; the device category "
                    f"{device.device_type!r} has no wireless subsystem, and "
                    f"{len(configuration)} configuration lines were examined"
                ),
            ),
        )

    return WirelessDevice(
        device=device_key,
        is_controller=is_controller,
        ssids=(),
        radios_enabled=0,
        status=WirelessStatus.INDETERMINATE,
        evidence=(
            _absent(
                "any wireless directive, and the device category is not recorded, so "
                "inapplicability cannot be positively stated"
            ),
        ),
    )


def analyse_wireless(model: NetworkModel) -> tuple[WirelessDevice, ...]:
    """Report wireless *configuration* facts for every device in ``model``.

    Order is deterministic: devices sorted by key. No result asserts that an SSID
    is reachable, that a client is associated, or that a radio is transmitting.
    """
    return tuple(_wireless_device(key, model.devices[key]) for key in sorted(model.devices))


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

_ENDPOINT_OBSERVATION_FIELDS = {
    "endhost_ip": "ipv4",
    "endhost_gateway": "gateway",
    "endhost_dns": "dns",
}


def _endpoint_kind(device: DeviceInfo) -> str | None:
    category = _category(device)
    if not category:
        return None
    for words, kind in _ENDPOINT_KINDS:
        if _category_matches(category, words):
            return kind
    return None


def _endpoint_observations(model: NetworkModel, device_key: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"ipv4": [], "gateway": [], "dns": []}
    for observation in model.observations:
        if observation.entity_type != "device" or observation.entity_id != device_key:
            continue
        slot = _ENDPOINT_OBSERVATION_FIELDS.get(observation.field)
        if slot is None:
            continue
        for value in observation.value.split(","):
            value = value.strip()
            if value and value not in found[slot]:
                found[slot].append(value)
    return found


def _endpoint(device_key: str, device: DeviceInfo, model: NetworkModel) -> EndpointConfig | None:
    kind = _endpoint_kind(device)
    if kind is None:
        return None

    evidence: list[str] = []
    ipv4: str | None = None
    mask: str | None = None
    gateway: str | None = None
    dns: list[str] = []
    dhcp: bool | None = None

    for number, raw in enumerate(device.configuration, start=1):
        text = raw.strip()
        if not text:
            continue
        lowered = text.lower()

        if lowered in {"ip address dhcp", "ip address dhcp client"}:
            dhcp = True
            evidence.append(_cited(number, text))
            continue
        if lowered.startswith("ip dhcp client"):
            dhcp = True
            evidence.append(_cited(number, text))
            continue

        match = _IP_ADDRESS.match(text)
        if match is not None:
            ipv4 = match.group("addr")
            mask = match.group("mask")
            evidence.append(_cited(number, text))
            if dhcp is None:
                dhcp = False
            continue

        if lowered.startswith("ip default-gateway "):
            gateway = text.split(None, 2)[2].strip()
            evidence.append(_cited(number, text))
            continue

        if lowered.startswith("ip name-server "):
            for value in text.split()[2:]:
                if value not in dns:
                    dns.append(value)
            evidence.append(_cited(number, text))

    observed = _endpoint_observations(model, device_key)
    if ipv4 is None and observed["ipv4"]:
        ipv4 = observed["ipv4"][0]
        evidence.append(f"observation field endhost_ip: {ipv4}")
    if ipv4 is not None and mask is None and "/" in ipv4:
        address, _, prefix = ipv4.partition("/")
        ipv4 = address
        mask = f"prefix/{prefix}" if prefix else None
    if gateway is None and observed["gateway"]:
        gateway = observed["gateway"][0]
        evidence.append(f"observation field endhost_gateway: {gateway}")
    if not dns and observed["dns"]:
        dns = list(observed["dns"])
        evidence.append(f"observation field endhost_dns: {', '.join(dns)}")

    if not evidence:
        return None

    return EndpointConfig(
        device=device_key,
        kind=kind,
        ipv4=ipv4,
        mask=mask,
        gateway=gateway,
        dns=tuple(dns),
        dhcp_enabled=dhcp,
        evidence=tuple(evidence),
    )


def analyse_endpoints(model: NetworkModel) -> tuple[EndpointConfig, ...]:
    """Report static endpoint facts for devices whose category is an end host.

    Only devices with a recognised category (pc, laptop, server, printer) and at
    least one recorded address or name-server fact are returned. Nothing here
    states that an endpoint is powered on, attached, or able to reach anything.
    """
    results: list[EndpointConfig] = []
    for key in sorted(model.devices):
        endpoint = _endpoint(key, model.devices[key], model)
        if endpoint is not None:
            results.append(endpoint)
    return tuple(results)


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------

_SERVICE_ORDER = ("dhcp", "dns", "http", "tftp")


def _dhcp_record(
    device_key: str, blocks: tuple[_Block, ...], configuration: list[str]
) -> ServiceConfig | None:
    pools: list[dict] = []
    evidence: list[str] = []
    enabled: bool | None = None

    for block in blocks:
        if block.kind != "dhcp-pool":
            continue
        pool: dict = {"name": block.name}
        evidence.append(_cited(block.number, block.header))
        for number, text in block.lines:
            evidence.append(_cited(number, text))
            lowered = text.lower()
            if lowered.startswith("network "):
                tokens = text.split()
                if len(tokens) >= 3:
                    pool["network"] = tokens[1]
                    pool["mask"] = tokens[2]
            elif lowered.startswith("default-router "):
                pool["default_router"] = text.split(None, 1)[1].strip()
            elif lowered.startswith("dns-server "):
                pool["dns_server"] = text.split()[1:]
            elif lowered.startswith("lease "):
                pool["lease"] = text.split(None, 1)[1].strip()
            elif lowered.startswith("domain-name "):
                pool["domain_name"] = text.split(None, 1)[1].strip()
        pools.append(pool)

    for number, raw in enumerate(configuration, start=1):
        lowered = raw.strip().lower()
        if lowered == "service dhcp":
            enabled = True
            evidence.append(_cited(number, raw.strip()))
        elif lowered == "no service dhcp":
            enabled = False
            evidence.append(_cited(number, raw.strip()))

    if not pools and enabled is None:
        return None
    return ServiceConfig(
        device=device_key,
        service="dhcp",
        enabled=enabled,
        pools=tuple(pools),
        evidence=tuple(dict.fromkeys(evidence)),
    )


def _dns_record(device_key: str, configuration: list[str]) -> ServiceConfig | None:
    enabled: bool | None = None
    evidence: list[str] = []
    for number, raw in enumerate(configuration, start=1):
        text = raw.strip()
        lowered = text.lower()
        if lowered == "ip dns server":
            enabled = True
            evidence.append(_cited(number, text))
        elif lowered == "no ip dns server":
            enabled = False
            evidence.append(_cited(number, text))
    if not evidence:
        return None
    return ServiceConfig(
        device=device_key,
        service="dns",
        enabled=enabled,
        pools=(),
        evidence=tuple(dict.fromkeys(evidence)),
    )


def _http_record(device_key: str, configuration: list[str]) -> ServiceConfig | None:
    enabled: bool | None = None
    evidence: list[str] = []
    for number, raw in enumerate(configuration, start=1):
        text = raw.strip()
        lowered = text.lower()
        if lowered == "ip http server":
            enabled = True
            evidence.append(_cited(number, text))
        elif lowered == "no ip http server":
            enabled = False
            evidence.append(_cited(number, text))
        elif lowered in {"ip http secure-server", "no ip http secure-server"}:
            # HTTPS is a distinct server; it is cited but does not state the
            # plain HTTP service's state.
            evidence.append(_cited(number, text))
    if not evidence:
        return None
    return ServiceConfig(
        device=device_key,
        service="http",
        enabled=enabled,
        pools=(),
        evidence=tuple(dict.fromkeys(evidence)),
    )


def _tftp_record(device_key: str, configuration: list[str]) -> ServiceConfig | None:
    evidence: list[str] = []
    for number, raw in enumerate(configuration, start=1):
        text = raw.strip()
        if text.lower().startswith("tftp-server "):
            evidence.append(_cited(number, text))
    if not evidence:
        return None
    return ServiceConfig(
        device=device_key,
        service="tftp",
        enabled=True,
        pools=(),
        evidence=tuple(evidence),
    )


def analyse_services(model: NetworkModel) -> tuple[ServiceConfig, ...]:
    """Report DHCP/DNS/HTTP/TFTP service *configuration* per device.

    A record is emitted only when at least one relevant line is recorded, so
    silence is never reported as an enabled or disabled service. ``ip
    helper-address`` is not a DHCP pool and is never folded into the DHCP record;
    see :func:`analyse_dhcp_relays`. ``ip name-server`` is a resolver setting and
    is reported by :func:`analyse_dns_resolvers`, not here.
    """
    records: list[ServiceConfig] = []
    for key in sorted(model.devices):
        configuration = [line for line in model.devices[key].configuration if line.strip()]
        if not configuration:
            continue
        blocks = _blocks(configuration)
        candidates = (
            _dhcp_record(key, blocks, configuration),
            _dns_record(key, configuration),
            _http_record(key, configuration),
            _tftp_record(key, configuration),
        )
        per_device = [record for record in candidates if record is not None]
        per_device.sort(key=lambda record: _SERVICE_ORDER.index(record.service))
        records.extend(per_device)
    return tuple(records)


# ---------------------------------------------------------------------------
# DHCP relay and DNS resolver — deliberately separate from server config
# ---------------------------------------------------------------------------


def analyse_dhcp_relays(model: NetworkModel) -> tuple[DhcpRelay, ...]:
    """Report ``ip helper-address`` targets, which are relay configuration.

    A relay record is never a DHCP server pool: it shows that broadcast traffic is
    forwarded toward an address, not that a server exists or answers there.
    """
    relays: list[DhcpRelay] = []
    for key in sorted(model.devices):
        for block in _blocks(model.devices[key].configuration):
            if block.kind != "interface":
                continue
            for number, text in block.lines:
                if not text.lower().startswith("ip helper-address "):
                    continue
                tokens = text.split()
                relays.append(
                    DhcpRelay(
                        device=key,
                        interface=block.name,
                        server=tokens[2] if len(tokens) >= 3 else "",
                        evidence=(
                            _cited(block.number, block.header),
                            _cited(number, text),
                        ),
                    )
                )
    return tuple(relays)


def analyse_dns_resolvers(model: NetworkModel) -> tuple[DnsResolver, ...]:
    """Report ``ip name-server`` resolver settings, distinct from a DNS server.

    ``ip name-server`` tells a device which server to *ask*. It is not evidence
    that the device serves DNS; that is ``ip dns server`` and is reported by
    :func:`analyse_services`.
    """
    resolvers: list[DnsResolver] = []
    for key in sorted(model.devices):
        servers: list[str] = []
        evidence: list[str] = []
        for number, raw in enumerate(model.devices[key].configuration, start=1):
            text = raw.strip()
            if not text.lower().startswith("ip name-server "):
                continue
            evidence.append(_cited(number, text))
            for value in text.split()[2:]:
                if value not in servers:
                    servers.append(value)
        if servers:
            resolvers.append(
                DnsResolver(device=key, servers=tuple(servers), evidence=tuple(evidence))
            )
    return tuple(resolvers)
