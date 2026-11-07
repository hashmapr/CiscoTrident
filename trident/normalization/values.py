"""Canonical value normalisation shared by every layer.

These functions are the definition of "equivalent" used by the consensus engine.
They are deliberately pure and side-effect free.
"""

from __future__ import annotations

import ipaddress
import re

# ---------------------------------------------------------------------------
# MAC addresses
# ---------------------------------------------------------------------------

_MAC_SEP_RE = re.compile(r"[^0-9A-Fa-f]")


def normalize_mac(value: str | None) -> str | None:
    """Normalise a MAC address to lowercase ``aa:bb:cc:dd:ee:ff``.

    Understands Cisco dotted (``0040.0B1E.B601``), colon, hyphen and bare forms.
    Returns None when the value is not a 48-bit MAC.
    """
    if not value:
        return None
    digits = _MAC_SEP_RE.sub("", value).lower()
    if len(digits) != 12:
        return None
    try:
        int(digits, 16)
    except ValueError:
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def macs_equal(a: str | None, b: str | None) -> bool:
    na, nb = normalize_mac(a), normalize_mac(b)
    return na is not None and na == nb


# ---------------------------------------------------------------------------
# Interface names
# ---------------------------------------------------------------------------

#: Longest prefixes first so 'GigabitEthernet' wins over 'Gi' and 'G'.
_INTERFACE_ALIASES: dict[str, str] = {
    "gigabitethernet": "GigabitEthernet",
    "fastethernet": "FastEthernet",
    "ethernet": "Ethernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "tengige": "TenGigabitEthernet",
    "ten-gigabitethernet": "TenGigabitEthernet",
    "port-channel": "Port-channel",
    "portchannel": "Port-channel",
    "port-channel-subinterface": "Port-channel",
    "serial": "Serial",
    "loopback": "Loopback",
    "vlan": "Vlan",
    "tunnel": "Tunnel",
    "management": "Management",
    "console": "Console",
    "wireless": "Wireless",
    "wlan-gigabitethernet": "Wlan-GigabitEthernet",
    "cellular": "Cellular",
    "dialer": "Dialer",
    "bvi": "BVI",
    "nvram": "nvram",
    "asyn": "Async",
    "async": "Async",
    "virtual-template": "Virtual-Template",
}

_ABBREV: dict[str, str] = {
    "gi": "GigabitEthernet",
    "ge": "GigabitEthernet",
    "g": "GigabitEthernet",
    "fa": "FastEthernet",
    "f": "FastEthernet",
    "et": "Ethernet",
    "e": "Ethernet",
    "te": "TenGigabitEthernet",
    "t": "TenGigabitEthernet",
    "se": "Serial",
    "s": "Serial",
    "lo": "Loopback",
    "vl": "Vlan",
    "vlan": "Vlan",
    "po": "Port-channel",
    "port-ch": "Port-channel",
    "mgmt": "Management",
    "nvr": "nvram",
}

_IFACE_SPLIT_RE = re.compile(r"^([A-Za-z][A-Za-z\-_ ]*?)\s*([\d/\.:]+)$")


def canonical_interface_name(name: str | None) -> str:
    """Return a canonical interface identifier.

    ``Gi0/1``, ``gi0/1``, ``GigabitEthernet0/1`` and ``GigabitEthernet 0/1``
    all canonicalise to ``GigabitEthernet0/1``. Unknown types are preserved with
    only case and whitespace normalised, which keeps comparisons safe.
    """
    if not name:
        return ""
    cleaned = name.strip().replace(" ", "")
    m = _IFACE_SPLIT_RE.match(cleaned)
    if not m:
        return cleaned

    raw_type, number = m.group(1).lower(), m.group(2)
    number = number.rstrip(".")

    if raw_type in _INTERFACE_ALIASES:
        prefix = _INTERFACE_ALIASES[raw_type]
    elif raw_type in _ABBREV:
        prefix = _ABBREV[raw_type]
    else:
        # Try prefix match against known long names (e.g. 'gigabitethernet0/1')
        prefix = None
        for long_name, canonical in sorted(
            _INTERFACE_ALIASES.items(), key=lambda kv: -len(kv[0])
        ):
            if raw_type == long_name:
                prefix = canonical
                break
        if prefix is None:
            prefix = m.group(1).strip()

    return f"{prefix}{number}"


def interfaces_equal(a: str | None, b: str | None) -> bool:
    ca, cb = canonical_interface_name(a), canonical_interface_name(b)
    return bool(ca) and ca == cb


# ---------------------------------------------------------------------------
# IP addresses and subnets
# ---------------------------------------------------------------------------

def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_ipv4(value: str | None) -> str | None:
    ip = normalize_ip(value)
    if ip is None:
        return None
    return ip if ":" not in ip else None


def prefix_to_mask(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def mask_to_prefix(mask: str | None) -> int | None:
    if not mask:
        return None
    try:
        net = ipaddress.IPv4Network(f"0.0.0.0/{mask.strip()}")
    except ValueError:
        return None
    return net.prefixlen


def is_valid_mask(mask: str | None) -> bool:
    """A contiguous IPv4 subnet mask, e.g. 255.255.255.0 (not 255.0.255.0)."""
    return mask_to_prefix(mask) is not None


def network_address(ip: str, mask_or_prefix: str | int) -> str | None:
    try:
        if isinstance(mask_or_prefix, int):
            iface = ipaddress.IPv4Interface(f"{ip}/{mask_or_prefix}")
        else:
            iface = ipaddress.IPv4Interface(f"{ip}/{mask_or_prefix}")
        return str(iface.network.network_address)
    except ValueError:
        return None


def broadcast_address(ip: str, mask_or_prefix: str | int) -> str | None:
    try:
        iface = ipaddress.IPv4Interface(f"{ip}/{mask_or_prefix}")
        return str(iface.network.broadcast_address)
    except ValueError:
        return None


def same_subnet(ip_a: str, ip_b: str, mask: str) -> bool | None:
    """True/False when determinable, None when inputs are invalid."""
    try:
        net = ipaddress.IPv4Network(f"{ip_a}/{mask}", strict=False)
        addr = ipaddress.IPv4Address(ip_b)
    except ValueError:
        return None
    if mask_to_prefix(mask) is None:
        return None
    return addr in net


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def normalize_os_version(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip()


def normalize_whitespace(value: str | None) -> str:
    return " ".join((value or "").split())


def norm_ip_network(value: str | None) -> str | None:
    """Normalise a route destination, allowing CIDR or 'net mask' forms."""
    if not value:
        return None
    value = value.strip()
    try:
        if "/" in value:
            return str(ipaddress.IPv4Network(value, strict=False))
        return str(ipaddress.IPv4Network(value, strict=False))
    except ValueError:
        return None
