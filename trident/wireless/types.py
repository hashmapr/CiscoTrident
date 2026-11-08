"""Result types for the wireless, endpoint and service analysis.

Matching configuration is NOT connectivity.

These types describe what the recorded configuration *says*. They do not model a
device connection, an association, a lease, a ping, a link state, or any other
runtime fact. Nothing here can be used to assert that a client is connected, that
an SSID is reachable, or that a DHCP client obtained an address.

The rules are enforced in ``__post_init__`` so a caller cannot manufacture an
unsupported claim:

* every result carries at least one evidence string;
* ``CONFIGURED`` needs a real configuration line, not only an absence note;
* ``MISSING`` needs positive evidence of absence (an explicit ``no`` directive, or
  a device category plus a stated reason) and can never carry SSIDs;
* ``UNSUPPORTED`` needs an explicit note saying why this snapshot cannot speak;
* ``OPEN`` needs a configuration line that shows no encryption — silence is
  ``UNKNOWN``, never ``OPEN``;
* ``psk_configured`` needs a line that mentions PSK/passphrase material.

Evidence strings follow the same conventions as :mod:`trident.security`:
``running-config line N: <text>`` for a cited line, ``not present: <what>`` for a
positively absent directive inside a recorded configuration, and
``not observable: <why>`` when the snapshot cannot speak at all.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

#: Prefix for evidence recording a directive that the recorded config omits.
ABSENT_PREFIX = "not present:"

#: Prefix for evidence recording that the snapshot cannot speak at all.
UNOBSERVABLE_PREFIX = "not observable:"

#: Prefix for a cited running-configuration line.
CITATION_PREFIX = "running-config line"


def is_absence_note(evidence: str) -> bool:
    """True when an evidence entry records silence rather than a cited line."""
    text = evidence.strip().lower()
    return text.startswith((ABSENT_PREFIX, UNOBSERVABLE_PREFIX))


def _cited(evidence: tuple[str, ...]) -> bool:
    return any(
        entry.strip().startswith(CITATION_PREFIX) for entry in evidence
    )


class WirelessStatus(enum.StrEnum):
    """How far the recorded configuration goes for one device.

    ``UNSUPPORTED`` is not ``MISSING``: the first says this snapshot cannot speak
    to wireless for the device, the second says the configuration positively shows
    no wireless subsystem.
    """

    CONFIGURED = "CONFIGURED"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    INDETERMINATE = "INDETERMINATE"
    UNSUPPORTED = "UNSUPPORTED"


class SecurityMode(enum.StrEnum):
    """The security mode a configuration line selects for an SSID.

    ``UNKNOWN`` is the honest answer when the configuration is silent or uses a
    directive this module does not classify. It is never promoted to ``OPEN``.
    """

    OPEN = "OPEN"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    ENTERPRISE = "ENTERPRISE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SsidConfig:
    """One SSID definition and the security facts recorded for it."""

    ssid: str
    security_mode: SecurityMode
    psk_configured: bool
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.ssid:
            raise ValueError("an SSID record must name the SSID")
        if not self.evidence:
            raise ValueError(
                f"SSID {self.ssid!r} has no evidence; every SSID record must cite a line "
                "or state that the configuration is silent"
            )
        if self.security_mode is not SecurityMode.UNKNOWN and not _cited(self.evidence):
            raise ValueError(
                f"SSID {self.ssid!r} claims {self.security_mode.value} without a cited "
                "configuration line; absence of a directive is not evidence of a mode"
            )
        if self.psk_configured and not any(
            "psk" in entry.lower() or "passphrase" in entry.lower()
            for entry in self.evidence
            if not is_absence_note(entry)
        ):
            raise ValueError(
                f"SSID {self.ssid!r} claims a PSK without a cited PSK line"
            )


@dataclass(frozen=True)
class WirelessDevice:
    """Wireless configuration facts for one device."""

    device: str
    is_controller: bool
    ssids: tuple[SsidConfig, ...]
    radios_enabled: int
    status: WirelessStatus
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.device:
            raise ValueError("a wireless record must name its device")
        if self.radios_enabled < 0:
            raise ValueError("radios_enabled cannot be negative")
        if not self.evidence:
            raise ValueError(
                f"wireless record for {self.device!r} has no evidence"
            )
        if self.status is WirelessStatus.CONFIGURED:
            if not self.ssids:
                raise ValueError(
                    f"{self.device!r} is CONFIGURED but records no SSID"
                )
            if any(ssid.security_mode is SecurityMode.UNKNOWN for ssid in self.ssids):
                raise ValueError(
                    f"{self.device!r} is CONFIGURED but at least one SSID has an UNKNOWN "
                    "security mode; that is PARTIAL, not CONFIGURED"
                )
            if self.radios_enabled == 0 and not self.is_controller:
                raise ValueError(
                    f"{self.device!r} is CONFIGURED but has no enabled radio and is not a "
                    "controller; that is PARTIAL, not CONFIGURED"
                )
            if not _cited(self.evidence):
                raise ValueError(
                    f"{self.device!r} claims CONFIGURED without a cited configuration line"
                )
        if self.status is WirelessStatus.MISSING:
            if self.ssids:
                raise ValueError(
                    f"{self.device!r} claims MISSING while recording SSID definitions"
                )
            if self.radios_enabled:
                raise ValueError(
                    f"{self.device!r} claims MISSING while recording enabled radios"
                )
            if not any(is_absence_note(entry) for entry in self.evidence):
                raise ValueError(
                    f"{self.device!r} claims MISSING without a positive absence note; "
                    "MISSING requires evidence that the feature is absent"
                )
        if self.status is WirelessStatus.UNSUPPORTED:
            if self.ssids or self.radios_enabled:
                raise ValueError(
                    f"{self.device!r} claims UNSUPPORTED while recording wireless facts"
                )
            if not any(is_absence_note(entry) for entry in self.evidence):
                raise ValueError(
                    f"{self.device!r} claims UNSUPPORTED without stating why the snapshot "
                    "cannot speak"
                )


@dataclass(frozen=True)
class EndpointConfig:
    """Static endpoint facts: addresses and name servers as recorded.

    ``dhcp_enabled`` is ``None`` unless the configuration itself states the method.
    An observed address is not evidence that the address was static.
    """

    device: str
    kind: str
    ipv4: str | None
    mask: str | None
    gateway: str | None
    dns: tuple[str, ...]
    dhcp_enabled: bool | None
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.device:
            raise ValueError("an endpoint record must name its device")
        if self.kind not in {"pc", "server", "laptop", "printer"}:
            raise ValueError(
                f"endpoint kind {self.kind!r} is not one of pc/server/laptop/printer"
            )
        if not self.evidence:
            raise ValueError(f"endpoint record for {self.device!r} has no evidence")
        if self.dhcp_enabled is True and not any(
            "dhcp" in entry.lower() for entry in self.evidence
        ):
            raise ValueError(
                f"{self.device!r} claims DHCP without a cited DHCP line"
            )


@dataclass(frozen=True)
class ServiceConfig:
    """One network service as configured on one device.

    ``enabled`` is ``None`` when the recorded configuration does not state the
    state. ``pools`` is only populated for ``service == "dhcp"`` and holds DHCP
    *server* pools; relay configuration is reported separately by
    :func:`trident.wireless.analyse_dhcp_relays`.
    """

    device: str
    service: str
    enabled: bool | None
    pools: tuple[dict, ...]
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.device:
            raise ValueError("a service record must name its device")
        if self.service not in {"dhcp", "dns", "http", "tftp"}:
            raise ValueError(
                f"service {self.service!r} is not one of dhcp/dns/http/tftp"
            )
        if not self.evidence:
            raise ValueError(
                f"service record for {self.device!r}/{self.service} has no evidence"
            )
        if self.service != "dhcp" and self.pools:
            raise ValueError(
                f"service {self.service!r} cannot carry DHCP pools"
            )
        if self.enabled is True and not _cited(self.evidence):
            raise ValueError(
                f"{self.device!r}/{self.service} claims enabled without a cited "
                "configuration line"
            )


@dataclass(frozen=True)
class DnsResolver:
    """One device's ``ip name-server`` resolver settings.

    A resolver asks a server; it does not serve DNS. This type is deliberately
    separate from :class:`ServiceConfig` with ``service="dns"``.
    """

    device: str
    servers: tuple[str, ...]
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.device:
            raise ValueError("a DNS resolver record must name its device")
        if not self.servers:
            raise ValueError("a DNS resolver record must name at least one server")
        if not self.evidence:
            raise ValueError("a DNS resolver record must cite the name-server line")


@dataclass(frozen=True)
class DhcpRelay:
    """One ``ip helper-address`` target recorded on an interface.

    This is relay configuration. It is deliberately a separate type from a DHCP
    server pool: a relay does not prove the server is reachable, does not prove a
    client obtains a lease, and is not a pool definition.
    """

    device: str
    interface: str
    server: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.device or not self.interface or not self.server:
            raise ValueError("a DHCP relay record must name device, interface and server")
        if not self.evidence:
            raise ValueError("a DHCP relay record must cite the helper-address line")
