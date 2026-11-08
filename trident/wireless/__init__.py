"""Wireless and endpoint configuration analysis for TRIDENT.

Matching configuration is NOT connectivity.

This package reads recorded running-configuration text from a ``NetworkModel``
and reports what that text says about wireless SSIDs, endpoint addressing, and
network services. It is a pure function of the snapshot.

There is intentionally no function that reports a device as connected, reachable,
associated, online, or as having obtained a lease. Those are runtime facts that a
configuration export cannot establish. The public surface returns configuration
facts and their evidence only.
"""

from .engine import (
    analyse_dhcp_relays,
    analyse_dns_resolvers,
    analyse_endpoints,
    analyse_services,
    analyse_wireless,
)
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
    is_absence_note,
)

__all__ = [
    "ABSENT_PREFIX",
    "UNOBSERVABLE_PREFIX",
    "DhcpRelay",
    "DnsResolver",
    "EndpointConfig",
    "SecurityMode",
    "ServiceConfig",
    "SsidConfig",
    "WirelessDevice",
    "WirelessStatus",
    "analyse_dhcp_relays",
    "analyse_dns_resolvers",
    "analyse_endpoints",
    "analyse_services",
    "analyse_wireless",
    "is_absence_note",
]
