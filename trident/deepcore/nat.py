"""NAT and PAT translation reasoning.

Given a configured translation policy and a packet, work out what the packet looks
like after translation — deterministically, with no simulator involved.

The distinction that keeps this honest:

* **Configured translation** is what the rules say would happen to a matching
  packet. That is what this module computes.
* **Active translation** is what the device has actually translated, which only a
  ``show ip nat translations`` capture can establish.

A prediction here is the first kind. It is never presented as evidence that a flow
was translated, and dynamic PAT port assignments are never guessed: the port a
given flow receives depends on runtime allocation order, so that value is reported
as unknown rather than invented.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field

from .protocols import NatConfig


class Outcome(enum.StrEnum):
    """What the rules say about one packet."""

    #: A rule matches and the packet is translated.
    TRANSLATED = "TRANSLATED"
    #: The rules leave the packet alone.
    UNTRANSLATED = "UNTRANSLATED"
    #: A required role is missing, so NAT would not happen at all.
    MISSING_ROLE = "MISSING_ROLE"
    #: The configuration is contradictory and cannot be evaluated.
    MISCONFIGURED = "MISCONFIGURED"
    #: The evidence needed to decide is absent.
    UNDECIDED = "UNDECIDED"


@dataclass
class Translation:
    """One predicted translation."""

    outcome: Outcome
    direction: str  # inbound | outbound
    original_source: str
    original_destination: str
    translated_source: str | None = None
    translated_destination: str | None = None
    rule: str = ""
    #: True when the source port was rewritten (PAT).
    overloaded: bool = False
    #: Why the translated port cannot be predicted, when it cannot.
    port_note: str = ""
    problems: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    @property
    def source_changed(self) -> bool:
        return (
            self.translated_source is not None
            and self.translated_source != self.original_source
        )

    def as_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "direction": self.direction,
            "original_source": self.original_source,
            "original_destination": self.original_destination,
            "translated_source": self.translated_source,
            "translated_destination": self.translated_destination,
            "rule": self.rule,
            "overloaded": self.overloaded,
            "port_note": self.port_note,
            "problems": list(self.problems),
            "caveats": list(self.caveats),
            "source_changed": self.source_changed,
        }


def _in_network(address: str, network: str) -> bool:
    try:
        return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(
            network, strict=False
        )
    except ValueError:
        return False


def _acl_matches(acl_line: str, address: str) -> bool:
    """Whether one ACL body line matches ``address`` as a source.

    Only the common ``permit|deny <proto> <source> ...`` shape is evaluated. A
    line this cannot parse matches nothing, and that is reported by the caller as
    a caveat rather than treated as a match.
    """
    tokens = acl_line.split()
    if len(tokens) < 2:
        return False
    if tokens[0].lower() not in {"permit", "deny"}:
        return False
    # Skip ``permit`` and the protocol.
    rest = tokens[2:]
    if not rest:
        return False

    source = rest[0]
    if source.lower() == "any":
        return True
    if source.lower() == "host":
        return len(rest) > 1 and rest[1] == address

    # A wildcard form is ``<network> <wildcard>``; the wildcard alone (e.g.
    # ``0.0.0.255``) is not an address, so it must be consumed with the network.
    if len(rest) > 1 and _looks_like_wildcard(rest[1]):
        try:
            wildcard = ipaddress.IPv4Address(rest[1])
        except ValueError:
            return False
        # Invert the wildcard into a mask and test membership.
        mask_int = int(wildcard) ^ 0xFFFFFFFF
        try:
            network = ipaddress.IPv4Network(
                f"{source}/{ipaddress.IPv4Address(mask_int)}", strict=False
            )
            return ipaddress.IPv4Address(address) in network
        except ValueError:
            return False

    return _in_network(address, source)


def _is_address(value: str | None) -> bool:
    """True when ``value`` parses as an IPv4 address rather than a name."""
    if not value:
        return False
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _looks_like_wildcard(token: str) -> bool:
    """True for a wildcard mask such as ``0.0.0.255``."""
    try:
        ipaddress.IPv4Address(token)
    except ValueError:
        return False
    # A dotted quad in the source-wildcard position is a wildcard in IOS ACLs.
    return True


def translate_outbound(
    nat: NatConfig,
    source: str,
    destination: str,
    acl_bodies: dict[str, list[str]] | None = None,
    *,
    egress_interface: str | None = None,
) -> Translation:
    """Predict what the rules do to a packet leaving the inside network.

    ``acl_bodies`` maps an ACL id to its lines, so a dynamic rule that selects
    traffic by ACL can be evaluated. Without it, a dynamic rule that needs the ACL
    is reported ``UNDECIDED`` rather than assumed to match.
    """
    base = Translation(
        outcome=Outcome.UNTRANSLATED,
        direction="outbound",
        original_source=source,
        original_destination=destination,
        translated_source=source,
        translated_destination=destination,
    )

    if not nat.configured:
        base.caveats.append("no NAT is configured on this device")
        return base

    if not nat.inside_interfaces:
        base.outcome = Outcome.MISSING_ROLE
        base.problems.append(
            "NAT has rules but no inside interface, so nothing is translated"
        )
        return base
    if not nat.outside_interfaces:
        base.outcome = Outcome.MISSING_ROLE
        base.problems.append(
            "NAT has rules but no outside interface, so nothing is translated"
        )
        return base

    for rule in nat.static_rules:
        if rule.inside == source:
            base.outcome = Outcome.TRANSLATED
            base.translated_source = rule.outside
            base.rule = rule.raw or "static"
            return base

    for rule in nat.dynamic_rules:
        if rule.acl_id is None:
            continue
        bodies = (acl_bodies or {}).get(rule.acl_id.lower())
        if bodies is None:
            base.outcome = Outcome.UNDECIDED
            base.problems.append(
                f"rule selects traffic by ACL {rule.acl_id}, whose body was not provided"
            )
            return base
        if not any(_acl_matches(line, source) for line in bodies):
            continue

        base.rule = rule.raw or "dynamic"
        if rule.overload or rule.pool_name is None:
            # PAT: the source becomes the outside interface address. That address
            # has to come from configuration — the interface *name* is not an
            # address, and returning it would be a meaningless translation.
            target = egress_interface or rule.outside
            if target is None or not _is_address(target):
                base.outcome = Outcome.UNDECIDED
                base.problems.append(
                    
                        f"PAT translates to the address of "
                        f"{rule.outside or 'the outside interface'}, which was not "
                        "supplied; the interface name alone is not an address"
                    
                )
                return base
            base.outcome = Outcome.TRANSLATED
            base.translated_source = target
            base.overloaded = True
            base.port_note = (
                "the translated source port depends on runtime allocation order and "
                "cannot be predicted from configuration"
            )
            base.caveats.append(
                "the outside address is where the packet will appear to come from; the "
                "specific port is not predictable"
            )
            return base

        pool = nat.pools.get((rule.pool_name or "").lower())
        if pool is None:
            base.outcome = Outcome.MISCONFIGURED
            base.problems.append(f"rule references pool {rule.pool_name}, which is not defined")
            return base
        start, end, _mask = pool
        base.outcome = Outcome.TRANSLATED
        base.translated_source = start
        base.caveats.append(
            f"dynamic pool {rule.pool_name} spans {start}-{end}; the allocation order is "
            "runtime state, so the first address is shown as an example"
        )
        return base

    base.caveats.append("no rule matches this source")
    return base


def evaluate(
    nat: NatConfig,
    source: str,
    destination: str,
    acl_bodies: dict[str, list[str]] | None = None,
    *,
    egress_interface: str | None = None,
) -> dict:
    """Both directions of a flow, for a report."""
    outbound = translate_outbound(
        nat, source, destination, acl_bodies, egress_interface=egress_interface
    )
    inbound = Translation(
        outcome=Outcome.UNTRANSLATED,
        direction="inbound",
        original_source=destination,
        original_destination=outbound.translated_source or source,
        translated_source=destination,
        translated_destination=source,
        caveats=[
            (
                "an inbound reply only arrives if a translation state exists, which "
                "is runtime evidence"
            )
        ],
    )
    return {"outbound": outbound.as_dict(), "inbound": inbound.as_dict()}


def role_problems(nat: NatConfig) -> list[str]:
    """Configuration-level NAT problems that need no packet to detect."""
    problems: list[str] = []
    if nat.configured and not nat.inside_interfaces:
        problems.append("NAT is configured but no interface is marked 'ip nat inside'")
    if nat.configured and not nat.outside_interfaces:
        problems.append("NAT is configured but no interface is marked 'ip nat outside'")
    for rule in nat.dynamic_rules:
        if rule.pool_name and rule.pool_name.lower() not in nat.pools:
            problems.append(
                f"rule references pool {rule.pool_name}, which is not defined"
            )
    both = set(nat.inside_interfaces) & set(nat.outside_interfaces)
    for interface in sorted(both):
        problems.append(f"{interface} is marked both inside and outside")
    return problems


__all__ = [
    "Outcome",
    "Translation",
    "evaluate",
    "role_problems",
    "translate_outbound",
]
