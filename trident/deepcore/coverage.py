"""Protocol coverage matrix.

A feature being *recognised in a configuration file* is not the same as being
*modelled*, *checked*, or *proven against a running simulator*. This module makes
that difference mechanical.

Four independent levels, each earned separately:

1. **PARSED** — the configuration text is understood and stored as typed facts.
2. **MODELLED** — the semantics are represented, so a question about it can be
   answered deterministically.
3. **STATICALLY_VERIFIED** — a rule can confirm or contradict something about it
   from the model alone.
4. **SIMULATOR_TESTED** — a live Packet Tracer experiment has confirmed the
   behaviour, with the observation recorded.

A protocol at level 1 with level 4 claimed would be a lie, and the data structure
prevents the claim from being made casually: every level is a separate field with
its own evidence requirement.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MATRIX_PATH = Path(__file__).with_name("coverage.json")


class Level(enum.IntEnum):
    """How far support goes. Intentionally ordered."""

    UNSUPPORTED = 0
    PARSED = 1
    MODELLED = 2
    STATICALLY_VERIFIED = 3
    SIMULATOR_TESTED = 4


@dataclass
class Feature:
    """One protocol or feature and its honest support level."""

    name: str
    parsed: bool = False
    modelled: bool = False
    statically_verified: bool = False
    simulator_tested: bool = False
    #: Configurations this does not handle, stated rather than implied.
    limitations: list[str] = field(default_factory=list)
    #: Test or fixture that establishes each level that is claimed.
    evidence: list[str] = field(default_factory=list)

    @property
    def level(self) -> Level:
        if self.simulator_tested:
            return Level.SIMULATOR_TESTED
        if self.statically_verified:
            return Level.STATICALLY_VERIFIED
        if self.modelled:
            return Level.MODELLED
        if self.parsed:
            return Level.PARSED
        return Level.UNSUPPORTED

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "level": self.level.name,
            "parsed": self.parsed,
            "modelled": self.modelled,
            "statically_verified": self.statically_verified,
            "simulator_tested": self.simulator_tested,
            "limitations": list(self.limitations),
            "evidence": list(self.evidence),
        }


#: The matrix as it stands. Every claim below is backed by a test named in
#: ``evidence``; nothing is marked tested without one.
FEATURES: tuple[Feature, ...] = (
    Feature(
        name="ipv4_addressing",
        parsed=True,
        modelled=True,
        statically_verified=True,
        simulator_tested=True,
        evidence=[
            "tests/test_phase2/test_diagnostics.py",
            "tests/simulator/test_live_integration.py",
        ],
    ),
    Feature(
        name="subnetting",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=["tests/test_deepcore_path.py::test_longest_prefix_wins_over_a_default_route"],
        limitations=["overlapping subnets are flagged, not resolved"],
    ),
    Feature(
        name="vlans",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=["tests/adversarial/test_shutdown_semantics.py"],
        limitations=["VLAN database propagation across VTP domains is not modelled"],
    ),
    Feature(
        name="trunks",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=["tests/test_phase2/test_diagnostics.py"],
        limitations=["DTP negotiation state is not modelled"],
    ),
    Feature(
        name="static_routing",
        parsed=True,
        modelled=True,
        statically_verified=True,
        simulator_tested=True,
        evidence=[
            "tests/test_deepcore_path.py::test_two_hop_route_delivers",
            "tests/simulator/test_differential_live.py",
        ],
        limitations=["floating static routes are compared by AD but not by tracking object"],
    ),
    Feature(
        name="ospf",
        parsed=True,
        modelled=False,
        statically_verified=False,
        evidence=["trident/diagnostics/__init__.py (dynamic-route awareness)"],
        limitations=[
            (
                "adjacency state is not modelled; a configured OSPF network does "
                "not imply a formed adjacency"
            ),
            "no area or cost calculation",
        ],
    ),
    Feature(
        name="acl",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=[
            "tests/test_deepcore_path.py::test_explicit_bound_deny_is_reported",
            "tests/test_acl_real_config.py (ACEs captured from a real lab config)",
        ],
        limitations=[
            "only explicit denies bound to a specific interface are evaluated",
            "source and destination operands are both evaluated; an unevaluable",
            "operand yields `unknown`, never `permit`",
            "no ordering evaluation between multiple entries beyond the first match",
            "no evaluation of established/reflexive behaviour",
            "denies are not tested end to end with a real PDU through the ACL",
        ],
    ),
    Feature(
        name="dhcp",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=["tests/test_phase2/test_diagnostics.py"],
        limitations=["lease allocation is not simulated; only pool misconfiguration"],
    ),
    Feature(
        name="nat",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=[
            "tests/test_nat.py",
            "tests/test_protocol_parsing.py",
            "docs/oracle/evidence/lab_survey.json",
        ],
        limitations=[
            "configured translation only; no active translation table is consulted",
            "PAT port assignments are reported as runtime-dependent, never guessed",
            "no authorized lab carried a NAT configuration, so this is not",
            "simulator-tested: `show ip nat statistics` was empty everywhere it ran",
        ],
    ),
    Feature(
        name="stp",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=[
            "tests/test_stp.py",
            "tests/test_protocol_parsing.py",
            "scripts/oracle_differential_stp.py (live `show spanning-tree summary`)",
        ],
        limitations=[
            "roles between non-root bridges use local cost, not full root-path cost",
            "no priority or root command exists in any authorized lab, so root",
            "election is statically verified but not simulator-tested",
            "no BPDU timing, convergence, or VLAN-specific simulator comparison",
        ],
    ),
    Feature(
        name="etherchannel",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=[
            "tests/test_etherchannel.py",
            "tests/test_protocol_parsing.py",
            "scripts/oracle_differential_stp.py (live `show etherchannel summary`)",
        ],
        limitations=[
            "no authorized lab had a configured channel-group, so negotiation is",
            "statically verified but not simulator-tested against a real bundle",
            "no live verification of member compatibility or suspended members",
        ],
    ),
    Feature(
        name="qos",
        parsed=False,
        modelled=False,
        statically_verified=False,
        limitations=["not parsed"],
    ),
    Feature(
        name="routing_authentication",
        parsed=False,
        modelled=False,
        statically_verified=False,
        limitations=["not parsed"],
    ),
    Feature(
        name="ipv6",
        parsed=True,
        modelled=True,
        statically_verified=True,
        evidence=[
            "tests/test_ipv6.py",
            "tests/test_protocol_parsing.py",
            "docs/oracle/evidence/differential_megalab.json (live `show ipv6 route`)",
        ],
        limitations=[
            "ND cache contents are runtime state and are not modelled",
            "a link-local next hop without an outgoing interface is `UNDECIDED`",
            "no authorized lab ran IPv6 forwarding with a populated table, so this is",
            "not simulator-tested",
        ],
    ),
    Feature(
        name="port_security",
        parsed=False,
        modelled=False,
        statically_verified=False,
        limitations=["not parsed"],
    ),
    Feature(
        name="device_administration",
        parsed=False,
        modelled=False,
        statically_verified=False,
        limitations=["not parsed"],
    ),
)


class CoverageMatrix:
    """Query and serialise the coverage of one build."""

    def __init__(self, features: tuple[Feature, ...] = FEATURES) -> None:
        self.features = features

    def get(self, name: str) -> Feature | None:
        for feature in self.features:
            if feature.name == name:
                return feature
        return None

    def at_least(self, level: Level) -> list[str]:
        return [f.name for f in self.features if f.level >= level]

    def summary(self) -> dict:
        counts: dict[str, int] = {level.name: 0 for level in Level}
        for feature in self.features:
            counts[feature.level.name] += 1
        return {
            "total": len(self.features),
            "counts": counts,
            "simulator_tested": self.at_least(Level.SIMULATOR_TESTED),
            "statically_verified": self.at_least(Level.STATICALLY_VERIFIED),
            "parsed_only": [
                f.name
                for f in self.features
                if f.level is Level.PARSED
            ],
            "unsupported": [f.name for f in self.features if f.level is Level.UNSUPPORTED],
        }

    def as_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "features": [feature.as_dict() for feature in self.features],
        }

    def write(self, path: Path | None = None) -> Path:
        target = path or DEFAULT_MATRIX_PATH
        target.write_text(json.dumps(self.as_dict(), indent=2) + "\n")
        return target


__all__ = ["DEFAULT_MATRIX_PATH", "FEATURES", "CoverageMatrix", "Feature", "Level"]
