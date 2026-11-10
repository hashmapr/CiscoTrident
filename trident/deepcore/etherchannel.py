"""EtherChannel compatibility reasoning.

An EtherChannel only forms when its members agree on more than the channel-group
number: the negotiation modes must be complementary, and the members must share
VLAN configuration, mode and speed/duplex. IOS silently refuses to bundle a port
that disagrees, leaving it as an independent link — which is why a broken
aggregation looks like nothing happened.

The rule that stops this being a false-positive generator: **independent
interfaces are not a broken EtherChannel.** A check only fires on ports that were
actually configured into a group. Two access ports that were never grouped are two
access ports, and reporting them would make every switch in every lab "wrong".
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .protocols import EtherChannel, PortChannelMode


class Compatibility(enum.StrEnum):
    """Whether an EtherChannel can form."""

    FORMS = "FORMS"
    #: The configuration is self-contradictory; the channel cannot form.
    CANNOT_FORM = "CANNOT_FORM"
    #: Evidence is missing for a check that would decide it.
    UNDECIDED = "UNDECIDED"


@dataclass
class Problem:
    """One reason a channel cannot form."""

    severity: str
    description: str
    evidence: str
    remediation: str | None = None

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class Assessment:
    """The result for one EtherChannel."""

    port_channel: str
    compatibility: Compatibility
    mode: PortChannelMode
    protocol: str
    members: list[str] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return self.compatibility is Compatibility.FORMS and not self.problems

    def as_dict(self) -> dict:
        return {
            "port_channel": self.port_channel,
            "compatibility": self.compatibility.value,
            "mode": self.mode.value,
            "protocol": self.protocol,
            "members": list(self.members),
            "problems": [problem.as_dict() for problem in self.problems],
            "assumptions": list(self.assumptions),
            "healthy": self.healthy,
        }


#: Mode pairs that successfully negotiate, by protocol.
_LACP_PAIRS = {
    frozenset({PortChannelMode.ACTIVE, PortChannelMode.ACTIVE}),
    frozenset({PortChannelMode.ACTIVE, PortChannelMode.PASSIVE}),
}
_PAGP_PAIRS = {
    frozenset({PortChannelMode.DESIRABLE, PortChannelMode.DESIRABLE}),
    frozenset({PortChannelMode.DESIRABLE, PortChannelMode.AUTO}),
}


def modes_negotiate(left: PortChannelMode, right: PortChannelMode) -> bool:
    """Whether two negotiation modes can form a channel together.

    ``on`` only pairs with ``on``: a static channel never negotiates. ``active``
    needs a partner that sends LACP; ``passive`` needs one that initiates.
    """
    if left is PortChannelMode.ON or right is PortChannelMode.ON:
        return left is PortChannelMode.ON and right is PortChannelMode.ON
    pair = frozenset({left, right})
    if pair in _LACP_PAIRS:
        return True
    return pair in _PAGP_PAIRS


def peer_mode_problem(local: PortChannelMode, peer: PortChannelMode) -> str | None:
    """Describe why two ends cannot negotiate, or ``None`` when they can."""
    if modes_negotiate(local, peer):
        return None
    if {local, peer} == {PortChannelMode.PASSIVE}:
        return "both ends are passive; neither initiates LACP negotiation"
    if {local, peer} == {PortChannelMode.AUTO}:
        return "both ends are auto; neither initiates PAgP negotiation"
    return f"{local.value} and {peer.value} do not negotiate with each other"


def assess_channel(channel: EtherChannel) -> Assessment:
    """Assess one EtherChannel's internal consistency."""
    assessment = Assessment(
        port_channel=channel.port_channel,
        compatibility=Compatibility.FORMS,
        mode=channel.mode,
        protocol=channel.protocol,
        members=list(channel.members),
    )

    if not channel.members:
        assessment.compatibility = Compatibility.UNDECIDED
        assessment.problems.append(
            Problem(
                severity="INFO",
                description=f"{channel.port_channel} has no member interfaces",
                evidence="no channel-group command references this port-channel",
            )
        )
        return assessment

    if channel.mode is PortChannelMode.UNKNOWN:
        # An unrecognised mode cannot be judged compatible or incompatible, so it
        # is undecided rather than a failure. Returning early stops the generic
        # problem check below from downgrading it to CANNOT_FORM.
        assessment.compatibility = Compatibility.UNDECIDED
        assessment.problems.append(
            Problem(
                severity="MEDIUM",
                description=f"{channel.port_channel} has no recognised negotiation mode",
                evidence="channel-group mode is absent or unrecognised",
            )
        )
        return assessment

    # The parser records disagreement between members as it reads them.
    for issue in channel.issues:
        assessment.problems.append(
            Problem(
                severity="HIGH",
                description=issue,
                evidence="conflicting channel-group mode lines",
                remediation="configure every member of a port-channel with the same mode",
            )
        )

    if assessment.problems:
        assessment.compatibility = Compatibility.CANNOT_FORM
        return assessment

    if len(channel.members) == 1:
        assessment.problems.append(
            Problem(
                severity="LOW",
                description=(
                    f"{channel.port_channel} has a single member; a channel of one port "
                    "provides no aggregation"
                ),
                evidence=f"only {channel.members[0]} is in the group",
            )
        )
        # A single-member channel still forms; it just buys nothing. That is a
        # design observation, not a failure, so compatibility stays FORMS.

    return assessment


def assess_peer(
    local: EtherChannel,
    peer: EtherChannel,
    local_bridge: str = "",
    peer_bridge: str = "",
) -> Assessment:
    """Assess a channel formed between two switches."""
    assessment = assess_channel(local)
    if assessment.compatibility is Compatibility.CANNOT_FORM:
        return assessment

    problem = peer_mode_problem(local.mode, peer.mode)
    if problem is not None:
        assessment.compatibility = Compatibility.CANNOT_FORM
        assessment.problems.append(
            Problem(
                severity="HIGH",
                description=problem,
                evidence=(
                    f"{local_bridge or 'local'} {local.port_channel} is {local.mode.value}; "
                    f"{peer_bridge or 'peer'} {peer.port_channel} is {peer.mode.value}"
                ),
                remediation="use complementary modes, e.g. active/active or active/passive",
            )
        )
        return assessment

    if local.protocol != peer.protocol:
        assessment.compatibility = Compatibility.CANNOT_FORM
        assessment.problems.append(
            Problem(
                severity="HIGH",
                description=(
                    f"negotiation protocols differ: {local.protocol} against "
                    f"{peer.protocol}"
                ),
                evidence="channel-protocol or mode implies a different protocol on each end",
                remediation="use the same negotiation protocol on both ends",
            )
        )
        return assessment

    if len(local.members) != len(peer.members):
        assessment.problems.append(
            Problem(
                severity="MEDIUM",
                description=(
                    f"member counts differ: {len(local.members)} against "
                    f"{len(peer.members)}"
                ),
                evidence="the two ends bundle a different number of physical links",
            )
        )

    return assessment


def assess_all(channels: dict[str, EtherChannel]) -> list[Assessment]:
    """Assess every channel a device has, without inventing peer relationships."""
    return [assess_channel(channel) for channel in channels.values()]


__all__ = [
    "Assessment",
    "Compatibility",
    "Problem",
    "assess_all",
    "assess_channel",
    "assess_peer",
    "modes_negotiate",
    "peer_mode_problem",
]
