"""Diagnosis: turn requirement verdicts into faults an operator can act on.

The verifier answers "does this requirement hold?" per requirement. A student
does not want N statements about N packets; they want the one misconfigured
port that causes all of them. This module performs that reduction while
preserving the honesty rules Engine D was built around:

* a finding exists only for a *failed* requirement — never for INCONCLUSIVE,
  never for UNSUPPORTED;
* evidence strings are copied from the verdict, not written here, so a
  correction can always be traced back to the fact that produced it;
* a correction is derived from the existing device/interface facts and states
  the expected value. No device is named that the model does not contain.

The false-positive guard is structural: findings are produced by iterating
requirements. With no requirement there is nothing to fail, and a missing route
on a network nobody asked about remains unmentioned.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from trident.assessment.requirements import ParsedRequirement, to_intent
from trident.engined.reachability import classify_device, vlan_path
from trident.engined.verify import RequirementVerdict, Status, verify_intent

_ROUTE_CATEGORIES = {
    "MISSING_ROUTE",
    "MISSING_FORWARD_ROUTE",
    "MISSING_RETURN_ROUTE",
    "UNREACHABLE_NEXT_HOP",
}

_ASSERTION_CATEGORIES = {
    "route": "MISSING_ROUTE",
    "interface_up": "ADMIN_SHUTDOWN",
    "vlan_membership": "VLAN_MISMATCH",
    "gateway": "WRONG_GATEWAY",
}


@dataclass
class Finding:
    """One requirement-level fault, with the evidence that supports it."""

    requirement: str
    device: str
    interface: str | None
    category: str
    evidence: list[str]
    confidence: str
    uncertainty: list[str]
    proposed_correction: str
    status: Status
    #: Index into :attr:`AssessmentDiagnosis.verdicts` that produced this
    #: finding. Lets a caller verify that every evidence string came from the
    #: corresponding verdict.
    verdict_index: int = -1

    def as_dict(self) -> dict:
        return {
            "requirement": self.requirement,
            "device": self.device,
            "interface": self.interface,
            "category": self.category,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "uncertainty": list(self.uncertainty),
            "proposed_correction": self.proposed_correction,
            "status": self.status.value,
            "verdict_index": self.verdict_index,
        }


@dataclass
class RootCause:
    """One underlying defect shared by one or more findings."""

    device: str
    interface: str | None
    category: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def requirements(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.requirement not in seen:
                seen.append(finding.requirement)
        return seen

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "interface": self.interface,
            "category": self.category,
            "count": self.count,
            "requirements": self.requirements,
            "proposed_correction": (
                self.findings[0].proposed_correction if self.findings else ""
            ),
        }


@dataclass
class AssessmentDiagnosis:
    """Everything known about a set of visible requirements."""

    verdicts: list[RequirementVerdict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    inconclusive: list[dict] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)
    unresolvable: list[str] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for verdict in self.verdicts if _is_pass(verdict))

    def root_causes(self) -> list[RootCause]:
        """Group findings by (device, interface, category).

        Three hosts behind one shut port are one defect with three symptoms.
        Grouping by the deciding hop is the smallest unit an operator can act
        on, which is why the category participates too: a missing route and an
        ACL deny on the same interface are separate repairs.
        """
        groups: dict[tuple[str, str | None, str], RootCause] = {}
        for finding in self.findings:
            key = (finding.device, finding.interface, finding.category)
            if key not in groups:
                groups[key] = RootCause(
                    device=finding.device,
                    interface=finding.interface,
                    category=finding.category,
                )
            groups[key].findings.append(finding)
        return list(groups.values())

    def as_dict(self) -> dict:
        return {
            "verdicts": [verdict.as_dict() for verdict in self.verdicts],
            "findings": [finding.as_dict() for finding in self.findings],
            "root_causes": [cause.as_dict() for cause in self.root_causes()],
            "unsupported": list(self.unsupported),
            "inconclusive": list(self.inconclusive),
            "unparsed": list(self.unparsed),
            "unresolvable": list(self.unresolvable),
            "summary": {
                "verdicts": len(self.verdicts),
                "passed": self.passed,
                "findings": len(self.findings),
                "root_causes": len(self.root_causes()),
                "unsupported": len(self.unsupported),
                "inconclusive": len(self.inconclusive),
                "unparsed": len(self.unparsed),
                "unresolvable": len(self.unresolvable),
            },
        }


def _is_pass(verdict: RequirementVerdict) -> bool:
    return (
        not verdict.failed
        and verdict.reachable is not None
        and verdict.status in {Status.VERIFIED, Status.DERIVED}
    )


def _confidence(verdict: RequirementVerdict) -> str:
    """Confidence follows the status, never the other way round.

    Only a live observation can produce HIGH. Static analysis is MEDIUM at
    best. A contradiction is LOW because the two evidence channels disagree.
    """
    if verdict.status is Status.VERIFIED:
        return "HIGH"
    if verdict.status is Status.DERIVED:
        return "MEDIUM"
    return "LOW"


def _uncertainty(verdict: RequirementVerdict) -> list[str]:
    reasons: list[str] = []
    if verdict.status is Status.DERIVED:
        reasons.append("derived from configuration analysis; no live observation")
    elif verdict.status is Status.CONTRADICTED:
        reasons.append("live observation contradicts the static prediction")
    if verdict.missing:
        reasons.append("missing facts: " + "; ".join(verdict.missing))
    if not verdict.evidence:
        reasons.append("the verifier produced no evidence string")
    return reasons


def _category(verdict: RequirementVerdict, report) -> str:
    requirement = verdict.requirement
    if requirement.must_not_reach:
        return "ISOLATION_VIOLATION"
    if requirement.assertion:
        return _ASSERTION_CATEGORIES.get(
            requirement.assertion.lower(), "ASSERTION_FAILED"
        )
    faults = report.localize_faults()
    if faults:
        return faults[0].kind
    return "UNREACHABLE"


# ---------------------------------------------------------------------------
# Correction synthesis
# ---------------------------------------------------------------------------


def _addressed_interfaces(model, device: str) -> list:
    return [
        iface
        for iface in (getattr(model, "interfaces", {}) or {}).values()
        if getattr(iface, "device", None) == device
        and getattr(iface, "ipv4_address", None)
    ]


def _gateway_of(model, device: str) -> str | None:
    interfaces = _addressed_interfaces(model, device)
    if not interfaces:
        return None
    return getattr(interfaces[0], "ipv4_gateway", None)


def _vlan_assignments(model, device: str, interface: str | None) -> list[str]:
    if not interface:
        return []
    found = (getattr(model, "interfaces", {}) or {}).get(f"{device}:{interface}")
    if found is None:
        return []
    return [str(v) for v in getattr(found, "vlan_assignments", []) or []]


def _vlan_of(model, device: str) -> int | None:
    try:
        return vlan_path(model, device).vlan
    except Exception:  # noqa: BLE001 - a model gap must not break a correction
        return None


def _expected_route(model, device: str, target_ip: str | None) -> tuple[str | None, str | None]:
    """The destination network, and a real next hop from ``device`` if one exists.

    Both values come from interfaces already in the model. When no neighbour is
    modelled the next hop is None and the correction names only the prefix — a
    true statement about the existing topology, not an invented address.
    """
    if not target_ip:
        return None, None
    try:
        target = ipaddress.IPv4Address(target_ip)
    except ValueError:
        return None, None

    best_net: ipaddress.IPv4Network | None = None
    for iface in (getattr(model, "interfaces", {}) or {}).values():
        address = getattr(iface, "ipv4_address", None)
        prefix = getattr(iface, "prefix_length", None)
        if not address or prefix is None:
            continue
        try:
            net = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
        except ValueError:
            continue
        if target not in net:
            continue
        if best_net is None or net.prefixlen > best_net.prefixlen:
            best_net = net

    next_hop: str | None = None
    own_nets: list[ipaddress.IPv4Network] = []
    for iface in _addressed_interfaces(model, device):
        prefix = getattr(iface, "prefix_length", None)
        if prefix is None:
            continue
        try:
            own_nets.append(
                ipaddress.IPv4Network(f"{iface.ipv4_address}/{prefix}", strict=False)
            )
        except ValueError:
            continue

    candidates: list[tuple[str, str]] = []
    for iface in (getattr(model, "interfaces", {}) or {}).values():
        other = getattr(iface, "device", None)
        address = getattr(iface, "ipv4_address", None)
        if not other or other == device or not address:
            continue
        try:
            hop = ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if not any(hop in net for net in own_nets):
            continue
        if classify_device(model, other) not in {"router", "l3_switch"}:
            continue
        candidates.append((other, address))
    if candidates:
        candidates.sort()
        next_hop = candidates[0][1]

    return (str(best_net) if best_net is not None else None), next_hop


def _target_ip(model, verdict: RequirementVerdict, category: str) -> str | None:
    endpoint = verdict.requirement.src if category == "MISSING_RETURN_ROUTE" else verdict.requirement.dst
    try:
        return endpoint.resolve(model)
    except Exception:  # noqa: BLE001 - the correction degrades to the prefix only
        return None


def _propose(model, verdict: RequirementVerdict, category: str) -> str:
    requirement = verdict.requirement
    device = verdict.deciding_device or requirement.src.device
    interface = verdict.deciding_interface
    src = requirement.src.device
    dst = requirement.dst.device

    if requirement.assertion == "gateway":
        actual = _gateway_of(model, device)
        return (
            f"Set the default gateway on {device} to {requirement.operand} "
            f"(expected {requirement.operand}; the model shows {actual or 'none'})"
        )

    if requirement.assertion == "interface_up":
        return (
            f"Configure 'no shutdown' on {requirement.operand} "
            "(expected: administratively up; the model shows it down)"
        )

    if requirement.assertion == "vlan_membership":
        have = _vlan_assignments(model, device, interface)
        return (
            f"Assign {requirement.operand} to VLAN {requirement.protocol} "
            f"(expected VLAN {requirement.protocol}; the model shows "
            f"{', '.join(have) if have else 'none'})"
        )

    if requirement.assertion == "route":
        return (
            f"Add a route on {device} covering {requirement.operand} "
            f"(expected: {device} can forward {requirement.operand}; "
            "no covering route is configured)"
        )

    if category == "ISOLATION_VIOLATION":
        where = f" at {device}" if verdict.deciding_device else ""
        return (
            f"Remove the forwarding path between {src} and {dst}{where} "
            "(expected: no reachability between them, but traffic is forwarded)"
        )

    if category in _ROUTE_CATEGORIES:
        target = _target_ip(model, verdict, category)
        network, next_hop = _expected_route(model, device, target)
        if network and next_hop:
            return (
                f"Add a route on {device} for {network} via {next_hop} "
                f"(expected: forwarding for {target}; {device} has no covering route)"
            )
        if network:
            return (
                f"Add a route on {device} covering {network} "
                f"(expected: forwarding for {target}; {device} has no covering route)"
            )
        return (
            f"Add a route on {device} toward {target or dst} "
            "(expected: a forwarding entry covering the destination; none is configured)"
        )

    if category == "ADMIN_SHUTDOWN":
        target = f"{device} {interface}" if interface else device
        return (
            f"Configure 'no shutdown' on {target} "
            "(expected: administratively up; the model shows it down)"
        )

    if category == "ACL_DENY":
        return (
            f"Permit the required traffic from {src} to {dst} on {device} "
            "(expected: an ACE that permits it; the current ACL denies)"
        )

    if category == "TRUNK_VLAN_GAP":
        vlan = _vlan_of(model, dst) or _vlan_of(model, src)
        where = f"{device} {interface}".strip() if interface else device
        if vlan is not None:
            return (
                f"Add VLAN {vlan} to the allowed VLAN list on {where} "
                f"(expected: VLAN {vlan} permitted on the trunk)"
            )
        return (
            f"Add the required VLAN to the allowed VLAN list on {where} "
            "(expected: the VLAN carrying this traffic is permitted on the trunk)"
        )

    if category == "VLAN_MISSING":
        vlan = _vlan_of(model, dst) or _vlan_of(model, src)
        if vlan is not None:
            return (
                f"Create VLAN {vlan} in the VLAN database on {device} "
                f"(expected: VLAN {vlan} defined)"
            )
        return f"Create the missing VLAN in the VLAN database on {device} (expected: the VLAN is defined)"

    if category == "ROUTING_LOOP":
        return (
            f"Remove the forwarding loop through {device} "
            "(expected: a path that terminates at the destination)"
        )

    return (
        f"Inspect forwarding on {device} for traffic from {src} to {dst} "
        "(expected: a complete path; the current configuration has none)"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def diagnose(model, parsed_requirements: list[ParsedRequirement]) -> AssessmentDiagnosis:
    """Verify every parsed requirement against ``model`` and localise failures.

    INCONCLUSIVE and UNSUPPORTED requirements are recorded separately. They are
    neither passes nor faults: turning either into a finding would accuse a
    network of a defect the analysis could not actually decide.
    """
    diagnosis = AssessmentDiagnosis()

    for parsed in parsed_requirements:
        if not parsed.parsed:
            diagnosis.unparsed.append(parsed.raw)
            continue

        intent = to_intent(parsed, model)
        if parsed.unresolvable is not None:
            diagnosis.unresolvable.append(parsed.raw)
            diagnosis.unsupported.append(f"{parsed.raw}: {parsed.unresolvable}")
            continue

        report = verify_intent(model, intent)
        for verdict in report.verdicts:
            index = len(diagnosis.verdicts)
            diagnosis.verdicts.append(verdict)

            if verdict.status is Status.UNSUPPORTED:
                reason = "; ".join(verdict.missing) or "not modelled by Engine D"
                diagnosis.unsupported.append(f"{parsed.raw}: {reason}")
                continue

            if verdict.status is Status.INCONCLUSIVE:
                diagnosis.inconclusive.append(
                    {
                        "requirement": parsed.raw,
                        "status": verdict.status.value,
                        "reason": "; ".join(verdict.missing) or "could not be decided",
                        "missing": list(verdict.missing),
                    }
                )
                continue

            if not verdict.failed:
                continue

            category = _category(verdict, report)
            device = verdict.deciding_device or verdict.requirement.src.device
            diagnosis.findings.append(
                Finding(
                    requirement=parsed.raw,
                    device=device,
                    interface=verdict.deciding_interface,
                    category=category,
                    # Copied, never composed: every string is traceable to the
                    # verdict that decided this requirement.
                    evidence=list(verdict.evidence),
                    confidence=_confidence(verdict),
                    uncertainty=_uncertainty(verdict),
                    proposed_correction=_propose(model, verdict, category),
                    status=verdict.status,
                    verdict_index=index,
                )
            )

    return diagnosis


__all__ = [
    "AssessmentDiagnosis",
    "Finding",
    "RootCause",
    "diagnose",
]
