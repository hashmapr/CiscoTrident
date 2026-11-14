"""Verdict engine: turn path reasoning into an honest status.

The five statuses exist to stop three specific lies:

* calling something `VERIFIED` because static analysis said so (that is
  `DERIVED` — nothing observed the packet move);
* calling something `CONTRADICTED` on a guess, or promoting an uncertain finding
  because a live run happened to be available;
* calling something `UNSUPPORTED` "inconclusive" so it disappears into a count.

Every verdict carries the evidence that produced it. ``explain`` writes prose,
and is the only place a model could be consulted — it cannot change a status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .intent import NetworkIntent, Requirement
from .reachability import (
    TraceOutcome,
    classify_device,  # noqa: F401 - re-exported: callers import it from verify
    evaluate_acls,
    router_for_address,
    trace_path,
    vlan_path,
)
from .reachability import is_router_like as _is_router_like


class Status(StrEnum):
    """What we actually know, and why."""

    #: Deterministic analysis proves the outcome, and (if supplied) live
    #: observation agrees with it.
    VERIFIED = "VERIFIED"
    #: Deterministic analysis proves the outcome; nothing observed it.
    DERIVED = "DERIVED"
    #: The model lacks facts needed to decide. ``missing`` says which.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: Live observation disagrees with the deterministic prediction.
    CONTRADICTED = "CONTRADICTED"
    #: The requirement exercises something Engine D does not model.
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class RequirementVerdict:
    """The outcome for one requirement, with its evidence."""

    requirement: Requirement
    status: Status
    reachable: bool | None
    deciding_device: str | None = None
    deciding_interface: str | None = None
    evidence: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    #: Which half of the conversation failed: ``"forward"``, ``"return"`` or None.
    #: A forward path that works with a broken reply is a different fault from a
    #: forward path that never leaves the source, and an operator acts on them
    #: differently.
    failure_direction: str | None = None
    live_disagrees: bool = False

    @property
    def failed(self) -> bool:
        """True only when a required outcome is not met.

        A ``must_not_reach`` requirement inverts the test: reachability is the
        failure. Getting this wrong makes every correctly segmented network look
        broken, which is the single most common false positive in a verifier.
        """
        if self.reachable is None:
            return False
        if not self.status in {Status.DERIVED, Status.VERIFIED, Status.CONTRADICTED}:
            return False
        if self.requirement.must_not_reach:
            return self.reachable is True and self.requirement.required
        return self.requirement.required and self.reachable is False

    def as_dict(self) -> dict:
        return {
            "src": self.requirement.src.device,
            "dst": self.requirement.dst.device,
            "description": self.requirement.description,
            "status": self.status.value,
            "reachable": self.reachable,
            "deciding_device": self.deciding_device,
            "deciding_interface": self.deciding_interface,
            "evidence": list(self.evidence),
            "missing": list(self.missing),
            "failure_direction": self.failure_direction,
        }


@dataclass
class FaultFinding:
    """One root cause, with every requirement it explains."""

    device: str
    interface: str | None
    kind: str
    detail: str
    affected: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "interface": self.interface,
            "kind": self.kind,
            "detail": self.detail,
            "affected": list(self.affected),
        }


@dataclass
class IntentReport:
    """The result of verifying a whole intent."""

    intent: NetworkIntent
    verdicts: list[RequirementVerdict] = field(default_factory=list)

    @property
    def failures(self) -> list[RequirementVerdict]:
        return [v for v in self.verdicts if v.failed]

    @property
    def passes(self) -> list[RequirementVerdict]:
        return [v for v in self.verdicts if v.reachable and not v.failed]

    def by_status(self) -> dict[Status, int]:
        counts: dict[Status, int] = {status: 0 for status in Status}
        for verdict in self.verdicts:
            counts[verdict.status] += 1
        return counts

    def localize_faults(self) -> list[FaultFinding]:
        """Group failing requirements by shared root cause.

        Five hosts behind one shut port is ONE fault, not five. Grouping is by
        (device, interface) of the deciding hop, which is the smallest unit an
        operator can act on.
        """
        groups: dict[tuple[str, str | None], FaultFinding] = {}
        for verdict in self.failures:
            key = (verdict.deciding_device or "?", verdict.deciding_interface)
            label = f"{verdict.requirement.src.device} -> {verdict.requirement.dst.device}"
            if key not in groups:
                groups[key] = FaultFinding(
                    device=key[0],
                    interface=key[1],
                    kind=_kind_for(verdict),
                    detail=verdict.evidence[-1] if verdict.evidence else "",
                )
            groups[key].affected.append(label)
        return list(groups.values())

    def as_dict(self) -> dict:
        return {
            "intent": self.intent.name,
            "verdicts": [v.as_dict() for v in self.verdicts],
            "faults": [f.as_dict() for f in self.localize_faults()],
            "status_counts": {k.value: v for k, v in self.by_status().items()},
        }


def _kind_for(verdict: RequirementVerdict) -> str:
    """The fault class for a failed requirement, from its *deciding* evidence.

    Order matters and is by specificity of the deciding statement, not by which
    keyword appears anywhere in the log. A missing-route verdict includes the
    text "R1 has no ACL configured" among its evidence, so testing for "acl"
    anywhere mislabelled routing faults as ACL blocks.
    """
    text = " ".join(verdict.evidence).lower()
    if "administratively down" in text:
        return "ADMIN_SHUTDOWN"
    # An ACL is decisive only when an ACE actually matched and denied.
    if "ace" in text and "denied" in text:
        return "ACL_DENY"
    if "implicit deny" in text:
        return "ACL_DENY"
    if "trunk" in text:
        return "TRUNK_VLAN_GAP"
    if "not defined in the vlan database" in text:
        return "VLAN_MISSING"
    if "forwarding loop" in text or "hop limit" in text:
        return "ROUTING_LOOP"
    # The direction that failed names the fault. A missing outbound route and a
    # missing reply route are different repairs even though both read as "no
    # route" in a log; collapsing them sends an operator to the wrong router.
    if verdict.failure_direction == "forward":
        return "MISSING_FORWARD_ROUTE"
    if verdict.failure_direction == "return":
        return "MISSING_RETURN_ROUTE"
    if "no route" in text:
        return "MISSING_ROUTE"
    return "UNREACHABLE"


def verify_assertion(model, requirement: Requirement) -> RequirementVerdict:
    """Verify a non-reachability assertion.

    Three shapes are supported, because they are the three things a networking
    lab actually asks a student to confirm:

    * ``route`` — a device has a route covering the operand prefix;
    * ``interface_up`` — ``device:interface`` is not administratively down;
    * ``vlan_membership`` — ``device:interface`` is in ``vlan:N``.

    An unrecognised assertion is UNSUPPORTED, not a silent pass. That distinction
    is what keeps the status vocabulary honest.
    """
    assertion = (requirement.assertion or "").lower()
    operand = requirement.operand or ""

    if assertion == "route":
        device = requirement.src.device
        from .reachability import ForwardingTable

        decision = ForwardingTable(model, device).decide(_prefix_probe(operand))
        ok = decision.forwards
        return RequirementVerdict(
            requirement,
            Status.DERIVED,
            ok,
            deciding_device=device,
            evidence=[decision.detail],
        )

    if assertion == "gateway":
        device = requirement.src.device
        expected = operand
        interfaces = [
            i
            for i in getattr(model, "interfaces", {}).values()
            if i.device == device and getattr(i, "ipv4_address", None)
        ]
        if not interfaces:
            return RequirementVerdict(
                requirement, Status.INCONCLUSIVE, None,
                missing=[f"{device} has no addressed interface in the model"],
            )
        actual = getattr(interfaces[0], "ipv4_gateway", None)
        return RequirementVerdict(
            requirement, Status.DERIVED, actual == expected,
            deciding_device=device,
            evidence=[f"{device} gateway is {actual}; expected {expected}"],
        )

    if assertion == "interface_up":
        device, _, interface = operand.partition(":")
        found = model.interfaces.get(f"{device}:{interface}")
        if found is None:
            return RequirementVerdict(
                requirement, Status.INCONCLUSIVE, None,
                missing=[f"interface {operand} is not in the model"],
            )
        down = "down" in (getattr(found, "admin_state", "") or "").lower()
        return RequirementVerdict(
            requirement, Status.DERIVED, not down,
            deciding_device=device, deciding_interface=interface,
            evidence=[f"{operand} is {'down' if down else 'up'}"],
        )

    if assertion == "vlan_membership":
        device, _, interface = operand.partition(":")
        want = requirement.protocol if requirement.protocol.isdigit() else None
        found = model.interfaces.get(f"{device}:{interface}")
        if found is None:
            return RequirementVerdict(
                requirement, Status.INCONCLUSIVE, None,
                missing=[f"interface {operand} is not in the model"],
            )
        have = [str(v) for v in getattr(found, "vlan_assignments", [])]
        ok = bool(want) and want in have
        return RequirementVerdict(
            requirement, Status.DERIVED, ok,
            deciding_device=device, deciding_interface=interface,
            evidence=[f"{operand} is in VLAN(s) {have or 'none'}; expected {want}"],
        )

    return RequirementVerdict(
        requirement, Status.UNSUPPORTED, None,
        missing=[f"unknown assertion {requirement.assertion!r}"],
    )


def _prefix_probe(prefix: str) -> str:
    """An address inside ``prefix`` suitable for asking "is there a route?"."""
    import ipaddress

    try:
        net = ipaddress.IPv4Network(prefix, strict=False)
    except ValueError:
        return prefix
    hosts = list(net.hosts())[:1]
    return str(hosts[0]) if hosts else str(net.network_address)


def verify_requirement(
    model,
    requirement: Requirement,
    live_observation: bool | None = None,
) -> RequirementVerdict:
    """Determine whether one requirement holds.

    ``live_observation`` is a separate evidence channel: ``True`` means a live
    ping succeeded, ``False`` means it failed, ``None`` means nothing was
    observed. It never substitutes for reasoning; it can only confirm or
    contradict a prediction.
    """
    if requirement.assertion:
        return verify_assertion(model, requirement)

    try:
        src_ip = requirement.src.resolve(model)
        dst_ip = requirement.dst.resolve(model)
    except Exception as exc:  # noqa: BLE001 - reported as inconclusive, never guessed
        return RequirementVerdict(
            requirement, Status.INCONCLUSIVE, None,
            missing=[f"endpoint could not be resolved: {exc}"],
            evidence=[str(exc)],
        )

    # Off-subnet traffic needs a real gateway.
    #
    # This sits after the same-subnet branch below (a host with a wrong gateway
    # can still reach its own L2 segment), so it is checked later in the flow.
    if _uses_dynamic_routing(model):
        # The configuration says a routing protocol runs, but the model carries
        # no adjacencies or learned routes. Static analysis would be a guess, so
        # the honest status is INCONCLUSIVE naming the missing fact — never a
        # fabricated missing route.
        return RequirementVerdict(
            requirement, Status.INCONCLUSIVE, None,
            missing=["dynamic routing is not modelled, so no route table can be derived"],
            evidence=[
                ("a router runs a dynamic routing protocol; static path analysis "
                "cannot prove reachability")
            ],
        )

    # VLAN path, but only when the host is actually behind a switch that has a
    # VLAN-configured port. A host with no switch port (or a router-to-router
    # requirement) has no VLAN hop to check, and treating "no port found" as a
    # failure made every directly-connected model look broken.
    src_vlan = vlan_path(model, requirement.src.device)
    vlan_applies = src_vlan.vlan is not None or bool(src_vlan.blockers)
    if vlan_applies and not src_vlan.reachable:
        evidence = list(src_vlan.blockers) or [src_vlan.detail]
        deciding = _deciding_from_vlan(model, requirement.src.device, src_vlan)
        return RequirementVerdict(
            requirement, Status.DERIVED, False,
            deciding_device=deciding[0], deciding_interface=deciding[1],
            evidence=evidence,
        )

    # A destination on the same subnet is NOT automatically reachable: its
    # switch port may be in a different VLAN, which is invisible to L3 reasoning.
    # Checking only the source's VLAN let a VLAN-20 host look reachable.
    if _same_subnet(model, src_ip, dst_ip):
        dst_vlan = vlan_path(model, requirement.dst.device)
        if dst_vlan.vlan is not None and not dst_vlan.reachable:
            deciding = _deciding_from_vlan(model, requirement.dst.device, dst_vlan)
            return RequirementVerdict(
                requirement, Status.DERIVED, False,
                deciding_device=deciding[0], deciding_interface=deciding[1],
                evidence=list(dst_vlan.blockers) or [dst_vlan.detail],
            )
        src_vlan = vlan_path(model, requirement.src.device)
        if (
            src_vlan.vlan is not None
            and dst_vlan.vlan is not None
            and src_vlan.vlan != dst_vlan.vlan
        ):
            # Name the switch port, not the host: the host is the victim, the
            # port is the defect. Attributing to the host made a VLAN fault look
            # like a fabricated finding on a PC.
            port_device, port_iface = _vlan_port(model, requirement.dst.device)
            return RequirementVerdict(
                requirement, Status.DERIVED, False,
                deciding_device=port_device or dst_vlan.host,
                deciding_interface=port_iface,
                evidence=[
                    (
                        f"{requirement.src.device} is in VLAN {src_vlan.vlan} but "
                        f"{requirement.dst.device} is in VLAN {dst_vlan.vlan}; they "
                        "are not in the same broadcast domain despite sharing a subnet"
                    )
                ],
            )

    # Off-subnet only beyond this point (the same-subnet branch returned above),
    # so a host whose configured gateway nobody owns discards its own packets.
    # The failure belongs to the HOST, not to a router downstream: routing from
    # a router the packet never reaches would describe a path that cannot exist.
    gateway_problem = _gateway_problem(model, requirement.src.device)
    if gateway_problem is not None:
        return RequirementVerdict(
            requirement, Status.DERIVED, False,
            deciding_device=requirement.src.device,
            evidence=[gateway_problem],
        )

    # Locate the router that serves the source endpoint, then walk the packet
    # across every router it must cross. One router's table is not a path.
    src_router = _router_for_address(model, src_ip) or _device_if_router(model, src_ip)
    if src_router is None:
        return RequirementVerdict(
            requirement, Status.INCONCLUSIVE, None,
            missing=[
                f"no router interface serves {src_ip}",
                "no L3 gateway for the source is modelled, so forwarding cannot be evaluated",
            ],
            evidence=[
                f"forward path ({src_ip} -> {dst_ip}): no gateway is modelled for {src_ip}"
            ],
        )

    forward = trace_path(model, src_ip, dst_ip, start_router=src_router)
    forward_evidence = [
        f"forward path ({src_ip} -> {dst_ip}): {line}" for line in forward.evidence()
    ]

    if forward.outcome is TraceOutcome.UNSUPPORTED:
        return RequirementVerdict(
            requirement, Status.UNSUPPORTED, None,
            missing=["destination is not analysable"],
            evidence=forward_evidence,
        )
    if forward.outcome is TraceOutcome.INCONCLUSIVE:
        return RequirementVerdict(
            requirement, Status.INCONCLUSIVE, None,
            missing=list(forward.missing) or ["the forward path could not be decided"],
            evidence=forward_evidence,
        )
    if forward.outcome is TraceOutcome.HOP_LIMIT or not forward.reachable:
        return _apply_live(
            RequirementVerdict(
                requirement, Status.DERIVED, False,
                deciding_device=forward.fault_device,
                deciding_interface=forward.fault_interface,
                failure_direction="forward",
                evidence=forward_evidence,
            ),
            live_observation,
        )

    # An ACL on the way out can still drop a forwarded packet.
    acl = evaluate_acls(model, src_router, src_ip, dst_ip, requirement.protocol)
    if acl.action == "deny":
        forward_evidence.append(f"forward path: {acl.detail}")
        return _apply_live(
            RequirementVerdict(
                requirement, Status.DERIVED, False,
                deciding_device=src_router,
                failure_direction="forward",
                evidence=forward_evidence,
            ),
            live_observation,
        )
    forward_evidence.append(f"forward path: {acl.detail}")

    # A same-subnet pair needs no L3 return route, and its VLAN/broadcast-domain
    # status was already checked above.
    if _same_subnet(model, src_ip, dst_ip):
        return _apply_live(
            RequirementVerdict(
                requirement, Status.DERIVED, True,
                deciding_device=src_router,
                deciding_interface=forward.hops[-1].out_interface if forward.hops else None,
                evidence=forward_evidence,
            ),
            live_observation,
        )

    # Return path: a forward path with no reverse is a real and common failure.
    # Trace it independently so the failing direction names itself.
    dst_router = _router_for_address(model, dst_ip) or _device_if_router(model, dst_ip)
    if dst_router is None:
        return RequirementVerdict(
            requirement, Status.INCONCLUSIVE, None,
            missing=[
                f"no router interface serves {dst_ip}",
                ("the return path cannot be evaluated because the destination's "
                "gateway is not modelled"),
            ],
            evidence=forward_evidence,
        )

    back = trace_path(model, dst_ip, src_ip, start_router=dst_router)
    evidence = forward_evidence + [
        f"return path ({dst_ip} -> {src_ip}): {line}" for line in back.evidence()
    ]

    if back.outcome is TraceOutcome.UNSUPPORTED:
        return RequirementVerdict(
            requirement, Status.UNSUPPORTED, None,
            missing=["the return path is not analysable"],
            evidence=evidence,
        )
    if back.outcome is TraceOutcome.INCONCLUSIVE:
        return RequirementVerdict(
            requirement, Status.INCONCLUSIVE, None,
            missing=list(back.missing) or ["the return path could not be decided"],
            evidence=evidence,
        )
    if back.outcome is TraceOutcome.HOP_LIMIT or not back.reachable:
        return _apply_live(
            RequirementVerdict(
                requirement, Status.DERIVED, False,
                deciding_device=back.fault_device,
                deciding_interface=back.fault_interface,
                failure_direction="return",
                evidence=evidence,
            ),
            live_observation,
        )

    return _apply_live(
        RequirementVerdict(
            requirement, Status.DERIVED, True,
            deciding_device=src_router,
            deciding_interface=forward.hops[-1].out_interface if forward.hops else None,
            evidence=evidence,
        ),
        live_observation,
    )


def _apply_live(verdict: RequirementVerdict, observation: bool | None) -> RequirementVerdict:
    """Fold a live observation into a predicted verdict.

    Prediction and observation must agree for `VERIFIED`. They must *disagree*
    for `CONTRADICTED`. With no observation the honest status is `DERIVED`.
    """
    if observation is None:
        verdict.status = Status.DERIVED
        return verdict
    if verdict.reachable == observation:
        verdict.status = Status.VERIFIED
        verdict.evidence.append(
            f"live observation agrees: ping {'succeeded' if observation else 'failed'}"
        )
        return verdict
    verdict.status = Status.CONTRADICTED
    verdict.live_disagrees = True
    verdict.evidence.append(
        f"live observation CONTRADICTS the prediction: ping "
        f"{'succeeded' if observation else 'failed'} but analysis predicted "
        f"{'reachable' if verdict.reachable else 'unreachable'}"
    )
    return verdict


def verify_intent(
    model,
    intent: NetworkIntent,
    observations: dict[str, bool] | None = None,
) -> IntentReport:
    """Verify every requirement, and check that isolation actually holds."""
    observations = observations or {}
    expanded = intent.expand(model)
    report = IntentReport(intent)
    for requirement in expanded:
        key = f"{requirement.src.device}->{requirement.dst.device}"
        report.verdicts.append(
            verify_requirement(model, requirement, observations.get(key))
        )
    # Isolation is the *inverse* requirement: two endpoints that CAN reach each
    # other violate it. They must not be appended as ordinary requirements,
    # because a normal requirement reading "unreachable" is a failure, and here
    # unreachable is the correct outcome.
    for left, right in intent.isolated_pairs:
        for src, dst in ((left, right), (right, left)):
            probe = Requirement(
                src=src, dst=dst,
                description=f"isolation {src.device} !-> {dst.device}",
                required=False,
            )
            verdict = verify_requirement(model, probe, None)
            if verdict.reachable is True:
                # Leak found: report it as a failure, localized to the hop that
                # actually carries the traffic.
                report.verdicts.append(
                    RequirementVerdict(
                        requirement=probe,
                        status=Status.DERIVED,
                        reachable=False,
                        deciding_device=verdict.deciding_device,
                        deciding_interface=verdict.deciding_interface,
                        evidence=[
                            f"isolation violated: {src.device} can reach {dst.device}",
                            *verdict.evidence,
                        ],
                    )
                )
    return report


def _vlan_port(model, host: str) -> tuple[str | None, str | None]:
    """The switch and port serving ``host``, if any."""
    for link in getattr(model, "links", []):
        for local_dev, local_port, peer in (
            (link.device_a, link.interface_a, link.device_b),
            (link.device_b, link.interface_b, link.device_a),
        ):
            if peer != host:
                continue
            iface = model.interfaces.get(f"{local_dev}:{local_port}")
            if iface is not None and getattr(iface, "vlan_assignments", None):
                return local_dev, local_port
    return None, None


def _gateway_problem(model, device: str) -> str | None:
    """A reason this host cannot route off-subnet, or None if its gateway is real.

    Only reports when the gateway is *provably* wrong: it is set, and no
    interface in the model owns that address. An unset gateway is not reported
    here — many labs omit it, and calling that a fault would fire on healthy
    networks whose hosts are not expected to route.
    """
    import ipaddress

    interfaces = [
        i
        for i in getattr(model, "interfaces", {}).values()
        if i.device == device and getattr(i, "ipv4_address", None)
    ]
    if not interfaces:
        return None
    gateway = getattr(interfaces[0], "ipv4_gateway", None)
    if not gateway:
        return None
    try:
        ipaddress.IPv4Address(gateway)
    except ValueError:
        return None
    owners = {
        i.ipv4_address
        for i in getattr(model, "interfaces", {}).values()
        if getattr(i, "ipv4_address", None)
    }
    if gateway in owners:
        return None
    return (
        f"{device} has default gateway {gateway}, which no interface in the "
        "model owns, so off-subnet traffic is discarded"
    )


def _same_subnet(model, left: str, right: str) -> bool:
    """Whether two addresses share a subnet on any modelled interface."""
    import ipaddress

    for interface in getattr(model, "interfaces", {}).values():
        net = None
        address = getattr(interface, "ipv4_address", None)
        prefix = getattr(interface, "prefix_length", None)
        if address and prefix is not None:
            try:
                net = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
            except ValueError:
                net = None
        if net is None:
            continue
        try:
            if ipaddress.IPv4Address(left) in net and ipaddress.IPv4Address(right) in net:
                return True
        except ValueError:
            continue
    return False


def _router_for_address(model, address: str):
    """The *router* whose interface actually serves ``address``'s subnet.

    Delegates to the one implementation in :mod:`trident.engined.reachability`,
    which the path tracer also uses. Two copies of "find the gateway" would drift
    and could disagree about which router owns a path.

    Only routers qualify. An earlier version returned the first interface whose
    subnet contained the address, which could be another host on the same LAN —
    so a ping from PC2 to PC3 was routed from PC1, and a healthy network
    produced a missing-route finding. That is precisely the false positive
    Engine D exists to avoid, so the guard is structural: non-routers are never
    candidates.
    """
    return router_for_address(model, address)


def _device_if_router(model, address: str) -> str | None:
    """The router whose *own* interface address is ``address``, if any.

    ``_router_for_address`` deliberately ignores the exact address so a host is
    never mistaken for a gateway. When a requirement's endpoint *is* a router
    interface, that router is still the right device to ask.
    """
    for interface in getattr(model, "interfaces", {}).values():
        if getattr(interface, "ipv4_address", None) != address:
            continue
        if _is_router_like(model, interface.device):
            return interface.device
    return None


def _uses_dynamic_routing(model) -> bool:
    for info in getattr(model, "devices", {}).values():
        for line in getattr(info, "configuration", None) or ():
            if line.strip().lower().startswith(
                ("router ospf", "router eigrp", "router rip", "router bgp")
            ):
                return True
    return False


def _deciding_from_vlan(model, host: str, path) -> tuple[str | None, str | None]:
    if path.blockers:
        blocker = path.blockers[0]
        if ":" in blocker:
            device, _, rest = blocker.partition(":")
            interface = rest.split()[0] if rest else None
            return device, interface
    return host, None


def explain(verdict: RequirementVerdict) -> str:
    """Prose for a human. Cannot change the status — it only renders it."""
    direction = f"{verdict.requirement.src.device} -> {verdict.requirement.dst.device}"
    if verdict.status is Status.VERIFIED:
        head = f"{direction}: reachable, confirmed by observation."
    elif verdict.status is Status.DERIVED:
        head = (
            f"{direction}: "
            + ("reachable" if verdict.reachable else "NOT reachable")
            + " by configuration analysis; not observed."
        )
    elif verdict.status is Status.CONTRADICTED:
        head = f"{direction}: observation contradicts the analysis."
    elif verdict.status is Status.UNSUPPORTED:
        head = f"{direction}: outside what Engine D models."
    else:
        head = f"{direction}: cannot be decided from the available evidence."
    lines = [head]
    if verdict.deciding_device:
        where = verdict.deciding_device
        if verdict.deciding_interface:
            where += f" {verdict.deciding_interface}"
        lines.append(f"  decided at: {where}")
    for item in verdict.evidence:
        lines.append(f"  - {item}")
    for item in verdict.missing:
        lines.append(f"  missing: {item}")
    return "\n".join(lines)
