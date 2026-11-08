"""Built-in scenario catalogue for the fault-injection practice laboratory.

.. warning::

   **These scenarios are synthetic.** They are constructed in memory from
   ``faultlab.baseline_lab()``. They are *not* Packet Tracer ``.pkt``/``.pka``
   files, not captures of real equipment, and not parser fixtures. The topology
   and addressing are invented so that each defect has exactly one known cause.

Every scenario is single-fault except ``"dual-shutdown-gateway"``, whose
``single_fault`` flag is ``False``.
"""

from __future__ import annotations

from .inject import inject, inject_many
from .types import Fault, FaultKind, Scenario

# ---------------------------------------------------------------------------
# Single-fault definitions
# ---------------------------------------------------------------------------

_SINGLE: tuple[tuple[str, Fault], ...] = (
    (
        "wrong-vlan",
        Fault(
            fault_id="wrong-vlan-01",
            kind=FaultKind.WRONG_VLAN,
            device="SW2",
            interface="FastEthernet0/1",
            description=(
                "PC1 is cabled to SW2 Fa0/1, but the port is in VLAN 30 instead of "
                "the user VLAN 20."
            ),
            expected_symptom=(
                "PC1 (10.10.20.10) cannot reach PC2 or the gateway 10.10.20.1; "
                "its port reports VLAN 30 while its IP belongs to VLAN 20."
            ),
        ),
    ),
    (
        "invalid-mask",
        Fault(
            fault_id="invalid-mask-01",
            kind=FaultKind.INVALID_MASK,
            device="R2",
            interface="GigabitEthernet0/1",
            description=(
                "R2 Gi0/1 (the LAN gateway) carries a non-contiguous mask "
                "255.255.0.255, which is not a legal subnet mask."
            ),
            expected_symptom=(
                "The LAN gateway address 10.10.20.1 has an unusable mask, so no "
                "prefix length can be derived and hosts appear to be off-subnet."
            ),
        ),
    ),
    (
        "wrong-gateway",
        Fault(
            fault_id="wrong-gateway-01",
            kind=FaultKind.WRONG_GATEWAY,
            device="PC1",
            interface=None,
            description="PC1 is configured with default gateway 10.10.20.254 instead of 10.10.20.1.",
            expected_symptom=(
                "PC1 can reach local VLAN 20 hosts but cannot reach any remote "
                "subnet; its gateway address is not a live LAN interface."
            ),
        ),
    ),
    (
        "missing-static-route",
        Fault(
            fault_id="missing-static-route-01",
            kind=FaultKind.MISSING_STATIC_ROUTE,
            device="R1",
            interface=None,
            description="R1 has lost the static route to 10.10.20.0/24 via 10.10.10.2.",
            expected_symptom=(
                "The WAN side of R1 cannot reach the VLAN 20 LAN; there is no "
                "route for 10.10.20.0/24 on R1, only a default route."
            ),
        ),
    ),
    (
        "shutdown-interface",
        Fault(
            fault_id="shutdown-interface-01",
            kind=FaultKind.SHUTDOWN_INTERFACE,
            device="SW2",
            interface="FastEthernet0/2",
            description="SW2 Fa0/2, the port serving PC2, is administratively shut down.",
            expected_symptom=(
                "PC2 is isolated: its switch port is administratively down and "
                "the link never comes up."
            ),
        ),
    ),
    (
        "acl-block",
        Fault(
            fault_id="acl-block-01",
            kind=FaultKind.ACL_BLOCK,
            device="R2",
            interface="GigabitEthernet0/1",
            description=(
                "An extended ACL (101) bound inbound on R2 Gi0/1 denies TCP/443 to "
                "the server 10.10.20.50."
            ),
            expected_symptom=(
                "ICMP and other traffic to SRV1 works, but HTTPS to 10.10.20.50 "
                "is silently dropped at R2."
            ),
        ),
    ),
    (
        "trunk-mismatch",
        Fault(
            fault_id="trunk-mismatch-01",
            kind=FaultKind.TRUNK_MISMATCH,
            device="SW2",
            interface="GigabitEthernet0/1",
            description=(
                "SW2 Gi0/1 is a trunk that allows VLANs 10 and 30 but not 20, "
                "while the peer SW1 trunk allows 10, 20 and 30."
            ),
            expected_symptom=(
                "VLAN 20 hosts behind SW2 cannot reach VLAN 20 hosts on the other "
                "side of the trunk; the allowed-VLAN lists disagree."
            ),
        ),
    ),
    (
        "routing-loop",
        Fault(
            fault_id="routing-loop-01",
            kind=FaultKind.ROUTING_LOOP,
            device="R2",
            interface=None,
            description=(
                "R2 has a static route for 10.10.10.0/24 pointing at 10.10.20.1, "
                "which sends packets for the transit network back into the LAN."
            ),
            expected_symptom=(
                "Traffic for 10.10.10.0/24 bounces between R1 and R2 and dies; "
                "traceroute repeats the same two hops."
            ),
        ),
    ),
    (
        "dhcp-misconfiguration",
        Fault(
            fault_id="dhcp-misconfiguration-01",
            kind=FaultKind.DHCP_MISCONFIGURATION,
            device="R2",
            interface=None,
            description="The LAN-POOL DHCP gateway is 10.10.20.254 instead of 10.10.20.1.",
            expected_symptom=(
                "DHCP clients get an address but no working default gateway, so "
                "they reach only their own subnet."
            ),
        ),
    ),
    (
        "duplicate-ip",
        Fault(
            fault_id="duplicate-ip-01",
            kind=FaultKind.DUPLICATE_IP,
            device="PC2",
            interface="FastEthernet0",
            description="PC2 is configured with 10.10.20.10, the address already owned by PC1.",
            expected_symptom=(
                "Two hosts claim 10.10.20.10; ARP replies flap and connectivity to "
                "either host is intermittent."
            ),
        ),
    ),
    (
        "overlapping-subnet",
        Fault(
            fault_id="overlapping-subnet-01",
            kind=FaultKind.OVERLAPPING_SUBNET,
            device="R2",
            interface="Loopback0",
            description=(
                "R2 Loopback0 is 10.10.20.129/25, which overlaps the LAN subnet "
                "10.10.20.0/24 configured on R2 Gi0/1."
            ),
            expected_symptom=(
                "R2 has two connected interfaces whose networks overlap; routes "
                "for 10.10.20.0/24 are ambiguous and return traffic misdirects."
            ),
        ),
    ),
)

_MULTI: tuple[tuple[str, tuple[Fault, ...]], ...] = (
    (
        "dual-shutdown-gateway",
        (
            Fault(
                fault_id="shutdown-interface-02",
                kind=FaultKind.SHUTDOWN_INTERFACE,
                device="SW2",
                interface="FastEthernet0/3",
                description="SW2 Fa0/3, the port serving SRV1, is administratively shut down.",
                expected_symptom="SRV1 is isolated; its switch port is administratively down.",
            ),
            Fault(
                fault_id="wrong-gateway-02",
                kind=FaultKind.WRONG_GATEWAY,
                device="PC2",
                interface=None,
                description="PC2 is configured with default gateway 10.10.20.254.",
                expected_symptom=(
                    "PC2 reaches local hosts but no remote subnet, because its "
                    "gateway is not a live LAN interface."
                ),
            ),
        ),
    ),
)


def _scenario(name: str, faults: tuple[Fault, ...], single: bool) -> Scenario:
    model = inject(faults[0]) if single else inject_many(faults)
    return Scenario(name=name, model=model, faults=faults, single_fault=single)


def scenarios() -> tuple[Scenario, ...]:
    """Return the built-in catalogue: eleven single-fault and one two-fault case.

    A new tuple of fresh ``Scenario`` objects is built on every call, so callers
    may mutate the models without contaminating one another.
    """
    built = [_scenario(name, (fault,), True) for name, fault in _SINGLE]
    built.extend(_scenario(name, faults, False) for name, faults in _MULTI)
    return tuple(built)
