"""Operation Broken Campus — an original CyberPatriot-style networking lab.

A three-department school network, deliberately broken in fourteen places. Every
fault is a real misconfiguration a student can find with ``show`` commands, and
everything here is original: no Cisco curriculum topology, no competition
material, no answer key borrowed from anywhere.

Design constraints that shaped it:

* **Two switches, so faults can repeat.** VLAN 10 is misconfigured on the
  distribution switch *and* on an access port. One fault class, two findings,
  which is what forces a student to read per-device output instead of pattern
  matching once and declaring victory.
* **Every fault has an observable ``show`` symptom.** A fault with no symptom is
  a guess, not a lab.
* **Points sum to 100**, weighted by severity, so the rubric is a real score.
"""

from __future__ import annotations

from .spec import (
    DeviceRole,
    DeviceSpec,
    FaultCategory,
    FaultSpec,
    InterfaceSpec,
    LinkSpec,
    Severity,
    TargetKind,
    TopologySpec,
)

# Subnets. One per department, plus a management/transit subnet for the router
# link and a server farm. These are the values an answer key will cite.
ADMIN_NET = "192.168.10.0/24"
STUDENT_NET = "192.168.20.0/24"
FACULTY_NET = "192.168.30.0/24"
TRANSIT_NET = "10.0.0.0/30"
MGMT_NET = "192.168.99.0/24"


def _vlan_line(vlan: int) -> str:
    return f"switchport access vlan {vlan}"


def _access(lines: tuple[str, ...], vlan: int) -> tuple[str, ...]:
    return (*lines, "switchport mode access", _vlan_line(vlan), "no shutdown")


# ---------------------------------------------------------------------------
# Faults
# ---------------------------------------------------------------------------


FAULTS: list[FaultSpec] = [
    # --- addressing -------------------------------------------------------
    FaultSpec(
        fault_id="addr-mask-admin-pc",
        category=FaultCategory.ADDRESSING,
        severity=Severity.MAJOR,
        device="PC-ADMIN-1",
        interface="FastEthernet0",
        description="Administration PC has a /25 mask instead of /24, so its own "
        "subnet range stops at 192.168.10.127 and it cannot reach the gateway.",
        expected="255.255.255.0",
        actual="255.255.255.128",
        symptom="PC-ADMIN-1 can reach no host outside 192.168.10.1-126 and "
        "`ipconfig` shows a 255.255.255.128 mask.",
        points=7,
        hint_1="Compare the mask on the PC against the department subnet in the brief.",
        hint_2="A /24 is 255.255.255.0. A /25 halves the usable range.",
        target=TargetKind.ENDHOST,
        endhost_field="mask",
    ),
    FaultSpec(
        fault_id="addr-router-subif-wrong",
        category=FaultCategory.ADDRESSING,
        severity=Severity.CRITICAL,
        device="R1",
        interface="GigabitEthernet0/0.30",
        description="Faculty subinterface carries the Students address 192.168.20.1, "
        "duplicating VLAN 20's gateway and leaving VLAN 30 with no gateway at all.",
        expected="ip address 192.168.30.1 255.255.255.0",
        actual="ip address 192.168.20.1 255.255.255.0",
        symptom="VLAN 30 PCs have no default gateway reachable; R1 has the same "
        "address on Gi0/0.20 and Gi0/0.30.",
        points=10,
        hint_1="Read every subinterface address on R1 and compare to the subnet table.",
        hint_2="Gi0/0.30 is the Faculty gateway. It should be .30.1, not .20.1.",
    ),
    # --- VLANs ------------------------------------------------------------
    FaultSpec(
        fault_id="vlan-students-port-wrong",
        category=FaultCategory.VLAN,
        severity=Severity.MAJOR,
        device="SW-ACCESS",
        interface="FastEthernet0/3",
        description="PC-STUDENT-2 is a VLAN 20 host but its access port is in VLAN 30.",
        expected=_vlan_line(20),
        actual=_vlan_line(30),
        symptom="PC-STUDENT-2 gets a Faculty-range DHCP address or none, and "
        "`show vlan brief` lists Fa0/3 under VLAN 30.",
        points=6,
        hint_1="Match each access port to the department its PC belongs to.",
        hint_2="PC-STUDENT-2 sits in VLAN 20. Check Fa0/3 on SW-ACCESS.",
    ),
    FaultSpec(
        fault_id="vlan-missing-on-dist",
        category=FaultCategory.VLAN,
        severity=Severity.MAJOR,
        device="SW-DIST",
        interface="Vlan10",
        description="VLAN 10 is never created on the distribution switch, so its "
        "SVI cannot come up and Administration traffic has no L2 path.",
        expected="vlan 10",
        actual="! vlan 10",
        context="vlan 10",
        symptom="`show vlan brief` on SW-DIST has no VLAN 10 entry; the Vlan10 "
        "interface stays down/down.",
        points=6,
        hint_1="List the VLANs on both switches. A VLAN present on one is not enough.",
        hint_2="SW-DIST is missing VLAN 10 entirely.",
        target=TargetKind.BLOCK,
    ),
    FaultSpec(
        fault_id="vlan-faculty-name-only",
        category=FaultCategory.VLAN,
        severity=Severity.MINOR,
        device="SW-ACCESS",
        interface=None,
        description="VLAN 30 exists on SW-ACCESS but is configured as VLAN 30 name "
        "STUDENTS — a naming error that hides the real defect during triage.",
        expected=" name FACULTY",
        actual=" name STUDENTS",
        symptom="`show vlan brief` shows VLAN 30 labelled STUDENTS on SW-ACCESS.",
        points=2,
        hint_1="The VLAN *name* is documentation, but a wrong name misleads triage.",
        hint_2="Faculty is VLAN 30. Check the name on SW-ACCESS.",
        target=TargetKind.CONTEXT_LINE,
        context="vlan 30",
    ),
    # --- trunks -----------------------------------------------------------
    FaultSpec(
        fault_id="trunk-native-mismatch",
        category=FaultCategory.TRUNK,
        severity=Severity.CRITICAL,
        device="SW-ACCESS",
        interface="GigabitEthernet0/1",
        description="The access switch trunk uses native VLAN 1 while SW-DIST uses "
        "99, so untagged frames land in different VLANs on each side.",
        expected="switchport trunk native vlan 99",
        actual="switchport trunk native vlan 1",
        symptom="`show interfaces trunk` reports a native VLAN mismatch; some "
        "untagged traffic is black-holed or leaks between VLANs.",
        points=10,
        hint_1="Compare the native VLAN on both ends of the uplink.",
        hint_2="SW-DIST says 99, SW-ACCESS says 1.",
    ),
    FaultSpec(
        fault_id="trunk-vlan-list-missing",
        category=FaultCategory.TRUNK,
        severity=Severity.MAJOR,
        device="SW-DIST",
        interface="GigabitEthernet0/1",
        description="The dist-to-access trunk does not allow VLAN 30, so Faculty "
        "traffic cannot cross the uplink.",
        expected="switchport trunk allowed vlan 10,20,30,99",
        actual="switchport trunk allowed vlan 10,20,99",
        symptom="`show interfaces trunk` on SW-DIST omits VLAN 30 from the allowed "
        "list; Faculty hosts cannot reach their gateway.",
        points=8,
        hint_1="An allowed-VLAN list that omits a department silently deletes it.",
        hint_2="VLAN 30 is missing from the trunk's allowed list.",
    ),
    # --- routing ----------------------------------------------------------
    FaultSpec(
        fault_id="route-default-wrong-next-hop",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R1",
        interface=None,
        description="The default route points at 10.0.0.6, an address that does not "
        "exist on the /30 transit link.",
        expected="ip route 0.0.0.0 0.0.0.0 10.0.0.2",
        actual="ip route 0.0.0.0 0.0.0.0 10.0.0.6",
        symptom="`show ip route` shows the default via 10.0.0.6; nothing off-campus "
        "is reachable.",
        points=10,
        hint_1="Check that each next hop is on a connected subnet.",
        hint_2="The /30 is 10.0.0.0/30: usable addresses are .1 and .2, not .6.",
        target=TargetKind.GLOBAL_LINE,
    ),
    # --- gateways ---------------------------------------------------------
    FaultSpec(
        fault_id="gw-faculty-pc-wrong",
        category=FaultCategory.GATEWAY,
        severity=Severity.MAJOR,
        device="PC-FACULTY-1",
        interface="FastEthernet0",
        description="Faculty PC's default gateway is 192.168.30.254, which no device "
        "owns, instead of the router subinterface .1.",
        expected="192.168.30.1",
        actual="192.168.30.254",
        symptom="PC-FACULTY-1 pings its own subnet but nothing beyond it.",
        points=6,
        hint_1="A gateway must be an address that exists on the router.",
        hint_2="The Faculty gateway is 192.168.30.1.",
        target=TargetKind.ENDHOST,
        endhost_field="gateway",
    ),
    # --- DHCP -------------------------------------------------------------
    FaultSpec(
        fault_id="dhcp-pool-wrong-network",
        category=FaultCategory.DHCP,
        severity=Severity.CRITICAL,
        device="R1",
        interface=None,
        description="The Students DHCP pool declares network 192.168.200.0/24 — a "
        "typo — so the pool cannot serve 192.168.20.0/24 clients.",
        expected="network 192.168.20.0 255.255.255.0",
        actual="network 192.168.200.0 255.255.255.0",
        symptom="`show ip dhcp pool` shows the wrong network; Students PCs get no "
        "address without a static fallback.",
        points=10,
        hint_1="Compare each pool's network statement with the subnet table.",
        hint_2="192.168.200.0 is not 192.168.20.0. One extra zero.",
        target=TargetKind.CONTEXT_LINE,
        context="ip dhcp pool STUDENTS",
    ),
    FaultSpec(
        fault_id="dhcp-excluded-missing",
        category=FaultCategory.DHCP,
        severity=Severity.MINOR,
        device="R1",
        interface=None,
        description="No address is excluded for the router's own .1 in the "
        "Administration pool, so DHCP can hand the gateway address to a PC.",
        expected="ip dhcp excluded-address 192.168.10.1",
        actual="! ip dhcp excluded-address 192.168.10.1",
        symptom="No excluded-address line in the running config; a client may "
        "receive 192.168.10.1 and duplicate the gateway.",
        points=3,
        hint_1="Reserve infrastructure addresses before the pool can lease them.",
        hint_2="192.168.10.1 belongs to R1 and must be excluded.",
        target=TargetKind.GLOBAL_LINE,
    ),
    # --- DNS --------------------------------------------------------------
    FaultSpec(
        fault_id="dns-server-wrong",
        category=FaultCategory.DNS,
        severity=Severity.MAJOR,
        device="SERVER-1",
        interface=None,
        description="The DNS server resolves for the campus but its own forwarder "
        "points at 8.8.8.8 instead of the campus DNS 192.168.99.10.",
        expected="ip name-server 192.168.99.10",
        actual="ip name-server 8.8.8.8",
        symptom="`show running-config` on SERVER-1 shows an external name-server; "
        "internal names do not resolve for campus clients.",
        points=6,
        hint_1="Internal names must resolve through the campus resolver.",
        hint_2="The campus DNS server is 192.168.99.10.",
        target=TargetKind.GLOBAL_LINE,
    ),
    # --- interfaces -------------------------------------------------------
    FaultSpec(
        fault_id="iface-admin-port-shutdown",
        category=FaultCategory.INTERFACE,
        severity=Severity.MAJOR,
        device="SW-DIST",
        interface="FastEthernet0/1",
        description="The Administration PC's access port is administratively shut "
        "down, so the PC has link at the NIC but no switch port.",
        expected="no shutdown",
        actual="shutdown",
        symptom="`show interfaces status` on SW-DIST lists Fa0/1 as disabled/notconnect.",
        points=6,
        hint_1="A port that is administratively down cannot pass traffic.",
        hint_2="Fa0/1 on SW-DIST is shut down.",
    ),
    # --- security ---------------------------------------------------------
    FaultSpec(
        fault_id="sec-ssh-no-local-user",
        category=FaultCategory.SECURITY,
        severity=Severity.MAJOR,
        device="R1",
        interface=None,
        description="SSH is configured on the vty lines but no local username exists "
        "and `login local` is absent, so remote management is impossible or falls "
        "back to an unauthenticated path.",
        expected="username admin privilege 15 secret CampusAdmin!23",
        actual="! username admin privilege 15 secret CampusAdmin!23",
        symptom="`show run | section line vty` shows `transport input ssh` with no "
        "`login local`; a console-less login cannot authenticate.",
        points=7,
        hint_1="SSH needs an authentication source on the vty lines.",
        hint_2="Create the local user and add `login local` to `line vty 0 4`.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="sec-telnet-permitted",
        category=FaultCategory.SECURITY,
        severity=Severity.MINOR,
        device="SW-DIST",
        interface=None,
        description="The distribution switch's vty lines still permit Telnet "
        "alongside SSH, leaving plaintext management enabled.",
        expected="transport input ssh",
        actual="transport input all",
        symptom="`show run | section line vty` shows `transport input all`.",
        points=3,
        hint_1="Only SSH should be accepted for management.",
        hint_2="`transport input all` allows Telnet.",
        target=TargetKind.GLOBAL_LINE,
    ),
]


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def _sw_globals(hostname: str, mgmt_ip: str) -> tuple[str, ...]:
    """Common switch baseline: VLANs, management SVI, SSH, local user."""
    return (
        f"hostname {hostname}",
        "enable secret Class!23",
        "vlan 10",
        " name ADMIN",
        "vlan 20",
        " name STUDENTS",
        "vlan 30",
        " name FACULTY",
        "vlan 99",
        " name MGMT",
        "interface Vlan99",
        f" ip address {mgmt_ip} 255.255.255.0",
        " no shutdown",
        "ip default-gateway 192.168.99.1",
        "username admin privilege 15 secret CampusAdmin!23",
        "line con 0",
        " logging synchronous",
        "line vty 0 4",
        " login local",
        " transport input ssh",
    )


DEVICES: list[DeviceSpec] = [
    DeviceSpec(
        name="R1",
        model="2911",
        role=DeviceRole.ROUTER,
        x=250,
        y=180,
        globals=(
            "hostname R1",
            "enable secret Class!23",
            "username admin privilege 15 secret CampusAdmin!23",
            "ip dhcp excluded-address 192.168.10.1",
            "ip dhcp excluded-address 192.168.20.1",
            "ip dhcp excluded-address 192.168.30.1",
            "ip dhcp excluded-address 192.168.99.1",
            "ip dhcp pool ADMIN",
            " network 192.168.10.0 255.255.255.0",
            " default-router 192.168.10.1",
            " dns-server 192.168.99.10",
            "ip dhcp pool STUDENTS",
            " network 192.168.20.0 255.255.255.0",
            " default-router 192.168.20.1",
            " dns-server 192.168.99.10",
            "ip dhcp pool FACULTY",
            " network 192.168.30.0 255.255.255.0",
            " default-router 192.168.30.1",
            " dns-server 192.168.99.10",
            "interface GigabitEthernet0/0",
            " no ip address",
            " no shutdown",
        ),
        interfaces=(
            InterfaceSpec(
                name="GigabitEthernet0/0.10",
                lines=("encapsulation dot1Q 10", "ip address 192.168.10.1 255.255.255.0"),
            ),
            InterfaceSpec(
                name="GigabitEthernet0/0.20",
                lines=("encapsulation dot1Q 20", "ip address 192.168.20.1 255.255.255.0"),
            ),
            InterfaceSpec(
                name="GigabitEthernet0/0.99",
                lines=("encapsulation dot1Q 99", "ip address 192.168.99.1 255.255.255.0"),
            ),
            InterfaceSpec(
                name="GigabitEthernet0/0.30",
                lines=("encapsulation dot1Q 30", "ip address 192.168.30.1 255.255.255.0"),
                fault_id="addr-router-subif-wrong",
            ),
            InterfaceSpec(
                name="GigabitEthernet0/1",
                lines=("ip address 10.0.0.1 255.255.255.252", "no shutdown"),
            ),
        ),
        trailing=(
            "ip route 0.0.0.0 0.0.0.0 10.0.0.2",
            "line con 0",
            " logging synchronous",
            "line vty 0 4",
            " login local",
            " transport input ssh",
        ),
    ),
    DeviceSpec(
        name="SW-DIST",
        model="2960-24TT",
        role=DeviceRole.SWITCH,
        x=250,
        y=380,
        globals=_sw_globals("SW-DIST", "192.168.99.2"),
        interfaces=(
            InterfaceSpec(
                name="GigabitEthernet0/1",
                lines=(
                    "switchport mode trunk",
                    "switchport trunk native vlan 99",
                    "switchport trunk allowed vlan 10,20,30,99",
                    "no shutdown",
                ),
                fault_id="trunk-vlan-list-missing",
            ),
            InterfaceSpec(
                name="GigabitEthernet0/2",
                lines=("switchport mode trunk", "switchport trunk native vlan 99", "no shutdown"),
            ),
            InterfaceSpec(
                name="FastEthernet0/1",
                lines=_access((), 10),
                fault_id="iface-admin-port-shutdown",
            ),
            InterfaceSpec(name="FastEthernet0/3", lines=_access((), 10)),
            InterfaceSpec(name="FastEthernet0/5", lines=_access((), 99)),
        ),
    ),
    DeviceSpec(
        name="SW-ACCESS",
        model="2960-24TT",
        role=DeviceRole.SWITCH,
        x=250,
        y=580,
        globals=_sw_globals("SW-ACCESS", "192.168.99.3"),
        interfaces=(
            InterfaceSpec(
                name="GigabitEthernet0/1",
                lines=(
                    "switchport mode trunk",
                    "switchport trunk native vlan 99",
                    "switchport trunk allowed vlan 10,20,30,99",
                    "no shutdown",
                ),
                fault_id="trunk-native-mismatch",
            ),
            InterfaceSpec(name="FastEthernet0/1", lines=_access((), 20)),
            InterfaceSpec(
                name="FastEthernet0/3",
                lines=_access((), 20),
                fault_id="vlan-students-port-wrong",
            ),
            InterfaceSpec(name="FastEthernet0/5", lines=_access((), 30)),
            InterfaceSpec(name="FastEthernet0/7", lines=_access((), 30)),
        ),
    ),
    DeviceSpec(
        name="PC-ADMIN-1",
        model="PC-PT",
        role=DeviceRole.PC,
        x=520,
        y=200,
        pc_ip=("192.168.10.10", "255.255.255.128", "192.168.10.1"),
    ),
    DeviceSpec(
        name="PC-ADMIN-2",
        model="PC-PT",
        role=DeviceRole.PC,
        x=620,
        y=200,
        pc_ip=("192.168.10.11", "255.255.255.0", "192.168.10.1"),
    ),
    DeviceSpec(
        name="PC-STUDENT-1",
        model="PC-PT",
        role=DeviceRole.PC,
        x=520,
        y=320,
        pc_ip=("192.168.20.10", "255.255.255.0", "192.168.20.1"),
    ),
    DeviceSpec(
        name="PC-STUDENT-2",
        model="PC-PT",
        role=DeviceRole.PC,
        x=620,
        y=320,
        pc_ip=("192.168.20.11", "255.255.255.0", "192.168.20.1"),
    ),
    DeviceSpec(
        name="PC-FACULTY-1",
        model="PC-PT",
        role=DeviceRole.PC,
        x=720,
        y=320,
        pc_ip=("192.168.30.10", "255.255.255.0", "192.168.30.254"),
    ),
    DeviceSpec(
        name="PC-FACULTY-2",
        model="PC-PT",
        role=DeviceRole.PC,
        x=820,
        y=320,
        pc_ip=("192.168.30.11", "255.255.255.0", "192.168.30.1"),
    ),
    DeviceSpec(
        name="SERVER-1",
        model="Server-PT",
        role=DeviceRole.SERVER,
        x=820,
        y=200,
        pc_ip=("192.168.99.10", "255.255.255.0", "192.168.99.1"),
        globals=(
            "hostname SERVER-1",
            "no ip domain-lookup",
            "ip name-server 192.168.99.10",
        ),
    ),
]


LINKS: list[LinkSpec] = [
    LinkSpec("R1", "GigabitEthernet0/0", "SW-DIST", "GigabitEthernet0/1"),
    LinkSpec("SW-DIST", "GigabitEthernet0/2", "SW-ACCESS", "GigabitEthernet0/1"),
    # Administration and the server hang off the distribution switch.
    LinkSpec("SW-DIST", "FastEthernet0/1", "PC-ADMIN-1", "FastEthernet0"),
    LinkSpec("SW-DIST", "FastEthernet0/3", "PC-ADMIN-2", "FastEthernet0"),
    LinkSpec("SW-DIST", "FastEthernet0/5", "SERVER-1", "FastEthernet0"),
    # Students and faculty hang off the access switch.
    LinkSpec("SW-ACCESS", "FastEthernet0/1", "PC-STUDENT-1", "FastEthernet0"),
    LinkSpec("SW-ACCESS", "FastEthernet0/3", "PC-STUDENT-2", "FastEthernet0"),
    LinkSpec("SW-ACCESS", "FastEthernet0/5", "PC-FACULTY-1", "FastEthernet0"),
    LinkSpec("SW-ACCESS", "FastEthernet0/7", "PC-FACULTY-2", "FastEthernet0"),
]


BRIEF = """\
OPERATION BROKEN CAMPUS

Northgate Secondary School's network was reconfigured over the summer by a
volunteer who has since left. Staff report that Administration cannot reach the
server, Students cannot get addresses reliably, and Faculty has no internet.
Nothing is on fire — but the campus is one department short of working.

Your job: find and fix every configuration fault.

Departments
  Administration  VLAN 10  192.168.10.0/24   gateway 192.168.10.1
  Students        VLAN 20  192.168.20.0/24   gateway 192.168.20.1
  Faculty         VLAN 30  192.168.30.0/24   gateway 192.168.30.1
  Management      VLAN 99  192.168.99.0/24   router 192.168.99.1
  Server          SERVER-1 192.168.99.10

Required end state
  * Every PC has a correct address, mask and gateway for its department.
  * Inter-VLAN routing works for VLANs 10, 20 and 30.
  * DHCP on R1 serves all three departments with the right gateway and DNS.
  * The dist-to-access uplink carries a single native VLAN on both ends.
  * The trunk allows all four VLANs.
  * R1 has a working default route toward 10.0.0.2.
  * SSH works on R1 and SW-DIST; Telnet is not accepted.
  * SERVER-1 uses the campus DNS server 192.168.99.10.

Rules of engagement
  * Use `show` commands. Every fault is visible from the running configuration.
  * Do not change device names.
  * Do not add new VLANs or subnets.
  * Fix the fault, not the symptom: do not hard-code a static IP to dodge DHCP.
"""


TOPOLOGY = TopologySpec(
    name="operation-broken-campus",
    title="Operation Broken Campus",
    devices=DEVICES,
    links=LINKS,
    faults=FAULTS,
    brief=BRIEF,
    difficulty="intermediate",
)
