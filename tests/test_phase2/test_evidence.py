"""Adversarial tests for operational CLI evidence ingestion.

The contract under test is the honesty contract, not just parsing:

* every supported ``show`` command produces structured data, never prose
* runtime state is never labelled static configuration and vice versa
* no device is invented; no timestamp is invented
* unrecognised text stays unrecognised
* a malformed row is skipped and reported while the rest survives
* two devices pasted together are never merged
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from trident.evidence import (
    SOURCE_BY_KIND,
    CliRecord,
    EvidenceBundle,
    EvidenceKind,
    ObservationSource,
    ParseStatus,
    detect_kind,
    parse_cli_output,
    strip_prompts,
)

# ---------------------------------------------------------------------------
# Samples
# ---------------------------------------------------------------------------

IP_INT_BRIEF = """SW1#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  192.168.1.2     YES NVRAM  up                    up
GigabitEthernet0/1     10.0.0.1        YES manual up                    up
GigabitEthernet0/2     unassigned      YES unset  administratively down down
GigabitEthernet0/3     10.0.0.3        YES manual up                    up
"""

VLAN_BRIEF = """SW1#show vlan brief

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/1, Gi0/2, Gi0/3
10   DATA                             active    Gi0/5, Gi0/6
20   VOICE                            active
1002 fddi-default                     act/unsup
1003 token-ring-default               act/unsup
"""

INTERFACES_TRUNK = """SW1#show interfaces trunk

Port        Mode             Encapsulation  Status        Native vlan
Gi0/24      on               802.1q         trunking      99

Port        Vlans allowed on trunk
Gi0/24      1-10,20

Port        Vlans allowed and active in management domain
Gi0/24      1-10,20

Port        Vlans in spanning tree forwarding state and not pruned
Gi0/24      1-10
"""

IP_ROUTE = """R1#show ip route
Codes: L - local, C - connected, S - static, R - RIP, O - OSPF

Gateway of last resort is 192.168.1.1 to network 0.0.0.0

     10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks
C       10.0.0.0/24 is directly connected, GigabitEthernet0/0
L       10.0.0.1/32 is directly connected, GigabitEthernet0/0
O       10.2.0.0/24 [110/2] via 10.0.0.2, 00:03:41, GigabitEthernet0/0
S*   0.0.0.0/0 [1/0] via 192.168.1.1
"""

ACCESS_LISTS = """R1#show access-lists
Standard IP access list 10
    10 permit 192.168.1.0, wildcard bits 0.0.0.255 (5 matches)
    20 deny any
Extended IP access list BLOCK_WEB
    10 permit tcp any host 10.1.1.5 eq 80 (12 matches)
    20 deny ip any any
"""

OSPF_NEIGHBOR = """R1#show ip ospf neighbor

Neighbor ID     Pri   State           Dead Time   Address         Interface
2.2.2.2           1   FULL/DR         00:00:37    10.0.0.2        GigabitEthernet0/0
3.3.3.3           1   FULL/BDR        00:00:31    10.0.1.2        GigabitEthernet0/1
"""

ETHERCHANNEL_SUMMARY = """SW1#show etherchannel summary
Flags:  D - down        P - bundled in port-channel
        I - stand-alone s - suspended
        H - Hot-standby (LACP only)

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
1      Po1(SU)         LACP      Gi0/1(P)    Gi0/2(P)
2      Po2(SD)         LACP      Gi0/3(D)    Gi0/4(D)
"""

SPANNING_TREE = """SW1#show spanning-tree
VLAN0001
  Spanning tree enabled protocol ieee
  Root ID    Priority    32769
             Address     0011.2233.4455
             This bridge is the root
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32769  (priority 32768 sys-id-ext 1)
             Address     0011.2233.4455
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- --------------------------------
Gi0/1            Desg FWD 4         128.1    P2p
Gi0/2            Root FWD 4         128.2    P2p

VLAN0010
  Spanning tree enabled protocol ieee
  Root ID    Priority    32778
             Address     00aa.bbcc.ddee
             Hello Time   2 sec

  Bridge ID  Priority    32778  (priority 32768 sys-id-ext 10)
             Address     0011.2233.4455

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- --------------------------------
Gi0/24           Root FWD 4         128.24   P2p
"""

RUNNING_CONFIG = """SW1#show running-config
Building configuration...

Current configuration : 1204 bytes
!
version 15.1
service timestamps debug datetime msec
!
hostname SW1
!
interface GigabitEthernet0/1
 description uplink
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
interface Vlan1
 ip address 192.168.1.2 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 192.168.1.1
!
end
"""

_DEVICE = {
    EvidenceKind.IP_INTERFACE_BRIEF: "SW1",
    EvidenceKind.VLAN_BRIEF: "SW1",
    EvidenceKind.INTERFACES_TRUNK: "SW1",
    EvidenceKind.IP_ROUTE: "R1",
    EvidenceKind.ACCESS_LISTS: "R1",
    EvidenceKind.OSPF_NEIGHBOR: "R1",
    EvidenceKind.ETHERCHANNEL_SUMMARY: "SW1",
    EvidenceKind.SPANNING_TREE: "SW1",
}

_SAMPLES = {
    EvidenceKind.IP_INTERFACE_BRIEF: IP_INT_BRIEF,
    EvidenceKind.VLAN_BRIEF: VLAN_BRIEF,
    EvidenceKind.INTERFACES_TRUNK: INTERFACES_TRUNK,
    EvidenceKind.IP_ROUTE: IP_ROUTE,
    EvidenceKind.ACCESS_LISTS: ACCESS_LISTS,
    EvidenceKind.OSPF_NEIGHBOR: OSPF_NEIGHBOR,
    EvidenceKind.ETHERCHANNEL_SUMMARY: ETHERCHANNEL_SUMMARY,
    EvidenceKind.SPANNING_TREE: SPANNING_TREE,
    EvidenceKind.RUNNING_CONFIG: RUNNING_CONFIG,
}


# ---------------------------------------------------------------------------
# 1. Each kind parses real-looking output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(_SAMPLES, key=lambda k: k.value))
def test_each_kind_is_detected_and_parsed(kind: EvidenceKind) -> None:
    record = parse_cli_output(_SAMPLES[kind])
    assert record.kind is kind
    assert record.status is ParseStatus.PARSED, record.notes
    assert record.device == _DEVICE.get(kind, "SW1")
    assert record.parsed, "a PARSED record must carry structured data"
    assert record.notes == ()


def test_ip_interface_brief_structure() -> None:
    record = parse_cli_output(IP_INT_BRIEF)
    rows = record.parsed
    assert rows["Vlan1"] == {
        "ip": "192.168.1.2",
        "ok": "YES",
        "method": "NVRAM",
        "status": "up",
        "protocol": "up",
    }
    assert rows["GigabitEthernet0/2"]["status"] == "administratively down"
    assert rows["GigabitEthernet0/2"]["protocol"] == "down"
    assert set(rows["GigabitEthernet0/1"]) == {"ip", "ok", "method", "status", "protocol"}


def test_vlan_brief_structure() -> None:
    record = parse_cli_output(VLAN_BRIEF)
    vlans = record.parsed
    assert vlans["1"]["name"] == "default"
    assert vlans["1"]["ports"] == ["Gi0/1", "Gi0/2", "Gi0/3"]
    assert vlans["10"]["ports"] == ["Gi0/5", "Gi0/6"]
    assert vlans["20"]["ports"] == []
    assert vlans["1002"]["status"] == "act/unsup"


def test_interfaces_trunk_structure() -> None:
    record = parse_cli_output(INTERFACES_TRUNK)
    trunk = record.parsed["Gi0/24"]
    assert trunk["mode"] == "on"
    assert trunk["encapsulation"] == "802.1q"
    assert trunk["native_vlan"] == 99
    assert trunk["allowed_vlans"] == [str(v) for v in list(range(1, 11)) + [20]]
    assert trunk["active_vlans"] == [str(v) for v in list(range(1, 11)) + [20]]


def test_ip_route_structure() -> None:
    record = parse_cli_output(IP_ROUTE)
    routes = record.parsed
    assert len(routes) == 4
    connected = routes[0]
    assert connected["code"] == "C"
    assert connected["network"] == "10.0.0.0"
    assert connected["mask_or_prefix"] == "24"
    assert connected["interface"] == "GigabitEthernet0/0"
    assert connected["next_hop"] is None
    ospf = routes[2]
    assert ospf["code"] == "O"
    assert ospf["next_hop"] == "10.0.0.2"
    assert ospf["interface"] == "GigabitEthernet0/0"
    assert ospf["metric"] == 2
    default = routes[3]
    assert default["code"] == "S*"
    assert default["network"] == "0.0.0.0"
    assert default["next_hop"] == "192.168.1.1"
    assert default["interface"] is None


def test_access_lists_structure() -> None:
    record = parse_cli_output(ACCESS_LISTS)
    acls = record.parsed
    assert sorted(acls) == ["10", "BLOCK_WEB"]
    standard = acls["10"]
    assert standard[0]["seq"] == 10
    assert standard[0]["action"] == "permit"
    assert standard[0]["protocol"] is None, "a standard ACL has no protocol token"
    assert standard[0]["src"] == "192.168.1.0"
    extended = acls["BLOCK_WEB"]
    assert extended[0]["protocol"] == "tcp"
    assert extended[0]["src"] == "any"
    assert "host 10.1.1.5" in extended[0]["dst"]
    assert extended[1]["action"] == "deny"


def test_ospf_neighbor_structure() -> None:
    record = parse_cli_output(OSPF_NEIGHBOR)
    neighbors = record.parsed
    assert [n["neighbor_id"] for n in neighbors] == ["2.2.2.2", "3.3.3.3"]
    assert neighbors[0]["priority"] == 1
    assert neighbors[0]["state"] == "FULL/DR"
    assert neighbors[0]["dead_time"] == "00:00:37"
    assert neighbors[0]["address"] == "10.0.0.2"
    assert neighbors[1]["interface"] == "GigabitEthernet0/1"


def test_etherchannel_summary_structure() -> None:
    record = parse_cli_output(ETHERCHANNEL_SUMMARY)
    groups = record.parsed
    assert [g["group"] for g in groups] == [1, 2]
    assert groups[0]["protocol"] == "LACP"
    assert groups[0]["flags"] == "SU"
    assert groups[0]["ports"] == ["Gi0/1(P)", "Gi0/2(P)"]
    assert groups[1]["flags"] == "SD"


def test_spanning_tree_structure() -> None:
    record = parse_cli_output(SPANNING_TREE)
    stp = record.parsed
    assert sorted(stp, key=int) == ["1", "10"]
    vlan1 = stp["1"]
    assert vlan1["root_id"] == "0011.2233.4455"
    assert vlan1["bridge_id"] == "0011.2233.4455"
    assert [i["interface"] for i in vlan1["interfaces"]] == ["Gi0/1", "Gi0/2"]
    assert vlan1["interfaces"][1]["role"] == "Root"
    vlan10 = stp["10"]
    assert vlan10["root_id"] == "00aa.bbcc.ddee"
    assert vlan10["interfaces"][0]["interface"] == "Gi0/24"


def test_running_config_structure() -> None:
    record = parse_cli_output(RUNNING_CONFIG)
    cfg = record.parsed
    assert cfg["hostname"] == "SW1"
    assert cfg["ios_version"] == "15.1"
    iface = cfg["interfaces"]["GigabitEthernet0/1"]
    assert iface["switchport_mode"] == "trunk"
    assert iface["trunk_allowed"] == ["10", "20"]
    assert cfg["interfaces"]["Vlan1"]["ipv4_address"] == "192.168.1.2"
    assert record.parsed["lines"][0] == "Building configuration..."


# ---------------------------------------------------------------------------
# 2. Runtime vs static classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,expected",
    [
        (EvidenceKind.RUNNING_CONFIG, ObservationSource.STATIC_CONFIG),
        (EvidenceKind.IP_INTERFACE_BRIEF, ObservationSource.RUNTIME_STATE),
        (EvidenceKind.VLAN_BRIEF, ObservationSource.RUNTIME_STATE),
        (EvidenceKind.INTERFACES_TRUNK, ObservationSource.RUNTIME_STATE),
        (EvidenceKind.IP_ROUTE, ObservationSource.RUNTIME_STATE),
        (EvidenceKind.SPANNING_TREE, ObservationSource.RUNTIME_STATE),
        (EvidenceKind.ETHERCHANNEL_SUMMARY, ObservationSource.RUNTIME_STATE),
        (EvidenceKind.ACCESS_LISTS, ObservationSource.RUNTIME_STATE),
        (EvidenceKind.OSPF_NEIGHBOR, ObservationSource.RUNTIME_STATE),
    ],
)
def test_source_classification(kind: EvidenceKind, expected: ObservationSource) -> None:
    assert SOURCE_BY_KIND[kind] is expected
    record = parse_cli_output(_SAMPLES[kind])
    assert record.kind is kind
    assert record.source is expected


def test_runtime_show_command_is_never_static_config() -> None:
    for kind, text in _SAMPLES.items():
        if kind is EvidenceKind.RUNNING_CONFIG:
            continue
        assert parse_cli_output(text).source is ObservationSource.RUNTIME_STATE


def test_record_rejects_a_lying_source() -> None:
    with pytest.raises(ValueError, match="must be sourced from"):
        CliRecord(
            device="SW1",
            kind=EvidenceKind.IP_ROUTE,
            source=ObservationSource.STATIC_CONFIG,
            captured_at=None,
            raw_text="",
            parsed=[],
            status=ParseStatus.PARSED,
            notes=(),
            line_count=0,
        )


# ---------------------------------------------------------------------------
# 3. No device supplied -> device is None, PARTIAL, no invention
# ---------------------------------------------------------------------------


def test_no_device_supplied_is_unattributed_and_partial() -> None:
    body = "\n".join(IP_INT_BRIEF.splitlines()[1:])
    record = parse_cli_output(body)
    assert record.device is None
    assert record.status is ParseStatus.PARTIAL
    assert any("unattributed" in note for note in record.notes)
    # The rows still parse: absence of attribution is not absence of evidence.
    assert "GigabitEthernet0/1" in record.parsed


def test_no_device_never_defaults_to_a_name() -> None:
    for text in _SAMPLES.values():
        stripped = "\n".join(line for line in text.splitlines() if "#" not in line)
        record = parse_cli_output(stripped)
        assert record.device is None, f"invented device for sample: {record.device!r}"


def test_supplied_device_is_carried_through() -> None:
    body = "\n".join(IP_INT_BRIEF.splitlines()[1:])
    record = parse_cli_output(body, device="CORE-SW")
    assert record.device == "CORE-SW"
    assert record.status is ParseStatus.PARSED


def test_unattributed_record_cannot_claim_parsed() -> None:
    with pytest.raises(ValueError, match="cannot claim PARSED"):
        CliRecord(
            device=None,
            kind=EvidenceKind.IP_ROUTE,
            source=ObservationSource.RUNTIME_STATE,
            captured_at=None,
            raw_text="",
            parsed=[],
            status=ParseStatus.PARSED,
            notes=(),
            line_count=0,
        )


# ---------------------------------------------------------------------------
# 4. Garbage -> UNKNOWN / UNRECOGNISED
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   \n  \n",
        "hello world",
        "this is not a cisco command at all",
        "Traceback (most recent call last):\n  File \"x.py\"",
        "%% Invalid input detected at '^' marker.",
    ],
)
def test_garbage_is_unrecognised(text: str) -> None:
    record = parse_cli_output(text, device="R1")
    assert record.kind is EvidenceKind.UNKNOWN
    assert record.status is ParseStatus.UNRECOGNISED
    assert record.parsed == {}
    assert record.source is ObservationSource.RUNTIME_STATE
    assert detect_kind(text)[0] is EvidenceKind.UNKNOWN


def test_unknown_kind_cannot_carry_data() -> None:
    with pytest.raises(ValueError, match="never carry parsed data"):
        CliRecord(
            device="R1",
            kind=EvidenceKind.UNKNOWN,
            source=ObservationSource.RUNTIME_STATE,
            captured_at=None,
            raw_text="x",
            parsed={"x": 1},
            status=ParseStatus.UNRECOGNISED,
            notes=(),
            line_count=1,
        )


def test_detect_kind_confidence_bounds() -> None:
    for text in [*_SAMPLES.values(), "garbage"]:
        kind, confidence = detect_kind(text)
        assert isinstance(kind, EvidenceKind)
        assert 0.0 <= confidence <= 1.0
    assert detect_kind("garbage")[1] == 0.0
    assert detect_kind(IP_ROUTE)[1] >= 0.9


# ---------------------------------------------------------------------------
# 5. Truncated show ip int brief -> PARTIAL, good rows survive
# ---------------------------------------------------------------------------


def test_truncated_interface_line_is_skipped() -> None:
    text = """SW1#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     10.0.0.1        YES manual up                    up
GigabitEthernet0/2     10.0.0.2        YES
GigabitEthernet0/3     10.0.0.3        YES manual up                    up
"""
    record = parse_cli_output(text)
    assert record.status is ParseStatus.PARTIAL
    assert any("GigabitEthernet0/2" in note for note in record.notes)
    assert set(record.parsed) == {"GigabitEthernet0/1", "GigabitEthernet0/3"}
    assert record.parsed["GigabitEthernet0/3"]["ip"] == "10.0.0.3"


def test_partial_record_must_explain_itself() -> None:
    with pytest.raises(ValueError, match="at least one explanatory note"):
        CliRecord(
            device="SW1",
            kind=EvidenceKind.IP_ROUTE,
            source=ObservationSource.RUNTIME_STATE,
            captured_at=None,
            raw_text="",
            parsed=[],
            status=ParseStatus.PARTIAL,
            notes=(),
            line_count=0,
        )


# ---------------------------------------------------------------------------
# 6. Two devices pasted together are never merged
# ---------------------------------------------------------------------------


def test_two_devices_are_never_merged() -> None:
    text = """R1#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
Gi0/0                  10.0.0.1        YES manual up                    up
R2#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
Gi0/0                  10.0.0.2        YES manual up                    up
"""
    record = parse_cli_output(text)
    assert record.device is None
    assert record.status is ParseStatus.PARTIAL
    assert record.parsed == {}, "two devices must never be merged into one result"
    assert any("several devices" in note for note in record.notes)


def test_two_devices_stay_separate_when_supplied() -> None:
    text = """R1#show ip interface brief
Gi0/0                  10.0.0.1        YES manual up                    up
R2#show ip interface brief
Gi0/0                  10.0.0.2        YES manual up                    up
"""
    record = parse_cli_output(text, device="R1")
    # The caller asserted a device, but the paste still holds two devices.
    assert record.device is None
    assert record.parsed == {}


def test_bundle_keeps_devices_separate() -> None:
    bundle = EvidenceBundle()
    bundle.add(parse_cli_output(IP_INT_BRIEF))
    bundle.add(parse_cli_output(IP_ROUTE))
    bundle.add(parse_cli_output(IP_INT_BRIEF, device="SW2"))

    # R1 comes from the route paste's own prompt; nothing was merged.
    assert bundle.devices() == ("R1", "SW1", "SW2")
    assert len(bundle.for_device("SW1")) == 1
    assert len(bundle.for_device("SW2")) == 1
    assert bundle.for_device("SW2")[0].device == "SW2"
    assert bundle.runtime_routes("SW1") == []
    assert len(bundle.runtime_routes("R1")) == 4
    assert bundle.runtime_interfaces("SW2")


def test_bundle_never_merges_unattributed_into_a_device() -> None:
    bundle = EvidenceBundle()
    body = "\n".join(IP_INT_BRIEF.splitlines()[1:])
    bundle.add(parse_cli_output("R1#show ip route\n" + IP_ROUTE.split("\n", 1)[1]))
    bundle.add(parse_cli_output(body))

    assert bundle.unattributed()
    assert bundle.for_device("R1")
    assert len(bundle.runtime_interfaces("R1")) == 0, "unattributed rows must not leak"
    assert bundle.runtime_routes("R1")


# ---------------------------------------------------------------------------
# 7. Timestamp is never invented
# ---------------------------------------------------------------------------


def test_timestamp_is_none_when_not_supplied() -> None:
    for text in _SAMPLES.values():
        assert parse_cli_output(text).captured_at is None


def test_timestamp_is_carried_verbatim() -> None:
    stamp = "2026-11-08T06:48:07Z"
    assert parse_cli_output(IP_ROUTE, captured_at=stamp).captured_at == stamp
    # A caller-supplied value is never normalised or re-formatted.
    odd = "yesterday, roughly 3pm"
    assert parse_cli_output(IP_ROUTE, captured_at=odd).captured_at == odd


# ---------------------------------------------------------------------------
# 8. Prompt-derived device detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prompt,expected",
    [
        ("Router#", "Router"),
        ("SW1(config)#", "SW1"),
        ("R1>", "R1"),
        ("core-sw-01#", "core-sw-01"),
        ("R1#show ip route", "R1"),
        ("edge.router.lab# ", "edge.router.lab"),
    ],
)
def test_prompt_derived_device(prompt: str, expected: str) -> None:
    text = f"{prompt}\nGateway of last resort is 192.168.1.1 to network 0.0.0.0\n"
    record = parse_cli_output(text)
    assert record.device == expected


def test_strip_prompts_removes_prompt_and_echo() -> None:
    body, devices, echoes = strip_prompts("SW1#show vlan brief\nrest of output")
    assert body == ["rest of output"]
    assert devices == ["SW1"]
    assert echoes == ["show vlan brief"]


def test_repeated_prompt_for_one_device_is_still_one_device() -> None:
    text = """SW1#terminal length 0
SW1#show ip route
Gateway of last resort is 192.168.1.1 to network 0.0.0.0
"""
    record = parse_cli_output(text)
    assert record.device == "SW1"


def test_supplied_device_wins_and_conflict_is_noted() -> None:
    record = parse_cli_output(IP_ROUTE, device="CORE1")
    assert record.device == "CORE1"
    assert any("conflicts with prompt device" in note for note in record.notes)
    assert record.status is ParseStatus.PARTIAL


# ---------------------------------------------------------------------------
# 9. Malformed route line skipped, others parsed
# ---------------------------------------------------------------------------


def test_malformed_route_line_is_skipped() -> None:
    text = """R1#show ip route
Gateway of last resort is 192.168.1.1 to network 0.0.0.0
C       10.0.0.0/24 is directly connected, GigabitEthernet0/0
S       10.5.0.0/16 [1/0] via
O       10.2.0.0/24 [110/2] via 10.0.0.2, 00:03:41, GigabitEthernet0/0
S*   0.0.0.0/0 [1/0] via 192.168.1.1
"""
    record = parse_cli_output(text)
    assert record.status is ParseStatus.PARTIAL
    assert any("malformed route" in note for note in record.notes)
    networks = [route["network"] for route in record.parsed]
    assert networks == ["10.0.0.0", "10.2.0.0", "0.0.0.0"]
    assert record.parsed[1]["next_hop"] == "10.0.0.2"


def test_route_codes_legend_never_becomes_a_route() -> None:
    record = parse_cli_output(IP_ROUTE, device="R1")
    for route in record.parsed:
        assert route["code"] in {"C", "L", "O", "S*"}
        assert route["network"] != "0.0.0.0" or route["code"] == "S*"


# ---------------------------------------------------------------------------
# 10. Bundle typed views
# ---------------------------------------------------------------------------


def test_bundle_typed_views() -> None:
    bundle = EvidenceBundle()
    bundle.add(parse_cli_output(RUNNING_CONFIG))
    bundle.add(parse_cli_output(IP_INT_BRIEF))
    bundle.add(parse_cli_output(IP_ROUTE))

    interfaces = bundle.runtime_interfaces("SW1")
    assert interfaces["GigabitEthernet0/1"]["ip"] == "10.0.0.1"

    assert bundle.runtime_routes("SW1") == []
    assert bundle.static_config("SW1")[0] == "Building configuration..."
    assert any(line == "hostname SW1" for line in bundle.static_config("SW1"))


def test_bundle_by_kind_spans_devices() -> None:
    bundle = EvidenceBundle()
    bundle.add(parse_cli_output(IP_INT_BRIEF))
    bundle.add(parse_cli_output(IP_INT_BRIEF, device="SW2"))
    assert len(bundle.by_kind(EvidenceKind.IP_INTERFACE_BRIEF)) == 2
    assert bundle.by_kind(EvidenceKind.VLAN_BRIEF) == ()


def test_bundle_latest_record_wins() -> None:
    bundle = EvidenceBundle()
    bundle.add(parse_cli_output(IP_INT_BRIEF))
    newer = """SW1#show ip interface brief
Gi0/1                  10.9.9.9        YES manual up                    up
"""
    bundle.add(parse_cli_output(newer))
    assert bundle.runtime_interfaces("SW1") == {
        "Gi0/1": {"ip": "10.9.9.9", "ok": "YES", "method": "manual", "status": "up", "protocol": "up"}
    }


def test_bundle_unknown_device_returns_empty() -> None:
    bundle = EvidenceBundle()
    bundle.add(parse_cli_output(IP_INT_BRIEF))
    assert bundle.for_device("NOPE") == ()
    assert bundle.runtime_interfaces("NOPE") == {}
    assert bundle.runtime_routes("NOPE") == []
    assert bundle.static_config("NOPE") == []


# ---------------------------------------------------------------------------
# 11. Line counting and raw preservation
# ---------------------------------------------------------------------------


def test_raw_text_and_line_count_are_verbatim() -> None:
    record = parse_cli_output(IP_INT_BRIEF)
    assert record.raw_text == IP_INT_BRIEF
    assert record.line_count == len(IP_INT_BRIEF.splitlines())

    stripped_input = IP_INT_BRIEF.replace("\n", "\r\n")
    record_crlf = parse_cli_output(stripped_input)
    assert record_crlf.line_count == len(stripped_input.splitlines())
    assert record_crlf.kind is EvidenceKind.IP_INTERFACE_BRIEF


def test_records_are_immutable() -> None:
    record = parse_cli_output(IP_INT_BRIEF)
    with pytest.raises(FrozenInstanceError):
        record.device = "OTHER"  # type: ignore[misc]
    assert isinstance(record.notes, tuple)
