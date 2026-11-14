# Instructor key — Operation Broken Campus

Lab: `operation-broken-campus`  |  difficulty: intermediate
Student score: 0/100

## Faults

| id | device | interface | category | pts | expected | actual |
|---|---|---|---|---|---|---|
| addr-mask-admin-pc | PC-ADMIN-1 | FastEthernet0 | addressing | 7 | `255.255.255.0` | `255.255.255.128` |
| addr-router-subif-wrong | R1 | GigabitEthernet0/0.30 | addressing | 10 | `ip address 192.168.30.1 255.255.255.0` | `ip address 192.168.20.1 255.255.255.0` |
| vlan-students-port-wrong | SW-ACCESS | FastEthernet0/3 | vlan | 6 | `switchport access vlan 20` | `switchport access vlan 30` |
| vlan-missing-on-dist | SW-DIST | Vlan10 | vlan | 6 | `vlan 10` | `! vlan 10` |
| vlan-faculty-port-wrong | SW-ACCESS | FastEthernet0/5 | vlan | 2 | `switchport access vlan 30` | `switchport access vlan 20` |
| trunk-native-mismatch | SW-ACCESS | GigabitEthernet0/1 | trunk | 10 | `switchport trunk native vlan 99` | `switchport trunk native vlan 1` |
| trunk-vlan-list-missing | SW-DIST | GigabitEthernet0/1 | trunk | 8 | `switchport trunk allowed vlan 10,20,30,99` | `switchport trunk allowed vlan 10,20,99` |
| route-default-wrong-next-hop | R1 | — | routing | 10 | `ip route 0.0.0.0 0.0.0.0 10.0.0.2` | `ip route 0.0.0.0 0.0.0.0 10.0.0.6` |
| gw-faculty-pc-wrong | PC-FACULTY-1 | FastEthernet0 | gateway | 6 | `192.168.30.1` | `192.168.30.254` |
| dhcp-pool-wrong-network | R1 | — | dhcp | 10 | `network 192.168.20.0 255.255.255.0` | `network 192.168.200.0 255.255.255.0` |
| dhcp-excluded-missing | R1 | — | dhcp | 3 | `ip dhcp excluded-address 192.168.10.1` | `! ip dhcp excluded-address 192.168.10.1` |
| dhcp-pool-missing-dns | R1 | — | dns | 6 | ` dns-server 192.168.99.10` | `! dns-server 192.168.99.10` |
| iface-admin-port-shutdown | SW-DIST | FastEthernet0/1 | interface | 6 | `no shutdown` | `shutdown` |
| sec-ssh-no-local-user | R1 | — | security | 7 | `username admin privilege 15 secret CampusAdmin!23` | `! username admin privilege 15 secret CampusAdmin!23` |
| sec-enable-secret-missing | SW-ACCESS | — | security | 3 | `enable secret Class!23` | `! enable secret Class!23` |

## Why each fault breaks something

### addr-mask-admin-pc (major)

Administration PC has a /25 mask instead of /24, so its own subnet range stops at 192.168.10.127 and it cannot reach the gateway.

**Symptom:** PC-ADMIN-1 can reach no host outside 192.168.10.1-126 and `ipconfig` shows a 255.255.255.128 mask.

### addr-router-subif-wrong (critical)

Faculty subinterface carries the Students address 192.168.20.1, duplicating VLAN 20's gateway and leaving VLAN 30 with no gateway at all.

**Symptom:** VLAN 30 PCs have no default gateway reachable; R1 has the same address on Gi0/0.20 and Gi0/0.30.

### vlan-students-port-wrong (major)

PC-STUDENT-2 is a VLAN 20 host but its access port is in VLAN 30.

**Symptom:** PC-STUDENT-2 gets a Faculty-range DHCP address or none, and `show vlan brief` lists Fa0/3 under VLAN 30.

### vlan-missing-on-dist (major)

VLAN 10 is never created on the distribution switch, so its SVI cannot come up and Administration traffic has no L2 path.

**Symptom:** `show vlan brief` on SW-DIST has no VLAN 10 entry; the Vlan10 interface stays down/down.

### vlan-faculty-port-wrong (minor)

PC-FACULTY-1's access port is in VLAN 20 (Students) instead of VLAN 30 (Faculty).

**Symptom:** `show vlan brief` lists Fa0/5 under VLAN 20; PC-FACULTY-1 gets a Students address or none.

### trunk-native-mismatch (critical)

The access switch trunk uses native VLAN 1 while SW-DIST uses 99, so untagged frames land in different VLANs on each side.

**Symptom:** `show interfaces trunk` reports a native VLAN mismatch; some untagged traffic is black-holed or leaks between VLANs.

### trunk-vlan-list-missing (major)

The dist-to-access trunk does not allow VLAN 30, so Faculty traffic cannot cross the uplink.

**Symptom:** `show interfaces trunk` on SW-DIST omits VLAN 30 from the allowed list; Faculty hosts cannot reach their gateway.

### route-default-wrong-next-hop (critical)

The default route points at 10.0.0.6, an address that does not exist on the /30 transit link.

**Symptom:** `show ip route` shows the default via 10.0.0.6; nothing off-campus is reachable.

### gw-faculty-pc-wrong (major)

Faculty PC's default gateway is 192.168.30.254, which no device owns, instead of the router subinterface .1.

**Symptom:** PC-FACULTY-1 pings its own subnet but nothing beyond it.

### dhcp-pool-wrong-network (critical)

The Students DHCP pool declares network 192.168.200.0/24 — a typo — so the pool cannot serve 192.168.20.0/24 clients.

**Symptom:** `show ip dhcp pool` shows the wrong network; Students PCs get no address without a static fallback.

### dhcp-excluded-missing (minor)

No address is excluded for the router's own .1 in the Administration pool, so DHCP can hand the gateway address to a PC.

**Symptom:** No excluded-address line in the running config; a client may receive 192.168.10.1 and duplicate the gateway.

### dhcp-pool-missing-dns (major)

The Students DHCP pool omits `dns-server`, so Students PCs receive no resolver while other departments do.

**Symptom:** `show ip dhcp pool STUDENTS` has no DNS option; Students PCs get an address but cannot resolve names.

### iface-admin-port-shutdown (major)

The Administration PC's access port is administratively shut down, so the PC has link at the NIC but no switch port.

**Symptom:** `show interfaces status` on SW-DIST lists Fa0/1 as disabled/notconnect.

### sec-ssh-no-local-user (major)

SSH is configured on the vty lines but no local username exists and `login local` is absent, so remote management is impossible or falls back to an unauthenticated path.

**Symptom:** `show run | section line vty` shows `transport input ssh` with no `login local`; a console-less login cannot authenticate.

### sec-enable-secret-missing (minor)

SW-ACCESS has no enable secret, so privileged EXEC is reachable without an encrypted password.

**Symptom:** `show running-config` on SW-ACCESS has no `enable secret` line; `enable` prompts for nothing.

