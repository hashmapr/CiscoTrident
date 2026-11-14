# Operation Broken Campus — Student Brief

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


## Objectives

Each objective is worth the points shown. Every fault is
visible from a `show` command; none requires guessing.

| Objective | Points | What must be true |
|---|---|---|
| `obj-addressing-01` | 7 | Device addressing is correct for its subnet |
| `obj-addressing-02` | 10 | Device addressing is correct for its subnet |
| `obj-vlan-03` | 6 | VLAN membership matches the department plan |
| `obj-vlan-04` | 6 | VLAN membership matches the department plan |
| `obj-vlan-05` | 2 | VLAN membership matches the department plan |
| `obj-trunk-06` | 10 | The trunk carries every VLAN with one native VLAN |
| `obj-trunk-07` | 8 | The trunk carries every VLAN with one native VLAN |
| `obj-routing-08` | 10 | Routing reaches every required destination |
| `obj-gateway-09` | 6 | Every host has a reachable default gateway |
| `obj-dhcp-10` | 10 | DHCP serves each department correctly |
| `obj-dhcp-11` | 3 | DHCP serves each department correctly |
| `obj-dns-12` | 6 | Name resolution is configured for every pool |
| `obj-interface-13` | 6 | Every required interface is operational |
| `obj-security-14` | 7 | Management access requires authentication |
| `obj-security-15` | 3 | Management access requires authentication |

## Submission format

Write one line per fault you believe you found:

```
R1
SW-ACCESS FastEthernet0/3 VLAN
SW-DIST VLAN
```

Format: `device [interface] [category]`.

Categories: addressing, vlan, trunk, routing, gateway, dhcp, dns, interface, security.

Then:

```bash
trident practice operation-broken-campus --submit findings.txt --out report/
```
