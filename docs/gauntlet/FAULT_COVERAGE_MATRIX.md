# Fault coverage matrix — six gauntlet labs

Every fault below is drawn from the **15 faults independently verified observable
in Packet Tracer 9.0.1** (`tests/test_labgen_live.py`). No fault in any lab
originates anywhere else. What changes between difficulties is the *set* and the
*weighting*, not the vocabulary — see `trident/labgen/gauntlet.py:66`
(`LAB_FAULTS`) and `rebalance()` at `trident/labgen/gauntlet.py:76`, which rescales
weights by largest-remainder so each lab totals exactly 100.

The "expected detector" column is the fault's entry in `EXACT_DETECTOR`
(`trident/gauntlet_bench.py:168`), which is declared per fault id rather than per
category. `vlan-missing-on-dist` and `trunk-vlan-list-missing` also name an
interface, so a detection must match the device *and* the interface
(`trident/gauntlet_bench.py:187`).

---

## End-host probe limitation (applies to every table)

Two of the fifteen faults target end hosts:

* `addr-mask-admin-pc` — `PC-ADMIN-1`
* `gw-faculty-pc-wrong` — `PC-FACULTY-1`

Their nominal probe is `ipconfig`. **Packet Tracer 9.0.1 rejects `enterCommand` on
`PC-PT` devices** ("IPC call not found"), so that probe cannot actually be driven
live; the faults remain fully verifiable through the generated configuration and
through `trident.gauntlet_bench`. `_PROBE_TABLE` (`trident/labgen/gauntlet.py:177`)
does carry an `ipconfig` entry for both, and `probes_for()` therefore returns
15/15 probes for the insane lab — the entry is a *nominal* command, not an
executable one. The module docstring at `trident/labgen/gauntlet.py:160` describes
end-host faults as excluded, which does not match the table; the table is what
`probes_for()` uses. Treat every `ipconfig` row below as **not runnable on PT
9.0.1**.

All other probes are read-only commands confirmed answerable by PT 9.0.1.

---

## easy — 4 faults, 100 points

| fault id | category | device | interface | points | probe command | expected detector |
|---|---|---|---:|---:|---|---|
| `iface-admin-port-shutdown` | interface | SW-DIST | FastEthernet0/1 | 27 | `show interfaces status` | `SHUTDOWN_INTERFACE` |
| `sec-enable-secret-missing` | security | SW-ACCESS | — | 14 | `show running-config` | `WEAK_MANAGEMENT` |
| `addr-mask-admin-pc` | addressing | PC-ADMIN-1 | FastEthernet0 | 32 | `ipconfig` (not executable) | `INVALID_MASK` |
| `gw-faculty-pc-wrong` | gateway | PC-FACULTY-1 | FastEthernet0 | 27 | `ipconfig` (not executable) | `WRONG_GATEWAY` |

**Total: 4 faults, 100 points.**

## basic — 6 faults, 100 points

| fault id | category | device | interface | points | probe command | expected detector |
|---|---|---|---:|---:|---|---|
| `iface-admin-port-shutdown` | interface | SW-DIST | FastEthernet0/1 | 19 | `show interfaces status` | `SHUTDOWN_INTERFACE` |
| `sec-enable-secret-missing` | security | SW-ACCESS | — | 9 | `show running-config` | `WEAK_MANAGEMENT` |
| `addr-mask-admin-pc` | addressing | PC-ADMIN-1 | FastEthernet0 | 22 | `ipconfig` (not executable) | `INVALID_MASK` |
| `gw-faculty-pc-wrong` | gateway | PC-FACULTY-1 | FastEthernet0 | 19 | `ipconfig` (not executable) | `WRONG_GATEWAY` |
| `sec-ssh-no-local-user` | security | R1 | — | 22 | `show running-config` | `WEAK_MANAGEMENT` |
| `dhcp-excluded-missing` | dhcp | R1 | — | 9 | `show running-config` | `UNRESERVED_GATEWAY` |

**Total: 6 faults, 100 points.**

## intermediate — 8 faults, 100 points

| fault id | category | device | interface | points | probe command | expected detector |
|---|---|---|---:|---:|---|---|
| `iface-admin-port-shutdown` | interface | SW-DIST | FastEthernet0/1 | 15 | `show interfaces status` | `SHUTDOWN_INTERFACE` |
| `sec-enable-secret-missing` | security | SW-ACCESS | — | 8 | `show running-config` | `WEAK_MANAGEMENT` |
| `addr-mask-admin-pc` | addressing | PC-ADMIN-1 | FastEthernet0 | 18 | `ipconfig` (not executable) | `INVALID_MASK` |
| `gw-faculty-pc-wrong` | gateway | PC-FACULTY-1 | FastEthernet0 | 15 | `ipconfig` (not executable) | `WRONG_GATEWAY` |
| `sec-ssh-no-local-user` | security | R1 | — | 17 | `show running-config` | `WEAK_MANAGEMENT` |
| `dhcp-excluded-missing` | dhcp | R1 | — | 7 | `show running-config` | `UNRESERVED_GATEWAY` |
| `vlan-students-port-wrong` | vlan | SW-ACCESS | FastEthernet0/3 | 15 | `show vlan brief` | `WRONG_VLAN` |
| `vlan-faculty-port-wrong` | vlan | SW-ACCESS | FastEthernet0/5 | 5 | `show vlan brief` | `WRONG_VLAN` |

**Total: 8 faults, 100 points.**

## advanced — 11 faults, 100 points

| fault id | category | device | interface | points | probe command | expected detector |
|---|---|---|---:|---:|---|---|
| `iface-admin-port-shutdown` | interface | SW-DIST | FastEthernet0/1 | 10 | `show interfaces status` | `SHUTDOWN_INTERFACE` |
| `sec-enable-secret-missing` | security | SW-ACCESS | — | 5 | `show running-config` | `WEAK_MANAGEMENT` |
| `addr-mask-admin-pc` | addressing | PC-ADMIN-1 | FastEthernet0 | 11 | `ipconfig` (not executable) | `INVALID_MASK` |
| `gw-faculty-pc-wrong` | gateway | PC-FACULTY-1 | FastEthernet0 | 10 | `ipconfig` (not executable) | `WRONG_GATEWAY` |
| `sec-ssh-no-local-user` | security | R1 | — | 11 | `show running-config` | `WEAK_MANAGEMENT` |
| `dhcp-excluded-missing` | dhcp | R1 | — | 5 | `show running-config` | `UNRESERVED_GATEWAY` |
| `vlan-students-port-wrong` | vlan | SW-ACCESS | FastEthernet0/3 | 10 | `show vlan brief` | `WRONG_VLAN` |
| `vlan-faculty-port-wrong` | vlan | SW-ACCESS | FastEthernet0/5 | 3 | `show vlan brief` | `WRONG_VLAN` |
| `vlan-missing-on-dist` | vlan | SW-DIST | Vlan10 | 10 | `show vlan brief` | `WRONG_VLAN` |
| `dhcp-pool-wrong-network` | dhcp | R1 | — | 16 | `show running-config` | `DHCP_POOL_NETWORK` |
| `dhcp-pool-missing-dns` | dns | R1 | — | 9 | `show running-config` | `DHCP_POOL_DNS` |

**Total: 11 faults, 100 points.**

## expert — 13 faults, 100 points

| fault id | category | device | interface | points | probe command | expected detector |
|---|---|---|---:|---:|---|---|
| `iface-admin-port-shutdown` | interface | SW-DIST | FastEthernet0/1 | 8 | `show interfaces status` | `SHUTDOWN_INTERFACE` |
| `sec-enable-secret-missing` | security | SW-ACCESS | — | 4 | `show running-config` | `WEAK_MANAGEMENT` |
| `addr-mask-admin-pc` | addressing | PC-ADMIN-1 | FastEthernet0 | 9 | `ipconfig` (not executable) | `INVALID_MASK` |
| `gw-faculty-pc-wrong` | gateway | PC-FACULTY-1 | FastEthernet0 | 8 | `ipconfig` (not executable) | `WRONG_GATEWAY` |
| `sec-ssh-no-local-user` | security | R1 | — | 9 | `show running-config` | `WEAK_MANAGEMENT` |
| `dhcp-excluded-missing` | dhcp | R1 | — | 4 | `show running-config` | `UNRESERVED_GATEWAY` |
| `vlan-students-port-wrong` | vlan | SW-ACCESS | FastEthernet0/3 | 8 | `show vlan brief` | `WRONG_VLAN` |
| `vlan-faculty-port-wrong` | vlan | SW-ACCESS | FastEthernet0/5 | 2 | `show vlan brief` | `WRONG_VLAN` |
| `vlan-missing-on-dist` | vlan | SW-DIST | Vlan10 | 7 | `show vlan brief` | `WRONG_VLAN` |
| `dhcp-pool-wrong-network` | dhcp | R1 | — | 12 | `show running-config` | `DHCP_POOL_NETWORK` |
| `dhcp-pool-missing-dns` | dns | R1 | — | 7 | `show running-config` | `DHCP_POOL_DNS` |
| `trunk-native-mismatch` | trunk | SW-ACCESS | GigabitEthernet0/1 | 12 | `show interfaces trunk` | `TRUNK_MISMATCH` |
| `trunk-vlan-list-missing` | trunk | SW-DIST | GigabitEthernet0/1 | 10 | `show interfaces trunk` | `TRUNK_MISMATCH` |

**Total: 13 faults, 100 points.**

## insane — 15 faults, 100 points

| fault id | category | device | interface | points | probe command | expected detector |
|---|---|---|---:|---:|---|---|
| `iface-admin-port-shutdown` | interface | SW-DIST | FastEthernet0/1 | 6 | `show interfaces status` | `SHUTDOWN_INTERFACE` |
| `sec-enable-secret-missing` | security | SW-ACCESS | — | 3 | `show running-config` | `WEAK_MANAGEMENT` |
| `addr-mask-admin-pc` | addressing | PC-ADMIN-1 | FastEthernet0 | 7 | `ipconfig` (not executable) | `INVALID_MASK` |
| `gw-faculty-pc-wrong` | gateway | PC-FACULTY-1 | FastEthernet0 | 6 | `ipconfig` (not executable) | `WRONG_GATEWAY` |
| `sec-ssh-no-local-user` | security | R1 | — | 7 | `show running-config` | `WEAK_MANAGEMENT` |
| `dhcp-excluded-missing` | dhcp | R1 | — | 3 | `show running-config` | `UNRESERVED_GATEWAY` |
| `vlan-students-port-wrong` | vlan | SW-ACCESS | FastEthernet0/3 | 6 | `show vlan brief` | `WRONG_VLAN` |
| `vlan-faculty-port-wrong` | vlan | SW-ACCESS | FastEthernet0/5 | 2 | `show vlan brief` | `WRONG_VLAN` |
| `vlan-missing-on-dist` | vlan | SW-DIST | Vlan10 | 6 | `show vlan brief` | `WRONG_VLAN` |
| `dhcp-pool-wrong-network` | dhcp | R1 | — | 10 | `show running-config` | `DHCP_POOL_NETWORK` |
| `dhcp-pool-missing-dns` | dns | R1 | — | 6 | `show running-config` | `DHCP_POOL_DNS` |
| `trunk-native-mismatch` | trunk | SW-ACCESS | GigabitEthernet0/1 | 10 | `show interfaces trunk` | `TRUNK_MISMATCH` |
| `trunk-vlan-list-missing` | trunk | SW-DIST | GigabitEthernet0/1 | 8 | `show interfaces trunk` | `TRUNK_MISMATCH` |
| `route-default-wrong-next-hop` | routing | R1 | — | 10 | `show running-config` | `UNREACHABLE_NEXT_HOP` |
| `addr-router-subif-wrong` | addressing | R1 | GigabitEthernet0/0.30 | 10 | `show running-config` | `DUPLICATE_IP` |

**Total: 15 faults, 100 points.**

---

## Coverage summary

| lab | faults | point total | distinct categories | probe devices |
|---|---:|---:|---|---|
| easy | 4 | 100 | interface, security, addressing, gateway | SW-DIST, SW-ACCESS, PC-ADMIN-1, PC-FACULTY-1 |
| basic | 6 | 100 | + dhcp | + R1 |
| intermediate | 8 | 100 | + vlan | SW-DIST, SW-ACCESS, R1, PCs |
| advanced | 11 | 100 | + dns | SW-DIST, SW-ACCESS, R1, PCs |
| expert | 13 | 100 | + trunk | SW-DIST, SW-ACCESS, R1, PCs |
| insane | 15 | 100 | all nine (interface, security, addressing, gateway, dhcp, vlan, dns, trunk, routing) | SW-DIST, SW-ACCESS, R1, PCs |

The 15-fault pool covers nine distinct fault categories: addressing (2 faults),
vlan (3), trunk (2), routing (1), gateway (1), dhcp (2), dns (1), interface (1),
security (2). `FaultCategory.ACCESS` has no fault in the pool, because no
ACL fault was among the 15 live-verified ones. No lab introduces a fault that was
not live-verified.

Faults added at each step, in order:

* **easy → basic**: `sec-ssh-no-local-user`, `dhcp-excluded-missing`
* **basic → intermediate**: `vlan-students-port-wrong`, `vlan-faculty-port-wrong`
* **intermediate → advanced**: `vlan-missing-on-dist`, `dhcp-pool-wrong-network`, `dhcp-pool-missing-dns`
* **advanced → expert**: `trunk-native-mismatch`, `trunk-vlan-list-missing`
* **expert → insane**: `route-default-wrong-next-hop`, `addr-router-subif-wrong`

Reproduce the totals:

```bash
cd /Users/tanayshah/CiscoTrident && source .venv/bin/activate
python -c "from trident.labgen.gauntlet import all_labs; [print(d, len(l.faults), l.point_total()) for d,l in all_labs().items()]"
```
