# Operation Broken Campus — reproducible setup

Original practice lab for CyberPatriot networking training. Not derived from any
Cisco curriculum topology or competition material.

## What it is

A three-department school network, deliberately broken in 15 places:

| Department | VLAN | Subnet | Gateway |
|---|---|---|---|
| Administration | 10 | 192.168.10.0/24 | 192.168.10.1 |
| Students | 20 | 192.168.20.0/24 | 192.168.20.1 |
| Faculty | 30 | 192.168.30.0/24 | 192.168.30.1 |
| Management | 99 | 192.168.99.0/24 | 192.168.99.1 |

Equipment: 2 routers (R1 + an ISP peer), 2 switches, 6 PCs, 1 server.

## Generate the lab

The `.pkt` is generated from a spec, so the lab and the answer key cannot drift
apart.

```bash
cd ~/CiscoTrident
source .venv/bin/activate

# Student build (faults applied)
trident practice operation-broken-campus --generate test-labs/broken_campus

# Reference build (no faults), for comparing what "fixed" means
python -c "
from trident.labgen import generate
from trident.labgen.broken_campus import TOPOLOGY
generate(TOPOLOGY, 'test-labs/broken_campus/reference.pkt', apply_faults=False)
"
```

`--generate` prints the SHA-256 and states plainly that the file is **not**
simulator-verified. Encoding success is not compatibility.

## Verify it in Packet Tracer

```bash
TRIDENT_ALLOW_LIVE_SIMULATOR=1 TRIDENT_RUN_LIVE_LABGEN=1 \
  pytest tests/test_labgen_live.py -m live_simulator -v
```

This opens the generated file in Packet Tracer 9.0.1 and runs the command that
makes each fault observable, asserting the fault is really there. It skips —
never passes — when Packet Tracer is unavailable.

Last recorded run of this session: **2 passed**. Every fault was observable.

## Run a practice attempt

```bash
# What am I trying to achieve?
trident practice operation-broken-campus --objectives

# Hints, one level at a time (progress persists per lab)
trident practice operation-broken-campus --hint obj-trunk-06
trident practice operation-broken-campus --hint obj-trunk-06

# Score a submission
cat > findings.txt <<'EOF'
R1 GigabitEthernet0/0.30 ADDRESSING
SW-ACCESS FastEthernet0/3 VLAN
EOF
trident practice operation-broken-campus --submit findings.txt --out report/
```

The report is written to `report/practice_report.md` and
`report/practice_score.json`. A missed fault's expected configuration is
**removed** from the student JSON; a found one keeps it, because confirming the
correct value is teaching.

## Instructor artefacts

```bash
trident practice operation-broken-campus --write-key key.json
```

`--write-key` is the only path that emits the manifest, and it is never part of
a plain `--submit`.

## If generation is unavailable

`pkt_core.builder` ships with `pkt-core`, which TRIDENT already depends on for
Engine B. If it cannot be imported, `--generate` exits 3 with the reason. The
lab can then be built by hand from `ANSWER_KEY.json`, which lists every device,
interface, expected value and actual value. That is a fallback, not a
supported workflow: nothing in this repository verifies a hand-built file.

## Fault inventory

15 faults, 100 points. See `ANSWER_KEY.json` for the machine-readable form and
`INSTRUCTOR_KEY.md` for the prose form.

| Category | Count |
|---|---|
| Addressing | 2 |
| VLAN | 3 |
| Trunk | 2 |
| Routing | 1 |
| Gateway | 1 |
| DHCP | 2 |
| DNS | 1 |
| Interface | 1 |
| Security | 2 |

Repeated categories on different devices are deliberate: two `WRONG_VLAN`-class
faults on different switches cannot be solved by pattern-matching one output.

## Known limitations

1. **PC NIC values are not readable over IPC.** On PT 9.0.1 a `PC-PT` device
   rejects `enterCommand` ("IPC call not found") and its `getPort` accessor
   rejects every argument form tried. End-host faults are therefore verified
   from the decoded XML, which is the same data Packet Tracer loads, not from a
   live `ipconfig`.
2. **`show running-config` is not sufficient evidence for VLANs.** Packet Tracer
   keeps the VLAN database in the device's `<VLANS>` element. Any lab tooling
   that only writes `vlan NN` config lines produces switches with no VLANs.
3. **`transport input all` is an IOS default** and is omitted from
   running-config, so a Telnet-permitted fault cannot be graded from config.
   The lab uses a different, observable security fault instead.
