"""Opt-in ground-truth checks for the six-level TRIDENT Gauntlet.

These tests exist to keep `docs/gauntlet/VERIFIED_GROUND_TRUTH.md` honest. They are the
opposite of a benchmark: they assert what Packet Tracer *actually* contains, including the
faults it **does not** contain.

Reading the assertions
-----------------------
* ``present`` — the fault is really in the device. The probe must match live output.
* ``absent_route`` / ``absent_value`` — the answer key claims a value that Packet Tracer
  does not hold. The test asserts the absence, because scoring an absent fault would reward
  a detector for finding something that is not there.
* ``hosts`` — end-host addressing read from Packet Tracer's own serialisation of the live
  network. PT 9.0.1 has no CLI on ``Pc``/``Server`` objects (``enterCommand`` is not an IPC
  call on them), so ``ipconfig`` cannot be used; ``fileSave`` into the disposable working
  copy is the only read path. Every host's gateway comes back as the template default,
  which is why the keyed gateway faults are ABSENT.

Running
-------
    TRIDENT_ALLOW_LIVE_SIMULATOR=1 TRIDENT_RUN_GROUND_TRUTH=1 \\
        pytest tests/test_gauntlet_ground_truth.py -m live_simulator -v

Sessions are serialised: one Packet Tracer process per test, closed in a ``finally`` block,
and the source ``.pkt`` is hashed before and after. Never run two of these in parallel.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.live_simulator,
    pytest.mark.skipif(
        os.environ.get("TRIDENT_ALLOW_LIVE_SIMULATOR") != "1"
        or os.environ.get("TRIDENT_RUN_GROUND_TRUTH") != "1",
        reason=(
            "ground-truth checks open Packet Tracer; set TRIDENT_ALLOW_LIVE_SIMULATOR=1 "
            "and TRIDENT_RUN_GROUND_TRUTH=1 to run them"
        ),
    ),
]

LABS_DIR = Path(
    os.environ.get(
        "TRIDENT_GAUNTLET_DIR",
        "/Users/tanayshah/Downloads/trident_gauntlet_complete/built",
    )
)

#: Packet Tracer's template default for an untouched PC / Server gateway. Every host in
#: every level reports one of these, regardless of what the spec or answer key asks for.
PC_TEMPLATE_GATEWAY = "1.1.1.2"
SERVER_TEMPLATE_GATEWAY = "192.168.10.1"

ADMIN_DOWN = r"administratively down\s+down"


# ---------------------------------------------------------------------------
# Level data: exactly what the live simulator reported during verification.
# ---------------------------------------------------------------------------

LEVELS: dict[str, dict] = {
    "01_easy": {
        "sha256": "c6140b8265a7cd1c4afbe71822809bd0fc00c7c4b6936abca2b2cd1d14a0c553",
        "devices": ["R1", "SW1", "PC1-1"],
        "links": 2,
        "present": [
            {
                "fault": "F01",
                "device": "R1",
                "command": "show ip interface brief",
                "matches": r"GigabitEthernet0/0\s+10\.1\.1\.1\s+YES manual " + ADMIN_DOWN,
            },
            {
                "fault": "F01",
                "device": "R1",
                "command": "show running-config",
                "matches": r"interface GigabitEthernet0/0\b[\s\S]{0,200}?shutdown",
            },
        ],
        "hosts": {"PC1-1": ("10.1.1.10", "255.255.255.0")},
        "absent_values": [],
    },
    "02_basic": {
        "sha256": "4032add3756433aa55aff32bb08e3345687c71737eea1f5b7d7fc002c362e5b2",
        "devices": ["R1", "SW1", "PC1-1", "PC1-2", "PC1-3"],
        "links": 4,
        "present": [
            {
                "fault": "F03",
                "device": "SW1",
                "command": "show interfaces status",
                "matches": r"Fa0/1\s+connected\s+91\s",
            },
            {
                "fault": "F03",
                "device": "SW1",
                "command": "show running-config",
                "matches": r"interface FastEthernet0/1\b[\s\S]{0,120}?switchport access vlan 91",
            },
        ],
        "hosts": {
            "PC1-1": ("10.2.1.10", "255.255.255.0"),
            "PC1-2": ("10.2.1.11", "255.255.255.0"),
            "PC1-3": ("10.2.1.12", "255.255.255.0"),
        },
        "absent_values": [("F02", "PC1-3", "10.2.1.254")],
    },
    "03_intermediate": {
        "sha256": "c187a87e77feb27b9bc67c4e0861985d7fd4aae647fffc7c5addc96cba24513d",
        "devices": ["R1", "R2", "SW1", "SW2", "PC1-1", "PC1-2", "PC2-1", "PC2-2"],
        "links": 7,
        "present": [
            {
                "fault": "F04",
                "device": "PC1-1",
                "host_mask": "255.255.0.0",
            },
            {
                "fault": "F05",
                "device": "R1",
                "command": "show ip route",
                "refutes": r"10\.3\.2\.0(?!\d)",
                "guard": r"10\.3\.1\.0/24",
            },
        ],
        "hosts": {
            "PC1-1": ("10.3.1.10", "255.255.0.0"),
            "PC1-2": ("10.3.1.11", "255.255.255.0"),
            "PC2-1": ("10.3.2.10", "255.255.255.0"),
            "PC2-2": ("10.3.2.11", "255.255.255.0"),
        },
        "absent_values": [("F02", "PC2-2", "10.3.2.254")],
    },
    "04_advanced": {
        "sha256": "28806e680bf840a4824069951ad5d04fe992242ebe8d327a0a858ec6c1a199c8",
        "devices": [
            "R1",
            "R2",
            "SW1",
            "SW2",
            "SW3",
            "PC1-1",
            "PC1-2",
            "PC2-1",
            "PC2-2",
            "PC3-1",
            "PC3-2",
        ],
        "links": 11,
        "present": [
            {
                "fault": "F01",
                "device": "R2",
                "command": "show ip interface brief",
                "matches": r"GigabitEthernet0/1\s+10\.4\.3\.1\s+YES manual " + ADMIN_DOWN,
            },
            {
                "fault": "F06",
                "device": "SW2",
                "command": "show interfaces trunk",
                "matches": r"Vlans allowed on trunk\s+Gig0/1\s+11\s*$",
            },
            {
                "fault": "F06",
                "device": "SW1",
                "command": "show interfaces trunk",
                "matches": r"Vlans allowed on trunk\s+Gig0/1\s+11-12",
            },
            {
                "fault": "F08",
                "device": "R1",
                "command": "show access-lists",
                "matches": r"deny icmp 10\.4\.1\.0 0\.0\.0\.255 host 10\.4\.1\.1 echo",
            },
            {
                "fault": "F08",
                "device": "R1",
                "command": "show running-config",
                "matches": r"interface GigabitEthernet0/0\b[\s\S]{0,200}?ip access-group BLOCK-GATEWAY-ICMP in",
            },
        ],
        "hosts": {
            "PC1-1": ("10.4.1.10", "255.255.255.0"),
            "PC3-2": ("10.4.3.11", "255.255.255.0"),
        },
        "absent_values": [("F02", "PC3-2", "10.4.3.254")],
    },
    "05_expert": {
        "sha256": "9450753082c9547b7c4a3fbc2cd926b98eeb6afecd96337de55f3e09811f0e68",
        "devices": [
            "R1",
            "R2",
            "R3",
            "SW1",
            "SW2",
            "SW3",
            "SW4",
            "PC1-1",
            "PC1-2",
            "PC2-1",
            "PC2-2",
            "PC3-1",
            "PC3-2",
            "PC4-1",
            "PC4-2",
            "SERVER1",
            "SERVER4",
        ],
        "links": 17,
        "present": [
            {
                "fault": "F01",
                "device": "R3",
                "command": "show ip interface brief",
                "matches": r"GigabitEthernet0/2\s+10\.5\.4\.1\s+YES manual " + ADMIN_DOWN,
            },
            {
                "fault": "F03",
                "device": "SW2",
                "command": "show interfaces status",
                "matches": r"Fa0/1\s+connected\s+92\s",
            },
            {
                "fault": "F04",
                "device": "PC1-1",
                "host_mask": "255.255.0.0",
            },
            {
                "fault": "F05",
                "device": "R1",
                "command": "show ip route",
                "refutes": r"10\.5\.4\.0(?!\d)",
                "guard": r"10\.5\.3\.0/24",
            },
            {
                "fault": "F06",
                "device": "SW2",
                "command": "show interfaces trunk",
                "matches": r"Vlans allowed on trunk\s+Gig0/1\s+11\s*$",
            },
        ],
        "hosts": {
            "PC1-1": ("10.5.1.10", "255.255.0.0"),
            "PC4-2": ("10.5.4.11", "255.255.255.0"),
            "SERVER1": ("10.5.1.100", "255.255.255.0"),
            "SERVER4": ("10.5.4.100", "255.255.255.0"),
        },
        "absent_values": [("F02", "PC4-2", "10.5.4.254")],
    },
    "06_insane": {
        "sha256": "37283abe5b75d3faef4bffa0a3b4d50aa7a4376077505fcb5ff9779dac433c71",
        "devices": [
            "R1",
            "R2",
            "R3",
            "R4",
            "SW1",
            "SW2",
            "SW3",
            "SW4",
            "SW5",
            "SW6",
            "PC1-1",
            "PC1-2",
            "PC1-3",
            "PC2-1",
            "PC2-2",
            "PC2-3",
            "PC3-1",
            "PC3-2",
            "PC4-1",
            "PC4-2",
            "PC5-1",
            "PC5-2",
            "PC6-1",
            "PC6-2",
            "SERVER1",
            "SERVER6",
        ],
        "links": 26,
        "present": [
            {
                "fault": "F01",
                "device": "R4",
                "command": "show ip interface brief",
                "matches": r"GigabitEthernet0/2\s+10\.6\.6\.1\s+YES manual " + ADMIN_DOWN,
            },
            {
                "fault": "F03",
                "device": "SW2",
                "command": "show interfaces status",
                "matches": r"Fa0/1\s+connected\s+92\s",
            },
            {
                "fault": "F04",
                "device": "PC1-1",
                "host_mask": "255.255.0.0",
            },
            {
                "fault": "F05",
                "device": "R1",
                "command": "show ip route",
                "refutes": r"10\.6\.6\.0(?!\d)",
                "guard": r"10\.6\.5\.0/24",
            },
            {
                "fault": "F10",
                "device": "R4",
                "command": "show ip route",
                "refutes": r"10\.6\.1\.0(?!\d)",
                "guard": r"10\.6\.2\.0/24",
            },
            {
                "fault": "F06",
                "device": "SW2",
                "command": "show interfaces trunk",
                "matches": r"Vlans allowed on trunk\s+Gig0/1\s+11\s*$",
            },
            {
                "fault": "F07",
                "device": "PC1-2",
                "host_ip_equals": ("PC1-1", "10.6.1.10"),
            },
            {
                "fault": "F08",
                "device": "R1",
                "command": "show access-lists",
                "matches": r"deny icmp 10\.6\.1\.0 0\.0\.0\.255 host 10\.6\.1\.1 echo",
            },
        ],
        "hosts": {
            "PC1-1": ("10.6.1.10", "255.255.0.0"),
            "PC1-2": ("10.6.1.10", "255.255.255.0"),
            "PC6-2": ("10.6.6.11", "255.255.255.0"),
            "SERVER1": ("10.6.1.100", "255.255.255.0"),
            "SERVER6": ("10.6.6.100", "255.255.255.0"),
        },
        "absent_values": [("F02", "PC6-2", "10.6.6.254"), ("F09", "PC1-1", "10.6.1.253")],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _host_state(backend, working_copy: Path) -> dict[str, dict[str, str]]:
    """Return ``{device: {ip, mask, gw}}`` from Packet Tracer's serialisation.

    ``fileSave`` writes the live in-memory network into the disposable working copy; the
    source lab is never opened for writing. This is the only way to read an end host's
    addressing on PT 9.0.1, whose ``Pc`` objects expose neither ``enterCommand`` nor any
    IP/gateway accessor.
    """
    from pkt_core.codec import decode

    backend.client.call(["appWindow", "fileSave"], timeout=30.0)
    container = decode(working_copy)
    xml = container.xml
    text = xml.decode("utf-8", "replace") if isinstance(xml, bytes) else xml

    state: dict[str, dict[str, str]] = {}
    for block in re.finditer(r"<DEVICE>(.*?)</DEVICE>", text, re.DOTALL):
        body = block.group(1)
        name = re.search(r"<NAME[^>]*>([^<]*)</NAME>", body)
        ip = re.search(r"<IP>([^<]*)</IP>", body)
        if not name or not ip:
            continue
        mask = re.search(r"<SUBNET>([^<]*)</SUBNET>", body)
        gw = re.search(r"<PORT_GATEWAY>([^<]*)</PORT_GATEWAY>", body)
        state[name.group(1)] = {
            "ip": ip.group(1),
            "mask": mask.group(1) if mask else "",
            "gw": gw.group(1) if gw else "",
        }
    return state


@contextlib.contextmanager
def _live_session(lab: Path, tag: str):
    """Open one lab, hand the backend to the caller, always tear the session down."""
    from trident.simulator.backends import (
        LiveBackend,
        credentials_from_env,
        find_packet_tracer,
    )
    from trident.simulator.isolation import Workspace

    bundle = find_packet_tracer()
    if bundle is None:
        pytest.skip("no Packet Tracer install found")
    credentials = credentials_from_env()
    if credentials is None:
        pytest.skip("no registered Packet Tracer ExApp credentials")

    workspace = Workspace()
    directory = workspace.new_session_dir(f"gt-test-{tag}")
    backend = None
    try:
        working_copy, _ = workspace.stage_copy(lab, directory)
        backend = LiveBackend(
            bundle=bundle,
            working_copy=working_copy,
            source_sha256=_sha256(lab),
            session_id=f"gt-test-{tag}",
            credentials=credentials,
            workspace=directory,
        )
        backend.connect(startup_timeout=120.0)
        yield backend, working_copy
    finally:
        if backend is not None:
            backend.close()
        workspace.cleanup(directory)


def _verify(level: str) -> None:
    spec = LEVELS[level]
    lab = LABS_DIR / f"{level}.pkt"
    if not lab.is_file():
        pytest.skip(f"lab not found: {lab}")

    before = _sha256(lab)
    assert before == spec["sha256"], (
        f"{lab.name} is not the artifact this document verified (sha256 {before}, expected {spec['sha256']})"
    )

    with _live_session(lab, level) as (backend, working_copy):
        names = [d["name"] for d in backend.devices() if not d["name"].startswith("Power Distribution")]
        assert names == spec["devices"], f"device inventory changed: {names}"

        hosts = _host_state(backend, working_copy) if spec["hosts"] or spec["absent_values"] else {}

        # 1. Faults the simulator really contains.
        failures: list[str] = []
        for probe in spec["present"]:
            fault, device = probe["fault"], probe["device"]
            if "host_mask" in probe:
                observed = hosts.get(device, {}).get("mask")
                if observed != probe["host_mask"]:
                    failures.append(
                        f"{fault}: {device} mask is {observed!r}, expected {probe['host_mask']!r}"
                    )
                continue
            if "host_ip_equals" in probe:
                other, expected_ip = probe["host_ip_equals"]
                mine = hosts.get(device, {}).get("ip")
                theirs = hosts.get(other, {}).get("ip")
                if not (mine == theirs == expected_ip):
                    failures.append(
                        f"{fault}: expected {device} and {other} both at {expected_ip}, "
                        f"got {mine!r} / {theirs!r}"
                    )
                continue

            result = backend.run_cli(device, probe["command"], 30.0)
            if not result.ok:
                failures.append(f"{fault}: {device} {probe['command']} failed: {result.error}")
                continue
            raw = result.raw or ""
            if "matches" in probe:
                if not re.search(probe["matches"], raw, re.MULTILINE | re.DOTALL):
                    failures.append(
                        f"{fault}: {device} {probe['command']} did not show {probe['matches']!r}"
                        f"\n    output: {raw[:400]!r}"
                    )
            elif "refutes" in probe:
                if probe.get("guard") and not re.search(probe["guard"], raw):
                    failures.append(
                        f"{fault}: guard {probe['guard']!r} absent from {device} route table; "
                        f"output unreadable: {raw[:300]!r}"
                    )
                if re.search(probe["refutes"], raw):
                    failures.append(
                        f"{fault}: {device} {' '.join(probe['command'].split())} contains "
                        f"{probe['refutes']!r}, so the keyed absence is no longer true"
                    )
        assert not failures, "PRESENT faults not observable:\n  " + "\n  ".join(failures)

        # 2. Host addressing as the simulator holds it (masks survive; gateways do not).
        for device, (expected_ip, expected_mask) in spec["hosts"].items():
            state = hosts.get(device)
            assert state, f"{device} missing from Packet Tracer's live serialisation"
            assert state["ip"] == expected_ip, f"{device} ip {state['ip']!r} != {expected_ip!r}"
            assert state["mask"] == expected_mask, f"{device} mask {state['mask']!r} != {expected_mask!r}"
            template = SERVER_TEMPLATE_GATEWAY if device.startswith("SERVER") else PC_TEMPLATE_GATEWAY
            assert state["gw"] == template, (
                f"{device} gateway is {state['gw']!r}; the verified ground truth is the "
                f"Packet Tracer template default {template!r}"
            )

        # 3. Values the answer key claims that are NOT in the simulator.
        for fault, device, keyed_gateway in spec["absent_values"]:
            state = hosts.get(device)
            assert state, f"{device} missing from Packet Tracer's live serialisation"
            assert keyed_gateway not in state["gw"], (
                f"{fault}: {device} gateway now reads {state['gw']!r}, which contains the keyed "
                f"value {keyed_gateway!r}. The answer key may be back in scope — re-verify "
                f"docs/gauntlet/VERIFIED_GROUND_TRUTH.md before scoring this fault."
            )

    after = _sha256(lab)
    assert after == before, f"source lab was modified during the session: {before} -> {after}"


# ---------------------------------------------------------------------------
# One test per level
# ---------------------------------------------------------------------------


def test_level_01_easy() -> None:
    """1 fault keyed, 1 PRESENT: R1 GigabitEthernet0/0 administratively down."""
    _verify("01_easy")


def test_level_02_basic() -> None:
    """2 keyed, 1 PRESENT (SW1 Fa0/1 in VLAN 91), 1 ABSENT (PC1-3 gateway)."""
    _verify("02_basic")


def test_level_03_intermediate() -> None:
    """3 keyed, 2 PRESENT (PC1-1 /16 mask, R1 missing 10.3.2.0 route), 1 ABSENT."""
    _verify("03_intermediate")


def test_level_04_advanced() -> None:
    """4 keyed, 3 PRESENT (R2 Gi0/1 down, SW2 trunk, R1 ACL), 1 ABSENT."""
    _verify("04_advanced")


def test_level_05_expert() -> None:
    """6 keyed, 5 PRESENT, 1 ABSENT (PC4-2 gateway)."""
    _verify("05_expert")


def test_level_06_insane() -> None:
    """10 keyed, 8 PRESENT, 2 ABSENT (PC6-2 and PC1-1 gateways)."""
    _verify("06_insane")
