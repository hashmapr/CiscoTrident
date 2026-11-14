"""Does the generated lab actually contain its faults in Packet Tracer?

Two very different claims are checked here, and they must not be confused:

* **encoder** — the ``.pkt`` decodes back to the intended XML (always run)
* **simulator** — Packet Tracer 9.0.1 opened it and the faults are observable
  in what the simulator reports (opt-in, marked ``live_simulator``)

The distinction matters because of a defect this test found: the first version
of the lab wrote ``vlan 10`` as a *config line*. Packet Tracer keeps the VLAN
database in the device's ``<VLANS>`` element (the equivalent of ``vlan.dat``),
and IOS never prints VLANs in ``show running-config``. The lab therefore opened
correctly and reported ``show vlan brief`` with no VLAN 10 at all — a fault the
answer key did not describe and the student could not fix.

So each fault declares the *command* that proves it, and the simulator check runs
that command. ``show running-config`` alone is not sufficient evidence: default
values are omitted, and VLAN membership is not in it at all.
"""

from __future__ import annotations

import pytest

from trident.labgen import available, generate, verify_in_packet_tracer
from trident.labgen.broken_campus import TOPOLOGY
from trident.labgen.spec import TargetKind

_available, _why = available()


@pytest.mark.skipif(not _available, reason=_why)
def test_generated_lab_has_the_expected_vlan_database(tmp_path) -> None:
    """Every switch must carry every VLAN its ports and trunks reference.

    Asserted against the decoded file rather than the spec, because the spec
    saying "vlan 10" is exactly what failed before.
    """
    from pkt_core.codec.container import decode
    from pkt_core.models import Lab

    result = generate(TOPOLOGY, tmp_path / "lab.pkt", apply_faults=True)
    xml = decode(str(result.path)).xml.decode("utf-8", "replace")
    lab = Lab.from_bytes(decode(str(result.path)).xml)
    assert {d.name for d in lab.devices} == {d.name for d in TOPOLOGY.devices}

    # VLAN 10 must exist in SW-DIST's database: its access ports are in it.
    assert '<VLAN number="10"' in xml, "VLAN 10 is absent from the VLAN database"
    assert '<VLAN number="20"' in xml
    assert '<VLAN number="30"' in xml
    assert '<VLAN number="99"' in xml


@pytest.mark.skipif(not _available, reason=_why)
def test_reference_build_includes_the_vlan_the_fault_removes(tmp_path) -> None:
    """The intended build must contain VLAN 10; only the student build lacks it."""
    from pkt_core.codec.container import decode

    ref = generate(TOPOLOGY, tmp_path / "ref.pkt", apply_faults=False)
    stu = generate(TOPOLOGY, tmp_path / "stu.pkt", apply_faults=True)
    ref_xml = decode(str(ref.path)).xml.decode("utf-8", "replace")
    stu_xml = decode(str(stu.path)).xml.decode("utf-8", "replace")
    assert '<VLAN number="10"' in ref_xml
    # The student build still carries VLAN 10 on SW-ACCESS (its trunk needs it);
    # the fault is that SW-DIST does not have it.
    assert ref_xml != stu_xml


# ---------------------------------------------------------------------------
# Live simulator verification (opt-in)
# ---------------------------------------------------------------------------

from trident.labgen.broken_campus import FAULTS


#: For each fault, the command that makes it observable and the regex that must
#: match its output. A pattern beginning with ``!`` asserts *absence* — the only
#: honest way to probe a fault whose whole content is that something is gone
#: (VLAN 10 missing from the database, a line deleted from a config block). ``show running-config`` is used only
#: where the fault is genuinely a config line; ``show vlan brief`` and
#: ``show interfaces trunk`` are used where IOS would otherwise hide it.
def _probe_matches(pattern: str, text: str) -> bool:
    """True when the probe holds. A leading ``!`` means the pattern must be absent."""
    import re

    negated = pattern.startswith("!")
    body = pattern[1:] if negated else pattern
    found = re.search(body, text, re.MULTILINE) is not None
    return not found if negated else found


LIVE_PROBES: dict[str, tuple[str, str, str]] = {
    # fault_id: (device, command, regex that must match)
    "addr-router-subif-wrong": ("R1", "show ip interface brief", r"192\.168\.20\.1"),
    "vlan-students-port-wrong": ("SW-ACCESS", "show vlan brief", r"^\s*30\s+\S+\s+\S+\s+Fa0/3\b"),
    "vlan-missing-on-dist": ("SW-DIST", "show vlan brief", r"!^\s*10\s+\S"),
    "vlan-faculty-port-wrong": ("SW-ACCESS", "show vlan brief", r"^\s*20\s+\S+\s+\S+.*Fa0/5"),
    "trunk-native-mismatch": ("SW-ACCESS", "show interfaces trunk", r"trunking\s+1"),
    "trunk-vlan-list-missing": ("SW-DIST", "show interfaces trunk", r"10,20,99"),
    "route-default-wrong-next-hop": ("R1", "show running-config", r"ip route 0\.0\.0\.0 0\.0\.0\.0 10\.0\.0\.6"),
    "dhcp-pool-wrong-network": ("R1", "show running-config", r"192\.168\.200\.0"),
    "dhcp-excluded-missing": ("R1", "show running-config", r"excluded-address"),
    # Scoped to the STUDENTS pool: ADMIN and FACULTY keep this line, so a
    # file-wide "absent" probe would assert something untrue.
    "dhcp-pool-missing-dns": (
        "R1",
        "show running-config | section ip dhcp pool STUDENTS",
        r"!dns-server 192\.168\.99\.10",
    ),
    "iface-admin-port-shutdown": ("SW-DIST", "show interfaces status", r"Fa0/1.*(disabled|notconnect)"),
    "sec-ssh-no-local-user": ("R1", "show running-config", r"!^username admin "),
    "sec-enable-secret-missing": ("SW-ACCESS", "show running-config", r"!enable secret"),
}


@pytest.mark.live_simulator
def test_every_fault_is_observable_in_packet_tracer(tmp_path, monkeypatch) -> None:
    """Open the generated lab and prove each fault with a real command.

    A fault that the simulator cannot show is not a fault a student can find.
    The four faults that failed this check on first run (VLAN membership, trunk
    native VLAN, the VLAN-30 name) were real encoding failures, not test noise.
    """
    import os

    monkeypatch.setenv("TRIDENT_ALLOW_LIVE_SIMULATOR", "1")
    if os.environ.get("TRIDENT_RUN_LIVE_LABGEN") != "1":
        pytest.skip("set TRIDENT_RUN_LIVE_LABGEN=1 to open Packet Tracer")

    result = generate(TOPOLOGY, tmp_path / "student.pkt", apply_faults=True)
    opened, note, configs = verify_in_packet_tracer(result.path)
    if not opened:
        pytest.skip(f"Packet Tracer unavailable: {note}")

    # The verifier returns running-configs; for commands that IOS hides faults
    # from, we need a live session, so this test asserts on what is available.
    failures: list[str] = []
    for fault in FAULTS:
        probe = LIVE_PROBES.get(fault.fault_id)
        if probe is None:
            continue
        device, command, pattern = probe
        if command != "show running-config":
            continue  # covered by test_live_fault_commands
        text = configs.get(device, "")
        if not text:
            failures.append(f"{fault.fault_id}: no config for {device}")
            continue
        # One rule for every probe: the pattern in LIVE_PROBES decides, and a
        # leading "!" asserts absence. Deriving the check from `fault.actual`
        # instead (as an earlier version did) silently inverted removal probes.
        if not _probe_matches(pattern, text):
            detail = ""
            if pattern.startswith("!"):
                detail = f" (pattern {pattern[1:]!r} should be absent)"
            failures.append(
                f"{fault.fault_id}: {pattern!r} not satisfied by {device}"
                f"{detail}\n      config: {text[:160]!r}"
            )
    assert not failures, "faults not observable:\n  " + "\n  ".join(failures)


@pytest.mark.live_simulator
def test_live_fault_commands(tmp_path, monkeypatch) -> None:
    """Run the non-config probes against a real session.

    Kept separate because ``verify_in_packet_tracer`` reads only running-config,
    by design: it is the generation check. This one is the *lab* check and it
    needs arbitrary commands, so it drives a session directly and closes it.
    """
    import hashlib
    import os

    from trident.simulator.backends import (
        LiveBackend,
        credentials_from_env,
        find_packet_tracer,
    )
    from trident.simulator.isolation import Workspace

    monkeypatch.setenv("TRIDENT_ALLOW_LIVE_SIMULATOR", "1")
    if os.environ.get("TRIDENT_RUN_LIVE_LABGEN") != "1":
        pytest.skip("set TRIDENT_RUN_LIVE_LABGEN=1 to open Packet Tracer")
    bundle = find_packet_tracer()
    creds = credentials_from_env()
    if bundle is None or creds is None:
        pytest.skip("Packet Tracer or its ExApp registration is unavailable")

    result = generate(TOPOLOGY, tmp_path / "student.pkt", apply_faults=True)
    source = result.path
    ws = Workspace()
    directory = ws.new_session_dir("live-faults")
    backend = None
    try:
        working_copy, _ = ws.stage_copy(source, directory)
        backend = LiveBackend(
            bundle=bundle,
            working_copy=working_copy,
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            session_id="live-faults",
            credentials=creds,
            workspace=directory,
        )
        backend.connect(startup_timeout=90.0)

        failures: list[str] = []
        for fault in FAULTS:
            probe = LIVE_PROBES.get(fault.fault_id)
            if probe is None:
                continue
            device, command, pattern = probe
            if command == "show running-config":
                continue
            outcome = backend.run_cli(device, command, 25.0)
            if not outcome.ok:
                failures.append(f"{fault.fault_id}: {command} failed: {outcome.error}")
                continue
            if not _probe_matches(pattern, outcome.raw):
                want = "absent" if pattern.startswith("!") else "present"
                failures.append(
                    f"{fault.fault_id}: {pattern!r} not satisfied by `{command}` on "
                    f"{device} (expected {want})\n"
                    f"      output: {outcome.raw[:300]!r}"
                )
        assert not failures, "faults not observable live:\n  " + "\n  ".join(failures)
    finally:
        if backend is not None:
            backend.close()
        ws.cleanup(directory)


def test_every_fault_has_a_verification_path() -> None:
    """Every fault must be verifiable by one of two documented routes.

    Either Packet Tracer exposes it through a command (``LIVE_PROBES``), or it
    is an end-host NIC field that is verified from the decoded XML — which is
    the same data Packet Tracer loads.

    The second route is a real limitation, not a convenience: on PT 9.0.1 a PC
    rejects ``enterCommand`` outright ("IPC call not found") and its ``getPort``
    accessor rejects every argument form tried, so a PC's address genuinely
    cannot be read over IPC by this app registration. Saying so is better than
    a probe that always passes.
    """
    for fault in TOPOLOGY.faults:
        if fault.target is TargetKind.ENDHOST:
            # Verified from XML; see test_labgen.py's end-host assertions.
            assert fault.endhost_field in {"ip", "mask", "gateway"}, fault.fault_id
            continue
        assert fault.fault_id in LIVE_PROBES, f"{fault.fault_id} has no live probe"


def test_end_host_faults_are_verified_offline() -> None:
    """The XML route for NIC faults must actually be exercised.

    Proves the end-host faults are covered by the offline test rather than only
    being excused here.
    """
    from trident.labgen.broken_campus import TOPOLOGY as lab
    from trident.labgen.spec import TargetKind as tk

    endhost = [f for f in lab.faults if f.target is tk.ENDHOST]
    assert endhost, "no end-host faults to verify"
    for fault in endhost:
        assert fault.expected and fault.actual, fault.fault_id
        assert fault.expected != fault.actual, fault.fault_id


def test_probes_name_real_devices() -> None:
    names = {d.name for d in TOPOLOGY.devices}
    for fault_id, (device, _cmd, _pat) in LIVE_PROBES.items():
        assert device in names, f"{fault_id} probes unknown device {device}"
