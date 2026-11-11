"""Oracle Differential Gauntlet — real Packet Tracer protocol probe.

Read-only evidence capture. Opens one disposable copy of an authorized practice
lab, runs typed ``show`` commands per protocol, and writes the simulator's own raw
text to a JSON evidence file. It never mutates the source lab and never asserts a
result: it records what the simulator actually said so a human (or a review step)
can compare it against DeepCore's deterministic prediction.

Usage:
    TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_gauntlet_probe.py \
        --lab "test-labs/incoming/Final_R3_BDSM.pka" --out docs/oracle/evidence/<name>.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trident.simulator import SimulatorRuntime
from trident.simulator.backends import find_packet_tracer, simulator_version

# Commands that establish protocol state. Each maps to a protocol family so the
# report can group evidence without re-parsing free text.
PROBES: list[tuple[str, str]] = [
    ("STP", "show spanning-tree summary"),
    ("STP", "show spanning-tree"),
    ("EtherChannel", "show etherchannel summary"),
    ("NAT", "show ip nat translations"),
    ("NAT", "show ip nat statistics"),
    ("IPv6", "show ipv6 interface brief"),
    ("IPv6", "show ipv6 route"),
    ("ACL", "show access-lists"),
    ("L2", "show vlan brief"),
    ("L2", "show interfaces status"),
    ("ROUTE", "show ip route"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_targets(session, limit: int) -> list[str]:
    """Devices that actually serve an IOS CLI.

    The live backend does not populate ``device_type`` or ``model`` (both arrive as
    ``None``), so protocol families cannot be inferred from metadata. Capability is
    therefore discovered by asking each candidate for ``show version``: a device
    that answers is CLI-capable; a device that reports ``enterCommand not found``
    (Packet Tracer's PCs, servers and hubs) is not. Discovery is recorded so the
    evidence shows why a device was included or skipped.
    """
    capable: list[str] = []
    skipped: list[dict] = []
    for dev in session.backend.devices():
        name = str(dev.get("name", "")).strip()
        if not name:
            continue
        try:
            result = session.run_cli(name, "show version", timeout=25)
        except Exception as exc:
            skipped.append({"device": name, "reason": f"{type(exc).__name__}: {exc}"[:200]})
            continue
        if result.ok and result.raw:
            capable.append(name)
        else:
            skipped.append(
                {"device": name, "reason": (result.error or "no CLI output")[:200]}
            )
        if len(capable) >= limit:
            break
    return capable, skipped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-devices", type=int, default=6)
    ap.add_argument("--command-timeout", type=float, default=30.0)
    args = ap.parse_args()

    lab = Path(args.lab).expanduser().resolve()
    if not lab.is_file():
        print(f"LAB_MISSING {lab}", file=sys.stderr)
        return 2

    bundle = find_packet_tracer()
    version = simulator_version(bundle) if bundle else "unknown"
    source_sha = sha256_file(lab)

    evidence: dict = {
        "generated_at": datetime.now(UTC).isoformat(),
        "lab": lab.name,
        "lab_path": str(lab),
        "source_sha256": source_sha,
        "simulator_version": version,
        "backend": None,
        "session_id": None,
        "devices_probed": [],
        "observations": [],
        "lifecycle": {},
        "errors": [],
    }

    runtime = SimulatorRuntime(prefer_live=True)
    session = runtime.create_session(lab)
    evidence["session_id"] = session.session_id
    evidence["backend"] = session.backend.kind.value
    evidence["capabilities"] = sorted(c.value for c in session.capabilities())

    try:
        targets, skipped = pick_targets(session, args.max_devices)
        evidence["devices_probed"] = targets
        evidence["devices_skipped"] = skipped
        if not targets:
            evidence["errors"].append("no CLI-capable devices discovered")

        for device in targets:
            for protocol, command in PROBES:
                try:
                    result = session.run_cli(
                        device, command, timeout=args.command_timeout
                    )
                    evidence["observations"].append(
                        {
                            "protocol": protocol,
                            "device": device,
                            "command": command,
                            "ok": bool(result.ok),
                            "observed": bool(result.observed),
                            "raw": result.raw,
                            "error": result.error,
                            "operation": result.operation,
                            "backend": result.provenance.backend.value,
                        }
                    )
                except Exception as exc:  # a failed probe is evidence, not a crash
                    evidence["observations"].append(
                        {
                            "protocol": protocol,
                            "device": device,
                            "command": command,
                            "ok": False,
                            "observed": False,
                            "raw": "",
                            "error": f"{type(exc).__name__}: {exc}",
                            "operation": command,
                            "backend": evidence["backend"],
                        }
                    )
    finally:
        close_note = session.close()
        evidence["lifecycle"]["close_note"] = close_note
        evidence["lifecycle"]["source_sha_after"] = sha256_file(lab)
        evidence["lifecycle"]["source_unchanged"] = (
            evidence["lifecycle"]["source_sha_after"] == source_sha
        )
        evidence["lifecycle"]["owned_pids_after"] = runtime.owned_pids()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    observed = sum(1 for o in evidence["observations"] if o["observed"])
    print(
        f"wrote {out} | devices={len(evidence['devices_probed'])} "
        f"probes={len(evidence['observations'])} observed={observed} "
        f"source_unchanged={evidence['lifecycle']['source_unchanged']} "
        f"pt={version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
