"""Oracle Differential Gauntlet — prediction vs. real Packet Tracer observation.

For each CLI-capable device in an authorized lab this script:

1. reads the device's own ``show running-config`` from Packet Tracer,
2. feeds that text to DeepCore's typed protocol parser,
3. builds a deterministic STP prediction from the parsed facts,
4. reads the simulator's own ``show spanning-tree`` / ``show etherchannel summary``,
5. compares the two and records AGREE / DISAGREE / UNDECIDED with raw evidence,
6. re-hashes the source file afterwards.

Rules enforced here (the ones that keep the result honest):

* A prediction is never labelled an observation, and an observation never
  overwrites a prediction. Both are stored.
* Missing evidence is ``UNDECIDED`` / ``NOT_OBSERVED``, never coerced into a
  result. A device whose config states no priority does not get 32768 invented.
* The script never decides for the operator whether a disagreement is a TRIDENT
  bug or a simulator limitation; it records the category as ``UNKNOWN`` and keeps
  the raw text so a human can judge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trident.deepcore.protocols import parse_protocols
from trident.simulator import SimulatorRuntime
from trident.simulator.backends import find_packet_tracer, simulator_version


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cli_devices(session) -> list[str]:
    capable: list[str] = []
    for dev in session.backend.devices():
        name = str(dev.get("name", "")).strip()
        if not name:
            continue
        try:
            probe = session.run_cli(name, "show version", timeout=25)
        except Exception:
            continue
        if probe.ok and probe.raw:
            capable.append(name)
    return capable


def show(session, device: str, command: str) -> dict:
    try:
        res = session.run_cli(device, command, timeout=30)
        return {
            "command": command,
            "device": device,
            "ok": bool(res.ok),
            "observed": bool(res.observed),
            "raw": res.raw or "",
            "error": res.error,
        }
    except Exception as exc:
        return {
            "command": command,
            "device": device,
            "ok": False,
            "observed": False,
            "raw": "",
            "error": f"{type(exc).__name__}: {exc}"[:300],
        }


# --- observation parsing (simulator text -> structure) ---------------------

_ROOT_BRIDGE_RE = re.compile(
    r"^(?P<bridge_id>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\(priority\s+(?P<priority>\d+)",
    re.MULTILINE,
)
_THIS_BRIDGE_RE = re.compile(
    r"Bridge ID\s+Priority\s+\d+\s*\n\s*Address\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
)
_COST_RE = re.compile(r"Root ID\s+.*?Cost\s+(?P<cost>\d+)", re.DOTALL)


def parse_stp_summary(text: str) -> dict:
    """Extract the facts ``show spanning-tree summary`` actually establishes."""
    facts: dict = {"is_root": None, "root_priority": None, "mode": None}
    low = text.lower()
    if "pvst" in low:
        facts["mode"] = "pvst"
    elif "rapid-pvst" in low:
        facts["mode"] = "rapid-pvst"
    elif "mst" in low:
        facts["mode"] = "mst"

    m = re.search(r"Root bridge for:\s*(?P<vlans>.+)", text)
    if m:
        vlans = m.group("vlans").strip().lower()
        facts["is_root"] = vlans in {"default", "all"} or bool(re.search(r"vlan", vlans))
        if facts["is_root"] is False and vlans in {"", "none"}:
            facts["is_root"] = False
    return facts


def parse_etherchannel_summary(text: str) -> dict:
    """Extract channel groups and their protocol from the summary table."""
    facts: dict = {"groups": [], "aggregators": None}
    m = re.search(r"Number of channel-groups in use:\s*(\d+)", text)
    if m:
        facts["aggregators"] = int(m.group(1))
    for line in text.splitlines():
        row = re.match(r"^\s*(?P<group>\d+)\s+(?P<po>Po\S+)\s*\((?P<state>[A-Za-z0-9]+)\)", line)
        if row:
            proto = "unknown"
            if "LACP" in line.upper():
                proto = "lacp"
            elif "PAgP" in line:
                proto = "pagp"
            facts["groups"].append(
                {
                    "group": int(row.group("group")),
                    "port_channel": row.group("po"),
                    "state": row.group("state"),
                    "protocol": proto,
                    "line": line.rstrip(),
                }
            )
    return facts


# --- prediction ------------------------------------------------------------


def predict_stp(configs) -> dict:
    """Turn parsed STP facts into a claim only where they support one."""
    stp = configs.stp
    claim: dict = {
        "mode": stp.mode.value if hasattr(stp.mode, "value") else str(stp.mode),
        "configured_priority": stp.effective_priority(),
        "root_primary_vlans": list(stp.root_primary_vlans),
        "candidate_root": stp.is_candidate_root(),
        "predicted_root_status": None,
        "basis": [],
    }
    # A device that configured `root primary` is predicted to be root. That is a
    # direct consequence of the command, not a guess. A device that configured
    # nothing about priority makes no claim at all.
    if stp.root_primary_vlans:
        claim["predicted_root_status"] = "ROOT"
        claim["basis"].append(
            f"spanning-tree vlan {stp.root_primary_vlans} root primary configured"
        )
    elif stp.effective_priority() is not None:
        claim["basis"].append(
            f"explicit bridge priority {stp.effective_priority()} configured"
        )
    else:
        claim["basis"].append("no priority or root command configured; no root claim made")
    return claim


def compare_stp(prediction: dict, observation: dict, raw: str) -> dict:
    observed_root = observation.get("is_root")
    predicted = prediction.get("predicted_root_status")
    verdict = "UNDECIDED"
    reason = ""

    if observed_root is None:
        # No observation means nothing to compare, whatever was predicted.
        return {
            "verdict": "NOT_OBSERVED",
            "reason": "show spanning-tree summary did not state root status",
            "predicted_root": predicted,
            "observed_root": None,
            "observed_mode": observation.get("mode"),
            "raw_excerpt": "\n".join(raw.splitlines()[:14]),
        }

    observed = "ROOT" if observed_root else "NON_ROOT"
    if predicted is None:
        # DeepCore made no claim, so this is neither agreement nor disagreement.
        # The observation is still recorded: it is simulator fact, and saying so
        # is more useful than discarding it.
        verdict = "UNTESTABLE"
        reason = (
            "DeepCore made no root claim (no priority or root command configured); "
            f"simulator reports {observed}"
        )
    elif predicted == observed:
        verdict = "AGREES"
        reason = f"predicted {predicted}, simulator reports {observed}"
    else:
        verdict = "DISAGREES"
        reason = f"predicted {predicted}, simulator reports {observed}"
    return {
        "verdict": verdict,
        "reason": reason,
        "predicted_root": predicted,
        "observed_root": observed_root,
        "observed_mode": observation.get("mode"),
        "raw_excerpt": "\n".join(raw.splitlines()[:14]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    lab = Path(args.lab).expanduser().resolve()
    if not lab.is_file():
        print(f"LAB_MISSING {lab}", file=sys.stderr)
        return 2

    source_sha = sha256_file(lab)
    bundle = find_packet_tracer()
    bundle_version = simulator_version(bundle) if bundle else "unknown"

    report: dict = {
        "generated_at": datetime.now(UTC).isoformat(),
        "lab": lab.name,
        "source_sha256": source_sha,
        "simulator_version": bundle_version,
        "backend": None,
        "results": [],
        "lifecycle": {},
        "summary": {},
    }

    runtime = SimulatorRuntime(prefer_live=True)
    session = runtime.create_session(lab)
    report["backend"] = session.backend.kind.value
    report["session_id"] = session.session_id

    try:
        for device in cli_devices(session):
            entry: dict = {"device": device}
            cfg = show(session, device, "show running-config")
            entry["config_evidence"] = {
                "ok": cfg["ok"],
                "observed": cfg["observed"],
                "chars": len(cfg["raw"]),
                "sha256": hashlib.sha256(cfg["raw"].encode()).hexdigest()[:16],
            }
            if not cfg["ok"] or not cfg["raw"]:
                entry["verdict"] = "NOT_OBSERVED"
                entry["reason"] = f"no running-config: {cfg['error']}"
                report["results"].append(entry)
                continue

            configs = parse_protocols(cfg["raw"].splitlines())
            prediction = predict_stp(configs)
            entry["prediction"] = prediction

            stp_obs_raw = show(session, device, "show spanning-tree summary")
            stp_obs = parse_stp_summary(stp_obs_raw["raw"]) if stp_obs_raw["ok"] else {}
            entry["stp"] = compare_stp(prediction, stp_obs, stp_obs_raw["raw"])

            eth_raw = show(session, device, "show etherchannel summary")
            parsed_eth = (
                parse_etherchannel_summary(eth_raw["raw"]) if eth_raw["ok"] else {}
            )
            configured_n = len(configs.etherchannels)
            observed_n = parsed_eth.get("aggregators") or 0
            # "0 configured and 0 observed" is not agreement: there is no channel
            # to compare, so nothing was corroborated. Scoring it AGREES would be
            # vacuous confirmation, which is the exact false elevation this
            # harness must avoid.
            if not eth_raw["ok"]:
                eth_verdict = "NOT_OBSERVED"
            elif configured_n == 0 and observed_n == 0:
                eth_verdict = "NOT_APPLICABLE"
            elif configured_n == observed_n:
                eth_verdict = "AGREES"
            else:
                eth_verdict = "DISAGREES"
            entry["etherchannel"] = {
                "configured_count": configured_n,
                "observed_count": observed_n,
                "configured_channels": {
                    k: {"mode": v.mode.value, "protocol": v.protocol, "members": v.members}
                    for k, v in configs.etherchannels.items()
                },
                "observed": parsed_eth,
                "verdict": eth_verdict,
                "raw_excerpt": "\n".join(eth_raw["raw"].splitlines()[-8:]),
            }

            report["results"].append(entry)
    finally:
        report["lifecycle"]["close_note"] = session.close()
        report["lifecycle"]["source_unchanged"] = sha256_file(lab) == source_sha
        report["lifecycle"]["owned_pids_after"] = runtime.owned_pids()

    tally: dict = {}
    for entry in report["results"]:
        for key in ("stp", "etherchannel"):
            verdict = (entry.get(key) or {}).get("verdict", entry.get("verdict", "SKIPPED"))
            tally[f"{key}:{verdict}"] = tally.get(f"{key}:{verdict}", 0) + 1
    report["summary"] = tally

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} | devices={len(report['results'])} | {tally}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
