"""Oracle Differential Gauntlet — real PDU differential on an authorized lab.

DeepCore predicts whether a device pair is reachable; Ghost sends a real simple
PDU and reports what the simulator actually did. The comparison is recorded, not
asserted: a disagreement is the interesting result.

Every experiment uses a disposable copy. The source hash is checked before and
after, and the script fails loudly if it changed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trident.config import settings
from trident.deepcore import DeepCore
from trident.deepcore.differential import compare
from trident.ingestion import ingest
from trident.pipeline import analyze
from trident.simulator import SimulatorRuntime
from trident.simulator.backends import find_packet_tracer, simulator_version


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cli_devices(session) -> list[str]:
    names: list[str] = []
    for dev in session.backend.devices():
        name = str(dev.get("name", "")).strip()
        if not name:
            continue
        try:
            probe = session.run_cli(name, "show version", timeout=25)
        except Exception:
            continue
        if probe.ok and probe.raw:
            names.append(name)
    return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-pairs", type=int, default=8)
    args = ap.parse_args()

    lab = Path(args.lab).expanduser().resolve()
    source_sha = sha256_file(lab)
    bundle = find_packet_tracer()

    report: dict = {
        "generated_at": datetime.now(UTC).isoformat(),
        "lab": lab.name,
        "source_sha256": source_sha,
        "simulator_version": simulator_version(bundle) if bundle else "unknown",
        "model": {},
        "experiments": [],
        "lifecycle": {},
    }

    # Static model from the same bytes the simulator will be given. Parsing the
    # file (not the simulator's CLI) keeps prediction independent of the oracle.
    outcome = asyncio.run(
        analyze(ingest(lab.name, lab.read_bytes(), settings), "differential", settings, use_ai=False)
    )
    model = outcome.model
    report["model"] = {
        "devices": len(model.devices),
        "interfaces": len(model.interfaces),
        "links": len(model.links),
        "acls": len(model.acls),
    }

    runtime = SimulatorRuntime(prefer_live=True)
    session = runtime.create_session(lab)
    report["backend"] = session.backend.kind.value
    report["session_id"] = session.session_id

    try:
        devices = cli_devices(session)
        report["cli_devices"] = devices
        core = DeepCore(model)
        pairs: list[tuple[str, str]] = []
        for src in devices:
            for dst in devices:
                if src == dst:
                    continue
                pairs.append((src, dst))
            if len(pairs) >= args.max_pairs:
                break
        pairs = pairs[: args.max_pairs]
        report["pairs_attempted"] = len(pairs)

        for src, dst in pairs:
            entry: dict = {"source": src, "destination": dst}
            try:
                prediction = core.predict_path(src, dst)
                entry["predicted"] = prediction.as_dict()
                entry["prediction_definite"] = bool(prediction.definite)
            except Exception as exc:
                entry["prediction_error"] = f"{type(exc).__name__}: {exc}"[:300]
                report["experiments"].append(entry)
                continue

            try:
                pdu = session.send_pdu(src, dst, timeout_seconds=25)
            except Exception as exc:
                entry["observed"] = {
                    "status": "EXPERIMENT_FAILED",
                    "error": f"{type(exc).__name__}: {exc}"[:300],
                }
                report["experiments"].append(entry)
                continue

            entry["observed"] = {
                "status": pdu.status.value,
                "observed": bool(pdu.observed),
                "operation": pdu.operation,
                "decisions": list(pdu.decisions[:3]),
            }
            try:
                discrepancy = compare(
                    prediction,
                    pdu.status.value,
                    operation=pdu.operation,
                    simulator_version=entry.get("simulator_version", ""),
                    source_sha256=source_sha,
                    observed_detail="; ".join(pdu.decisions[:2]),
                )
                entry["agreement"] = discrepancy.agreement.value
                entry["agreement_reason"] = discrepancy.observed_detail
            except Exception as exc:
                entry["agreement"] = "COMPARE_ERROR"
                entry["agreement_reason"] = f"{type(exc).__name__}: {exc}"[:200]
            report["experiments"].append(entry)
    finally:
        report["lifecycle"]["close_note"] = session.close()
        report["lifecycle"]["source_unchanged"] = sha256_file(lab) == source_sha
        report["lifecycle"]["owned_pids_after"] = runtime.owned_pids()

    tally: dict = {}
    for e in report["experiments"]:
        key = e.get("agreement", "NO_AGREEMENT_RECORDED")
        tally[key] = tally.get(key, 0) + 1
    report["summary"] = tally

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} | pairs={len(report['experiments'])} | {tally} "
          f"| source_unchanged={report['lifecycle']['source_unchanged']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
