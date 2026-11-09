"""Inspect Packet Tracer labs without ever starting Packet Tracer.

This is the safe path: it performs static analysis only, using the same
three-engine pipeline the application uses, and touches no simulator process.
Packet Tracer is never launched unless you pass ``--live`` *and* have set
``TRIDENT_ALLOW_LIVE_SIMULATOR=1``.

Usage::

    python -m trident.tools.inspect_labs test-labs/incoming
    python -m trident.tools.inspect_labs some_lab.pka
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SUFFIXES = {".pkt", ".pka", ".pkz", ".xml"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _collect(targets: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in targets:
        path = Path(raw).expanduser()
        if path.is_dir():
            found.extend(
                child for child in sorted(path.rglob("*")) if child.suffix.lower() in SUFFIXES
            )
        elif path.is_file() and path.suffix.lower() in SUFFIXES:
            found.append(path)
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in found:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def inspect(path: Path) -> dict:
    """Static analysis of one lab. Never starts a simulator."""
    import asyncio

    from trident.config import settings
    from trident.ingestion import IngestionError, ingest
    from trident.pipeline import analyze

    result: dict = {
        "file": str(path),
        "name": path.name,
        "bytes": path.stat().st_size,
        "sha256_before": _sha256(path),
    }
    try:
        ingested = ingest(path.name, path.read_bytes(), settings)
    except IngestionError as exc:
        result["status"] = "REJECTED"
        result["error"] = str(exc)
        result["sha256_after"] = _sha256(path)
        result["unchanged"] = result["sha256_before"] == result["sha256_after"]
        return result

    try:
        outcome = asyncio.run(analyze(ingested, "q", settings, use_ai=False))
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        result["status"] = "ANALYSIS_FAILED"
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["sha256_after"] = _sha256(path)
        result["unchanged"] = result["sha256_before"] == result["sha256_after"]
        return result

    response = outcome.response
    phase3 = response.phase3 or {}
    result.update(
        {
            "status": "ANALYZED" if outcome.model.devices else "NO_NETWORK_EXTRACTED",
            "engines": {p.engine: p.state.value for p in response.parsers},
            "engine_errors": {
                p.engine: p.message for p in response.parsers if p.state.value != "OK"
            },
            "devices": len(outcome.model.devices),
            "links": len(outcome.model.links),
            "interfaces": len(outcome.model.interfaces),
            "routes": len(outcome.model.routes),
            "vlans": len(outcome.model.vlans),
            "snapshot": response.snapshot_id,
            "snapshot_ambiguous": response.snapshot_ambiguous,
            "findings": phase3.get("findings", []),
            "escalatable": phase3.get("escalatable", 0),
            "warnings": response.warnings[:6],
        }
    )
    if not outcome.model.devices:
        result["note"] = (
            "no devices extracted: .pka files often carry empty snapshot blocks or an "
            "assessment wrapper rather than network configuration"
        )
    result["sha256_after"] = _sha256(path)
    result["unchanged"] = result["sha256_before"] == result["sha256_after"]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trident.tools.inspect_labs",
        description=(
            "Static analysis of Packet Tracer labs. Does NOT start Packet Tracer "
            "unless --live is passed and TRIDENT_ALLOW_LIVE_SIMULATOR=1 is set."
        ),
    )
    parser.add_argument("targets", nargs="+", help="files or directories")
    parser.add_argument("--json", default=None, help="write the full result as JSON here")
    parser.add_argument(
        "--live",
        action="store_true",
        help="also open each lab in Packet Tracer (requires TRIDENT_ALLOW_LIVE_SIMULATOR=1)",
    )
    args = parser.parse_args(argv)

    paths = _collect(args.targets)
    if not paths:
        print("no .pkt/.pka/.pkz/.xml files found in the given targets")
        return 1

    live = args.live
    if live:
        from trident.simulator.backends import live_allowed

        if not live_allowed():
            print(
                "refusing to launch Packet Tracer: --live was passed but "
                "TRIDENT_ALLOW_LIVE_SIMULATOR is not set to 1.\n"
                "Static analysis will run instead. Packet Tracer was NOT started."
            )
            live = False

    results = []
    for path in paths:
        print(f"\n=== {path}")
        result = inspect(path)
        if live:
            result["live"] = _inspect_live(path)
        results.append(result)

        print(f"  {result['status']}  {result['bytes']} bytes")
        if result.get("error"):
            print(f"  error: {result['error']}")
        if result["status"] == "ANALYZED":
            engines = result["engines"]
            print(
                f"  engines: A={engines.get('engine_a')} B={engines.get('engine_b')} "
                f"C={engines.get('engine_c')}"
            )
            print(
                f"  devices={result['devices']} links={result['links']} "
                f"interfaces={result['interfaces']} routes={result['routes']} "
                f"vlans={result['vlans']} snapshot={result['snapshot'] or 'none'}"
            )
            findings = result["findings"]
            if findings:
                for finding in findings:
                    where = " ".join(
                        str(x) for x in (finding.get("device"), finding.get("interface")) if x
                    )
                    print(f"  finding: {finding['kind']:26} {where} ({finding['confidence']})")
            else:
                print("  findings: none")
            if result["escalatable"]:
                print(f"  operationally testable gaps: {result['escalatable']}")
        if result.get("live"):
            live_result = result["live"]
            if live_result.get("ok"):
                print(f"  live: {live_result['devices']} devices — {live_result['names']}")
            else:
                print(f"  live: unavailable — {live_result.get('error')}")
        print(f"  original unchanged: {result['unchanged']}")

    analyzed = [r for r in results if r["status"] == "ANALYZED"]
    empty = [r for r in results if r["status"] == "NO_NETWORK_EXTRACTED"]
    failed = [r for r in results if r["status"] in {"REJECTED", "ANALYSIS_FAILED"}]
    changed = [r for r in results if not r["unchanged"]]

    print("\n=== SUMMARY")
    print(f"  files: {len(results)}")
    print(f"  analyzed: {len(analyzed)}")
    print(f"  no network extracted: {len(empty)}")
    print(f"  rejected/failed: {len(failed)}")
    print(f"  originals unchanged: {len(results) - len(changed)}/{len(results)}")
    if changed:
        print("  WARNING: some original files changed:")
        for record in changed:
            print(f"    {record['file']}")

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print(f"  json: {args.json}")

    return 0 if not changed else 2


def _inspect_live(path: Path) -> dict:
    """Open one lab in a live session. Only called when explicitly allowed."""
    from trident.simulator import SimulatorRuntime

    runtime = SimulatorRuntime(prefer_live=True)
    try:
        session = runtime.create_session(path)
    except Exception as exc:  # noqa: BLE001 - reported
        return {"ok": False, "error": str(exc)}
    try:
        names = [device["name"] for device in session.backend.devices()]
        samples = {}
        for name in names[:3]:
            try:
                result = session.run_cli(name, "show ip interface brief", timeout=45)
                samples[name] = result.raw.splitlines()[:4]
            except Exception:  # noqa: BLE001 - a device may not be a CLI device
                samples[name] = []
        return {
            "ok": True,
            "live": session.is_live,
            "devices": len(names),
            "names": names,
            "samples": samples,
        }
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
