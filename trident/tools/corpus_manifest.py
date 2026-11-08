"""Read-only PKA corpus manifest builder.

Scans a directory you own for ``.pka`` / ``.pkt`` files and records structural
facts about each one. It never copies, moves, uploads or modifies a file, and
prints no configuration contents (names/IPs stay out of the report).

Usage:
    python -m trident.tools.corpus_manifest [--dir DIR] [--json OUT] [--limit N]

Resolution order for the directory: ``--dir``, ``$TRIDENT_TEST_CORPUS_DIR``,
then ``tests/fixtures``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_SNAPSHOT_RE = re.compile(r"<PACKETTRACER5>(.*?)</PACKETTRACER5>", re.DOTALL)
_DEVICE_OPEN_RE = re.compile(r"<DEVICE[ />]")
_LINK_OPEN_RE = re.compile(r"<LINK[ />]")
_VERSION_RE = re.compile(r"<VERSION>(.*?)</VERSION>", re.DOTALL)


def _decode(raw: bytes) -> str:
    """Decode a container with Engine A's vendored decoder (read-only)."""
    import os as _os

    sys.path.insert(0, str(REPO_ROOT / "vendor" / "engine_a"))
    lib = REPO_ROOT / "vendor" / "engine_a" / "pka2xml"
    for name in ("libtwofish.dylib", "libtwofish.so", "libtwofish.dll"):
        candidate = lib / name
        if candidate.exists():
            _os.environ.setdefault("LIBTWOFISH", str(candidate))
            break
    from pka2xml import decrypt_pka

    return decrypt_pka(raw).decode("utf-8", errors="replace")


def _reference_ranges(xml: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for tag in ("COMPARISONS", "INITIALSETUP", "CLEAN_ACTIVITY", "ACTIVITY"):
        for m in re.finditer(rf"<{tag}>.*?</{tag}>", xml, re.DOTALL):
            ranges.append((m.start(), m.end()))
    return ranges


def _snapshot_summary(xml: str) -> dict:
    ref = _reference_ranges(xml)
    blocks = []
    for index, m in enumerate(_SNAPSHOT_RE.finditer(xml)):
        body = m.group(1)
        in_ref = any(m.start() >= a and m.end() <= b for a, b in ref)
        blocks.append(
            {
                "index": index,
                "devices": len(_DEVICE_OPEN_RE.findall(body)),
                "links": len(_LINK_OPEN_RE.findall(body)),
                "chars": len(body),
                "in_reference_wrapper": in_ref,
            }
        )
    candidates = [b for b in blocks if not b["in_reference_wrapper"]]
    non_empty = [b for b in candidates if b["devices"] > 0]
    if not blocks:
        selection = "root"
    elif not non_empty:
        selection = "abstain-empty"
    elif len(non_empty) == 1:
        selection = f"block{non_empty[0]['index']}"
    else:
        selection = "abstain-ambiguous"
    return {
        "blocks": blocks,
        "count": len(blocks),
        "selection": selection,
        "has_reference_networks": any(b["in_reference_wrapper"] for b in blocks) or bool(ref),
    }


def inspect_file(path: Path) -> dict:
    raw = path.read_bytes()
    entry: dict = {
        "file": path.name,
        "path": str(path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "format": path.suffix.lower().lstrip("."),
    }
    try:
        xml = _decode(raw)
    except Exception as exc:  # noqa: BLE001 - report, never crash the scan
        entry.update({"decoded": False, "decode_error": f"{type(exc).__name__}: {exc}"})
        return entry

    entry["decoded"] = True
    entry["xml_bytes"] = len(xml)
    m = _VERSION_RE.search(xml)
    entry["pt_version"] = m.group(1).strip() if m else "?"
    entry["root_tag"] = (re.search(r"<([A-Za-z0-9_]+)", xml.lstrip()) or [None, "?"])[1]
    entry["snapshots"] = _snapshot_summary(xml)
    return entry


def default_corpus_dir() -> Path:
    env = os.environ.get("TRIDENT_TEST_CORPUS_DIR", "").strip()
    if env:
        return Path(env).expanduser()
    return REPO_ROOT / "tests" / "fixtures"


def collect(directory: Path, limit: int | None = None) -> list[Path]:
    if not directory.is_dir():
        raise FileNotFoundError(f"corpus directory does not exist: {directory}")
    files = sorted(
        p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in {".pka", ".pkt"}
    )
    return files[:limit] if limit else files


def build_manifest(directory: Path, limit: int | None = None) -> dict:
    entries = [inspect_file(p) for p in collect(directory, limit)]
    return {
        "corpus_dir": str(directory),
        "files_found": len(entries),
        "decoded": sum(1 for e in entries if e.get("decoded")),
        "files": entries,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build a read-only PKA corpus manifest")
    ap.add_argument("--dir", default=None, help="corpus directory (default: env or tests/fixtures)")
    ap.add_argument("--json", default=None, help="write JSON manifest to this path")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)

    directory = Path(args.dir).expanduser() if args.dir else default_corpus_dir()
    manifest = build_manifest(directory, args.limit)

    if args.json:
        Path(args.json).write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"manifest written to {args.json} ({manifest['files_found']} files)")
    else:
        print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
