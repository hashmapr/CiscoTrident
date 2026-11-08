"""Multi-network benchmark runner for the TRIDENT practice-benchmark pack.

Runs each network's blind question set through the **production** pipeline, then
grades against the separately-supplied key. The key is never passed to the solver.

Usage:
    python -m trident.tools.benchmark_pack --pack DIR [--slug SLUG] [--json OUT]

Sources may be:
  * ``.pka``  -> full three-engine production path
  * ``.xml``  -> XML-only mode (deterministic analysis; reported separately,
                 because it does not exercise container decode)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import re
import sys
from dataclasses import asdict, dataclass, field

_IFACE_ALIASES = {
    "gi": "gigabitethernet",
    "gig": "gigabitethernet",
    "gigabit": "gigabitethernet",
    "fa": "fastethernet",
    "fast": "fastethernet",
    "se": "serial",
    "te": "tengigabitethernet",
    "po": "port-channel",
    "vl": "vlan",
}


def canon_iface(text: str) -> str:
    t = re.sub(r"\s+", "", (text or "").lower())
    t = t.replace("gigabitethernet", "gigabitethernet")
    m = re.match(r"([a-z\-]+?)(\d.*)$", t)
    if not m:
        return t
    prefix, rest = m.group(1), m.group(2)
    for short, full in sorted(_IFACE_ALIASES.items(), key=lambda x: -len(x[0])):
        if prefix == short:
            return full + rest
    return prefix + rest


def _norm(text) -> str:
    if isinstance(text, (list, tuple, set)):
        text = ", ".join(str(x) for x in text)
    return " ".join(str(text or "").split()).strip().lower()


def _split_multi(text: str) -> set[str]:
    parts = re.split(r"[,;]|\band\b", text or "")
    return {_norm(p) for p in parts if p.strip()}


def _device_aliases(model) -> dict[str, set[str]]:
    """Map every accepted device label (display name and hostname) to one key."""
    out: dict[str, set[str]] = {}
    if model is None:
        return out
    for key, info in model.devices.items():
        labels = {_norm(key)}
        if info.hostname:
            labels.add(_norm(info.hostname))
        out[_norm(key)] = labels
    return out


def _same_device(model, a: str, b: str) -> bool:
    """True when two labels name the same device (display name or hostname)."""
    if model is None:
        return _norm(a) == _norm(b)
    na, nb = _norm(a), _norm(b)
    info_a = next((i for k, i in model.devices.items() if _norm(k) == na), None)
    if info_a is None:
        info_a = next(
            (i for i in model.devices.values() if _norm(i.hostname or "") == na), None
        )
    if info_a is None:
        return na == nb
    candidates = {_norm(info_a.name)}
    if info_a.hostname:
        candidates.add(_norm(info_a.hostname))
    return nb in candidates


def _resolve_expected(model, text: str) -> str:
    """Resolve ``[[...]]`` placeholders that appear in the *key's* expected value.

    Some benchmark keys were generated from the raw XML, so an expected device
    name can still be a placeholder. Grading must compare like with like.
    """
    if not text or "[[" not in text or model is None:
        return text
    mapping = getattr(model, "placeholder_map", {}) or {}
    if not mapping:
        return text
    import re as _re

    return _re.sub(
        r"\[\[([^\]]+)\]\]", lambda m: mapping.get(m.group(1).strip(), m.group(0)), text
    )


def grade(question: dict, actual: str, model=None) -> bool:
    """Semantic comparison appropriate to the question's declared answer type."""
    if not actual or not actual.strip():
        return False
    qtype = (question.get("answer_type") or "").lower()
    expected = question.get("answer")
    if isinstance(expected, (list, tuple)):
        expected = ", ".join(_resolve_expected(model, str(x)) for x in expected)
    expected = _resolve_expected(model, expected or "")
    alternates = [
        _resolve_expected(model, str(a)) for a in (question.get("acceptable_alternates") or [])
    ]
    candidates = [expected, *alternates]

    if qtype in {"interface_name", "interface"}:
        want = {canon_iface(c) for c in candidates if c}
        return canon_iface(actual) in want

    if qtype in {"device_set", "device_list", "set", "unordered_device_set"}:
        got = [x for x in _split_multi(actual)]
        for cand in candidates:
            want = _split_multi(cand)
            if len(want) != len(got):
                continue
            unmatched = list(got)
            ok_all = True
            for w in want:
                hit = next((g for g in unmatched if _same_device(model, g, w)), None)
                if hit is None:
                    ok_all = False
                    break
                unmatched.remove(hit)
            if ok_all and not unmatched:
                return True
        return False

    if qtype in {"integer", "number", "count", "derived_prefix_length"}:
        answer = _norm(actual)
        if not re.fullmatch(r"-?\d+", answer):
            return False
        return any(answer == _norm(str(c)) for c in candidates if str(c).strip())

    if qtype in {"boolean", "bool"}:
        low = _norm(actual)
        yes = str(expected).strip().lower() in {"true", "yes"}
        return (low in {"true", "yes"}) if yes else (low in {"false", "no"})

    if qtype in {"ipv4", "ip", "ip_address", "ipv4_address", "ipv4_subnet_mask", "mask"}:
        # Strict: the answer must BE one of the accepted values, not contain it
        # inside a longer sentence or list.
        answer = _norm(actual)
        return any(_norm(c) == answer for c in candidates if c)

    if qtype in {"device_name", "device"}:
        return any(_same_device(model, actual, c) for c in candidates if c)

    # default: strict normalised equality. No substring containment -- an answer
    # that merely contains the expected value is not the expected value.
    low_actual = _norm(actual)
    return any(_norm(c) == low_actual for c in candidates if c)


@dataclass
class Row:
    id: str
    question: str
    category: str
    expected: str
    actual: str
    status: str
    correct: bool
    category_result: str = ""
    explanation: str = ""


@dataclass
class Report:
    slug: str
    source: str
    rows: list[Row] = field(default_factory=list)
    runtime_s: float = 0.0
    snapshot: str = ""
    devices: int = 0
    links: int = 0
    parser_states: dict = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.rows)

    @property
    def correct(self) -> int:
        return sum(1 for r in self.rows if r.correct)

    @property
    def verified(self) -> list[Row]:
        return [r for r in self.rows if r.status in ("VERIFIED", "VERIFIED_DERIVED")]

    @property
    def false_verified(self) -> list[Row]:
        return [r for r in self.verified if not r.correct]

    @property
    def verified_precision(self) -> float:
        v = self.verified
        return (sum(1 for r in v if r.correct) / len(v) * 100) if v else 0.0

    def by_category(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for row in self.rows:
            bucket = out.setdefault(row.category, {"total": 0, "correct": 0})
            bucket["total"] += 1
            bucket["correct"] += int(row.correct)
        return out

    def summary(self) -> dict:
        return {
            "slug": self.slug,
            "source": self.source,
            "total": self.total,
            "correct": self.correct,
            "incorrect": self.total - self.correct,
            "accuracy_pct": round(self.correct / self.total * 100, 1) if self.total else 0.0,
            "verified_total ": 0,
            "verified": len(self.verified),
            "verified_precision_pct": round(self.verified_precision, 1),
            "false_verified": len(self.false_verified),
            "abstained": sum(1 for r in self.rows if r.status in ("NOT_AVAILABLE", "INCOMPLETE")),
            "runtime_s": round(self.runtime_s, 1),
            "snapshot": self.snapshot,
            "devices": self.devices,
            "links": self.links,
            "parsers": self.parser_states,
            "categories": self.by_category(),
        }


def run_network(pack: pathlib.Path, slug: str, use_ai: bool = False) -> Report:
    import time

    entry = pack / slug
    key = json.loads((entry / "BENCHMARK_WITH_KEY.json").read_text())
    questions = key["questions"]
    manifest = json.loads((entry / "MANIFEST.json").read_text()) if (entry / "MANIFEST.json").exists() else {}

    # Resolve the source XML from the manifest, falling back to the key's own
    # manifest block, then to a filename heuristic.
    candidates = sorted((pack / "source_xml").glob("*.xml"))
    name = (
        manifest.get("source_xml")
        or manifest.get("source_file")
        or key.get("manifest", {}).get("source_xml")
        or key.get("manifest", {}).get("source_file")
    )
    source_xml = None
    if name:
        guess = pack / "source_xml" / name
        if guess.exists():
            source_xml = guess
    if source_xml is None:
        tokens = [t for t in slug.lower().split("_") if t]
        scored = sorted(
            candidates,
            key=lambda p: -sum(1 for t in tokens if t in p.name.lower()),
        )
        source_xml = scored[0] if scored else None
    if source_xml is None or not source_xml.exists():
        raise SystemExit(f"no source XML found for {slug} in {pack/'source_xml'}")

    from trident.ingestion import ingest
    from trident.pipeline import analyze

    # Solver receives question text only.
    blind = "\n".join(f"{q['id'][1:]}. {q['question']}" for q in questions)

    raw = source_xml.read_bytes()
    t0 = time.time()
    outcome = asyncio.run(
        analyze(ingest(source_xml.name, raw), blind, use_ai=use_ai)
    )
    runtime = time.time() - t0

    by_num = {}
    for result in outcome.response.results:
        by_num[result.question_number] = result

    report = Report(slug=slug, source=source_xml.name, runtime_s=runtime)
    report.snapshot = outcome.response.snapshot_id
    report.devices = outcome.response.network_summary.get("devices", 0)
    report.links = outcome.response.network_summary.get("links", 0)
    report.parser_states = {
        p.engine: p.state.value for p in outcome.response.parsers
    }

    for q in questions:
        number = int(q["id"][1:])
        result = by_num.get(number)
        actual = (result.answer if result else "") or ""
        status = result.status.value if result else "MISSING"
        ok = grade(q, actual, outcome.model)
        bucket = ""
        if not ok:
            bucket = "FALSE_VERIFIED" if status in ("VERIFIED", "VERIFIED_DERIVED") else status
        report.rows.append(
            Row(
                id=q["id"],
                question=q["question"],
                category=q.get("category") or "",
                expected=q.get("answer") or "",
                actual=actual,
                status=status,
                correct=ok,
                category_result=bucket,
                explanation=(result.explanation or "")[:220] if result else "",
            )
        )
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the TRIDENT benchmark pack")
    ap.add_argument("--pack", default=str(pathlib.Path.home() / "Downloads" / "TRIDENT_4_Network_Benchmark_Pack"))
    ap.add_argument("--slug", action="append", default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--ai", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    pack = pathlib.Path(args.pack).expanduser()
    if not pack.is_dir():
        print(f"pack not found: {pack}", file=sys.stderr)
        return 2

    slugs = args.slug or sorted(
        p.name for p in pack.iterdir() if (p / "BENCHMARK_WITH_KEY.json").exists()
    )

    reports = []
    for slug in slugs:
        print(f"\n=== {slug} ===", flush=True)
        report = run_network(pack, slug, args.ai)
        reports.append(report)
        s = report.summary()
        print(
            f"{s['correct']}/{s['total']} ({s['accuracy_pct']}%)  "
            f"verified {s['verified']} precision {s['verified_precision_pct']}%  "
            f"FALSE-VERIFIED {s['false_verified']}  "
            f"devices {s['devices']} links {s['links']} snapshot {s['snapshot']} "
            f"{s['runtime_s']}s",
            flush=True,
        )
        if args.verbose:
            for row in report.rows:
                if not row.correct:
                    print(
                        f"  FAIL {row.id} [{row.category}] {row.status}: "
                        f"got {row.actual[:50]!r} want {row.expected[:40]!r}",
                        flush=True,
                    )

    payload = {"networks": [r.summary() for r in reports]}
    if args.json:
        out = pathlib.Path(args.json)
        out.write_text(
            json.dumps(
                {**payload, "rows": {r.slug: [asdict(x) for x in r.rows] for r in reports}},
                indent=2,
            )
            + "\n"
        )
        print(f"\nwritten: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
