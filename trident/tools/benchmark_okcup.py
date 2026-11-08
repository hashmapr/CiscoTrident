"""65-question benchmark harness for the OK Cup PKA.

The questions are the ones audited in this repo; the expected answers are the
independently established values from the packet-tracer XML source (display
names, cable endpoints, running configs), not from TRIDENT's own output.

Expected answers are never visible to the solver: this module builds the question
text, runs the production pipeline, and only then compares.

Usage:
    python -m trident.tools.benchmark_okcup [--file PATH] [--json OUT] [--ai]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import asdict, dataclass, field

MH = "Main Hub Switch (Layer 3) (The Brainiac)"
N1 = "Node One Router (Our Loyal Minion)"
N1S = "Node One Switch (Our Network Sidekick)"
N2 = "Node Two Router (Another Loyal Minion)"
N2S = "Node Two Switch (Our Other Network Sidekick)"
SYM = "Symbiote Router (Our Pride and Joy)"
SYS = "Symbiote Switch (Our Network Backbone)"
RT = "Internet (Router) 1"
SW = "Internet (Layer 2 Switch) 1"

#: (question_number, question, expected_answer, kind)
#: kind: exact | set | number | text
BENCHMARK: list[tuple[int, str, str, str]] = [
    (1, f"Which device is connected to {MH} GigabitEthernet1/0/2?", N1, "exact"),
    (2, f"What is the peer interface on {N1} for GigabitEthernet0/0?", "GigabitEthernet1/0/2", "iface"),
    (3, f"Which device is connected to {N1} GigabitEthernet0/1?", N1S, "exact"),
    (4, f"What is the peer interface on {N1} for GigabitEthernet0/1?", "GigabitEthernet0/1", "iface"),
    (5, f"Which device is connected to {N1S} FastEthernet0/1?", "Node One PC", "exact"),
    (6, f"What is the peer interface on {N1S} for FastEthernet0/1?", "FastEthernet0", "iface"),
    (7, f"Which device is connected to {N2S} FastEthernet0/1?", "Node Two PC", "exact"),
    (8, f"What is the peer interface on {N2S} for FastEthernet0/1?", "FastEthernet0", "iface"),
    (9, f"Which device is connected to {N2S} GigabitEthernet0/1?", N2, "exact"),
    (10, f"What is the peer interface on {N2S} for GigabitEthernet0/1?", "GigabitEthernet0/1", "iface"),
    (11, f"Which device is connected to {N2} GigabitEthernet0/0?", MH, "exact"),
    (12, f"What is the peer interface on {N2} for GigabitEthernet0/0?", "GigabitEthernet1/0/3", "iface"),
    (13, "Which device is connected to Hub Switch 1 (Our Trusty Sidekick) FastEthernet0/2?", "Main Hub PC 1", "exact"),
    (14, "What is the peer interface on Hub Switch 1 (Our Trusty Sidekick) for FastEthernet0/2?", "FastEthernet0", "iface"),
    (15, "Which device is connected to Hub Switch 1 (Our Trusty Sidekick) FastEthernet0/3?", "Main Hub PC 2", "exact"),
    (16, "What is the peer interface on Hub Switch 1 (Our Trusty Sidekick) for FastEthernet0/3?", "FastEthernet0", "iface"),
    (17, "Which device is connected to Hub Switch 1 (Our Trusty Sidekick) FastEthernet0/1?", MH, "exact"),
    (18, "What is the peer interface on Hub Switch 1 (Our Trusty Sidekick) for FastEthernet0/1?", "GigabitEthernet1/0/4", "iface"),
    (19, "Which device is connected to Hub Switch 2 (Another Trusty Sidekick) FastEthernet0/2?", "Main Hub PC 3", "exact"),
    (20, "What is the peer interface on Hub Switch 2 (Another Trusty Sidekick) for FastEthernet0/2?", "FastEthernet0", "iface"),
    (21, "Which device is connected to Hub Switch 2 (Another Trusty Sidekick) FastEthernet0/3?", "Main Hub Server", "exact"),
    (22, "What is the peer interface on Hub Switch 2 (Another Trusty Sidekick) for FastEthernet0/3?", "FastEthernet0", "iface"),
    (23, "Which device is connected to Hub Switch 1 (Our Trusty Sidekick) GigabitEthernet0/1?", "Hub Switch 2 (Another Trusty Sidekick)", "exact"),
    (24, "What is the peer interface on Hub Switch 1 (Our Trusty Sidekick) for GigabitEthernet0/1?", "GigabitEthernet0/1", "iface"),
    (25, "Which device is connected to Hub Switch 2 (Another Trusty Sidekick) FastEthernet0/1?", MH, "exact"),
    (26, "What is the peer interface on Hub Switch 2 (Another Trusty Sidekick) for FastEthernet0/1?", "GigabitEthernet1/0/5", "iface"),
    (27, "Which device is connected to Symbiote Switch (Our Network Backbone) FastEthernet0/1?", "Symbiotes Den Server", "exact"),
    (28, "What is the peer interface on Symbiote Switch (Our Network Backbone) for FastEthernet0/1?", "FastEthernet0", "iface"),
    (29, "Which device is connected to Symbiote Switch (Our Network Backbone) GigabitEthernet0/1?", SYM, "exact"),
    (30, "What is the peer interface on Symbiote Switch (Our Network Backbone) for GigabitEthernet0/1?", "GigabitEthernet0/1", "iface"),
    (31, f"Which device is connected to {SYM} GigabitEthernet0/0?", MH, "exact"),
    (32, f"What is the peer interface on {SYM} for GigabitEthernet0/0?", "GigabitEthernet1/0/10", "iface"),
    (33, f"Which device is connected to {MH} GigabitEthernet1/0/1?", RT, "exact"),
    (34, f"What is the peer interface on {MH} for GigabitEthernet1/0/1?", "GigabitEthernet0/1", "iface"),
    (35, f"Which device is connected to {RT} GigabitEthernet0/0?", SW, "exact"),
    (36, f"What is the peer interface on {RT} for GigabitEthernet0/0?", "GigabitEthernet0/1", "iface"),
    (37, f"Which device is connected to {SW} FastEthernet0/1?", "Internet (Server) 1", "exact"),
    (38, f"What is the peer interface on {SW} for FastEthernet0/1?", "FastEthernet0", "iface"),
    (39, f"What is the model of {N1}?", "2911", "text"),
    (40, f"What is the model of {N2}?", "2911", "text"),
    (41, f"What is the model of {MH}?", "3650-24PS", "text"),
    (42, f"What is the model of {SYM}?", "2911", "text"),
    (43, f"What is the model of {RT}?", "2911", "text"),
    (44, f"What is the model of {SW}?", "2960-24TT", "text"),
    (45, f"Which devices are directly connected to {MH}?", "Hub Switch 1 (Our Trusty Sidekick)|Hub Switch 2 (Another Trusty Sidekick)|Internet (Router) 1|Node One Router (Our Loyal Minion)|Node Two Router (Another Loyal Minion)|Symbiote Router (Our Pride and Joy)", "set"),
    (46, "Which devices are directly connected to Hub Switch 1 (Our Trusty Sidekick)?", "Hub Switch 2 (Another Trusty Sidekick)|Main Hub PC 1|Main Hub PC 2|Main Hub Switch (Layer 3) (The Brainiac)", "set"),
    (47, "Which devices are directly connected to Hub Switch 2 (Another Trusty Sidekick)?", "Hub Switch 1 (Our Trusty Sidekick)|Main Hub PC 3|Main Hub Server|Main Hub Switch (Layer 3) (The Brainiac)", "set"),
    (48, f"Which devices are directly connected to {N1}?", "Main Hub Switch (Layer 3) (The Brainiac)|Node One Switch (Our Network Sidekick)", "set"),
    (49, f"Which devices are directly connected to {N2}?", "Main Hub Switch (Layer 3) (The Brainiac)|Node Two Switch (Our Other Network Sidekick)", "set"),
    (50, f"Which devices are directly connected to {SYM}?", "Main Hub Switch (Layer 3) (The Brainiac)|Symbiote Switch (Our Network Backbone)", "set"),
    (51, f"Which devices are directly connected to {RT}?", "Internet (Layer 2 Switch) 1|Main Hub Switch (Layer 3) (The Brainiac)", "set"),
    (52, "How many physical links are in the network?", "19", "number"),
    (53, "How many devices are in the network?", "20", "number"),
    (54, f"What is the hostname of {RT}?", "OpenSeas", "text"),
    (55, f"What is the hostname of {SW}?", "AtWorldsEnd", "text"),
    (56, f"What is the IP address of {RT} GigabitEthernet0/0?", "44.102.3.1", "ip"),
    (57, f"What is the subnet mask of {RT} GigabitEthernet0/0?", "255.255.255.0", "mask"),
    (58, f"What is the network address of {RT} GigabitEthernet0/0?", "44.102.3.0", "ip"),
    (59, f"What is the IP address of {RT} GigabitEthernet0/1?", "34.130.13.1", "ip"),
    (60, f"What is the subnet mask of {RT} GigabitEthernet0/1?", "255.255.255.0", "mask"),
    (61, f"What is the network address of {RT} GigabitEthernet0/1?", "34.130.13.0", "ip"),
    (62, f"What is the default route next hop on {RT}?", "34.130.13.2", "ip"),
    (63, f"What is the IP address of {SW} Vlan1?", "44.102.3.2", "ip"),
    (64, f"What is the default gateway of {SW}?", "44.102.3.1", "ip"),
    (65, f"Are {RT} GigabitEthernet0/0 and {SW} Vlan1 in the same subnet?", "true", "bool"),
]

_IFACE_CANON = {
    "gi": "gigabitethernet",
    "gig": "gigabitethernet",
    "gigabit": "gigabitethernet",
    "fa": "fastethernet",
    "fast": "fastethernet",
    "vl": "vlan",
}


def canon_iface(text: str) -> str:
    """Canonicalise an interface name so Gi0/1 == GigabitEthernet0/1."""
    t = re.sub(r"\s+", "", (text or "").lower())
    m = re.match(r"([a-z\-]+?)(\d.*)$", t)
    if not m:
        return t
    prefix, rest = m.group(1), m.group(2)
    for short, full in _IFACE_CANON.items():
        if prefix.startswith(short):
            return full + rest
    return prefix + rest


def _norm(text: str) -> str:
    return " ".join((text or "").split()).strip().lower()


def grade(kind: str, expected: str, actual: str) -> bool:
    """Compare semantically: interface aliases, unordered sets, capitalisation."""
    if not actual:
        return False
    if kind == "iface":
        return canon_iface(expected) == canon_iface(actual)
    if kind == "set":
        want = {_norm(x) for x in expected.split("|") if x.strip()}
        got = {_norm(x) for x in re.split(r"[,;]", actual) if x.strip()}
        return want == got
    if kind == "number":
        return re.search(rf"(?<!\d){re.escape(expected)}(?!\d)", actual) is not None
    if kind == "bool":
        low = _norm(actual)
        return (expected == "true" and low in {"true", "yes"}) or (
            expected == "false" and low in {"false", "no"}
        )
    if kind == "ip":
        return expected in actual
    return _norm(expected) == _norm(actual)


@dataclass
class Row:
    question_number: int
    question: str
    expected: str
    actual: str
    status: str
    kind: str
    correct: bool
    error_category: str = ""
    explanation: str = ""


@dataclass
class Report:
    total: int = 0
    correct: int = 0
    incorrect: int = 0
    correct_abstentions: int = 0
    unnecessary_abstentions: int = 0
    false_verified: int = 0
    verified_total: int = 0
    verified_correct: int = 0
    rows: list[Row] = field(default_factory=list)

    def add(self, row: Row) -> None:
        self.rows.append(row)
        self.total += 1
        verified = row.status in ("VERIFIED", "VERIFIED_DERIVED")
        if verified:
            self.verified_total += 1
        if row.correct:
            self.correct += 1
            if verified:
                self.verified_correct += 1
        else:
            if verified:
                self.false_verified += 1
                self.incorrect += 1
            elif row.status in ("NOT_AVAILABLE", "INCOMPLETE"):
                # abstention: correct only if the fact genuinely is not present
                self.unnecessary_abstentions += 1
            else:
                self.incorrect += 1

    @property
    def accuracy(self) -> float:
        return (self.correct / self.total * 100) if self.total else 0.0

    @property
    def verified_precision(self) -> float:
        return (
            self.verified_correct / self.verified_total * 100 if self.verified_total else 0.0
        )


def run(file_path: pathlib.Path, use_ai: bool) -> Report:
    import asyncio

    from trident.ingestion import ingest
    from trident.pipeline import analyze

    # Solver only ever receives the question text.
    question_text = "\n".join(f"{n}. {q}" for n, q, _e, _k in BENCHMARK)
    outcome = asyncio.run(
        analyze(ingest(file_path.name, file_path.read_bytes()), question_text, use_ai=use_ai)
    )
    by_number = {r.question_number: r for r in outcome.response.results}

    report = Report()
    for number, question, expected, kind in BENCHMARK:
        result = by_number.get(number)
        actual = (result.answer if result else "") or ""
        status = result.status.value if result else "MISSING"
        ok = grade(kind, expected, actual)
        category = ""
        if not ok:
            if status in ("VERIFIED", "VERIFIED_DERIVED"):
                category = "FALSE_VERIFIED"
            elif status in ("NOT_AVAILABLE", "INCOMPLETE"):
                category = "ABSTAINED"
            else:
                category = status
        report.add(
            Row(
                question_number=number,
                question=question,
                expected=expected,
                actual=actual,
                status=status,
                kind=kind,
                correct=ok,
                error_category=category,
                explanation=(result.explanation or "")[:200] if result else "",
            )
        )
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the OK Cup 65-question benchmark")
    ap.add_argument(
        "--file",
        default=str(pathlib.Path.home() / "Downloads" / "R1_OKCUP_24_25_CiscoPT(1).pka"),
    )
    ap.add_argument("--json", default=None)
    ap.add_argument("--ai", action="store_true", help="enable AI planning")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    path = pathlib.Path(args.file).expanduser()
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 2

    report = run(path, args.ai)
    payload = {
        "file": path.name,
        "total": report.total,
        "correct": report.correct,
        "incorrect": report.incorrect,
        "unnecessary_abstentions": report.unnecessary_abstentions,
        "false_verified": report.false_verified,
        "accuracy_pct": round(report.accuracy, 1),
        "verified_total": report.verified_total,
        "verified_precision_pct": round(report.verified_precision, 1),
        "rows": [asdict(r) for r in report.rows],
    }
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")

    print(
        f"score {report.correct}/{report.total} ({report.accuracy:.1f}%)  "
        f"verified {report.verified_total}  precision {report.verified_precision:.1f}%  "
        f"false-verified {report.false_verified}"
    )
    if args.verbose:
        for row in report.rows:
            flag = "ok " if row.correct else "FAIL"
            print(
                f"{flag} Q{row.question_number:<3} {row.status:<17} "
                f"{(row.actual or '')[:58]:58s} | expected {(row.expected or '')[:40]}"
            )
    else:
        for row in report.rows:
            if not row.correct:
                print(
                    f"FAIL Q{row.question_number}: {row.status} got {(row.actual or '')[:60]!r} "
                    f"want {(row.expected or '')[:60]!r} [{row.error_category}]"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
