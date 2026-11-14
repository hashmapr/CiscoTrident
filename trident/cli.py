"""Command line entry point for ``trident``.

The TUI/server is still the default when no subcommand is given, so existing
usage (``python -m trident``) is unchanged. Subcommands are added as narrow,
scriptable verbs.

``trident practice`` is the CyberPatriot practice runner. It is deliberately a
separate verb from the server: a practice attempt is a short, bounded, offline
operation, and it must not need a browser or a running service.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _practice_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "practice",
        help="run a scored CyberPatriot-style practice attempt",
        description=(
            "Analyse a practice lab, list its objectives, take progressive "
            "hints, and score a submission. The instructor answer key is never "
            "shown unless --write-key is given."
        ),
    )
    p.add_argument(
        "lab",
        nargs="?",
        help="path to the practice .pkt/.pka file (or a built-in lab name)",
    )
    p.add_argument(
        "--list-labs",
        action="store_true",
        help="list built-in practice labs and exit",
    )
    p.add_argument(
        "--difficulty",
        choices=("beginner", "intermediate", "advanced"),
        default="intermediate",
        help="scoring precision (default: intermediate)",
    )
    p.add_argument(
        "--objectives",
        action="store_true",
        help="print the objectives and exit",
    )
    p.add_argument(
        "--hint",
        metavar="OBJECTIVE_ID",
        help="show the next progressive hint for one objective",
    )
    p.add_argument(
        "--hints-for",
        metavar="OBJECTIVE_ID",
        action="append",
        default=[],
        help="take a hint before scoring (repeatable)",
    )
    p.add_argument(
        "--submit",
        metavar="FILE",
        help="score a submission file: one 'device [interface] [category]' per line",
    )
    p.add_argument(
        "--out",
        metavar="DIR",
        help="write the student report (Markdown + JSON) into DIR",
    )
    p.add_argument(
        "--write-key",
        metavar="FILE",
        help="write the instructor answer key to FILE (instructor use only)",
    )
    p.add_argument(
        "--generate",
        metavar="DIR",
        help="generate the built-in lab as a .pkt into DIR, then exit",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of prose",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trident",
        description="Cisco Packet Tracer analysis and CyberPatriot practice.",
    )
    sub = parser.add_subparsers(dest="command")
    _practice_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "practice":
        return _run_practice(args)
    if args.command is None:
        # Preserve the historical behaviour: no subcommand starts the server.
        from .server import run

        run()
        return 0
    parser.print_help()
    return 2


def _run_practice(args: argparse.Namespace) -> int:
    import json

    from .labgen import GenerationUnavailable, available, generate
    from .practice import (
        PracticeError,
        PracticeSession,
        parse_findings,
        render_markdown,
        score_submission,
        write_answer_key,
        write_reports,
    )

    builtin = _builtin_labs()

    if args.list_labs:
        for name, loader in builtin.items():
            spec = loader()
            print(f"{name:28s} {len(spec.faults):2d} faults  {spec.difficulty}")
        return 0

    if not args.lab:
        print("error: a lab path or a built-in lab name is required", file=sys.stderr)
        print(f"built-in labs: {', '.join(builtin)}", file=sys.stderr)
        return 2

    if args.lab in builtin:
        session = PracticeSession(builtin[args.lab](), difficulty=args.difficulty)
    else:
        path = Path(args.lab).expanduser()
        if not path.is_file():
            print(f"error: no such lab file: {path}", file=sys.stderr)
            return 2
        # A lab file has no manifest with it; the built-in spec is the only
        # source of objectives. Say so rather than inventing objectives.
        print(
            "error: scoring an arbitrary .pkt needs an instructor manifest; "
            "only the built-in labs carry one. Use --list-labs.",
            file=sys.stderr,
        )
        return 2

    if args.generate:
        ok, why = available()
        if not ok:
            print(f"error: cannot generate a .pkt here: {why}", file=sys.stderr)
            print("       a manual construction procedure is in "
                  "docs/cyberpatriot/OPERATION_BROKEN_CAMPUS.md", file=sys.stderr)
            return 3
        try:
            result = generate(session.spec, Path(args.generate) / f"{session.spec.name}.pkt")
        except GenerationUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        print(f"wrote {result.path} ({result.device_count} devices, "
              f"{result.link_count} links, faults applied)")
        print(f"sha256 {result.sha256}")
        if not result.verified:
            print(f"note: {result.verification_note}")
        return 0

    if args.write_key:
        out = write_answer_key(session, Path(args.write_key))
        print(f"instructor key written to {out}")
        return 0

    if args.objectives:
        if args.json:
            print(json.dumps([
                {
                    "objective_id": o.objective_id,
                    "title": o.title,
                    "category": o.category.value,
                    "points": o.points,
                }
                for o in session.objectives()
            ], indent=2))
        else:
            print(f"{session.spec.title}  ({session.spec.difficulty})")
            print(f"{session.spec.brief.splitlines()[0] if session.spec.brief else ''}")
            print()
            for objective in session.objectives():
                print(f"  {objective.objective_id:34s} {objective.points:3d} pts  {objective.title}")
        return 0

    if args.hint:
        try:
            hint = session.hint(args.hint)
        except PracticeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"hint {hint.level} for {args.hint}: {hint.text}")
        if hint.penalty:
            print(f"(-{hint.penalty} points)")
        return 0

    for objective_id in args.hints_for:
        try:
            hint = session.hint(objective_id)
        except PracticeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"hint {hint.level} for {objective_id}: {hint.text}")

    if args.submit:
        submission = Path(args.submit).expanduser()
        if not submission.is_file():
            print(f"error: no such submission file: {submission}", file=sys.stderr)
            return 2
        try:
            findings = parse_findings(submission.read_text())
        except PracticeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        session.submitted = True
        score = score_submission(session, findings)
        if args.json:
            print(json.dumps(score.as_dict(), indent=2))
        else:
            print(render_markdown(score))
        if args.out:
            written = write_reports(session, score, Path(args.out))
            print(f"report written to {written['markdown']}", file=sys.stderr)
            print(f"score written to  {written['json']}", file=sys.stderr)
        return 0

    # No action requested: show objectives, which is the useful default.
    for objective in session.objectives():
        print(f"  {objective.objective_id:34s} {objective.points:3d} pts  {objective.title}")
    print()
    print("next: --hint <objective_id>  |  --submit <file>  |  --write-key <file>")
    return 0


def _builtin_labs() -> dict:
    """Built-in practice labs. Imported lazily so ``trident`` stays cheap."""
    from .labgen.broken_campus import TOPOLOGY as broken_campus

    return {"operation-broken-campus": lambda: broken_campus}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
