"""The ``trident practice`` command must be usable and must not leak.

CLI behaviour is easy to break silently because nothing imports it. These tests
drive the real argument parser and capture stdout/stderr.
"""

from __future__ import annotations

import json

import pytest

from trident.cli import build_parser, main


@pytest.fixture(autouse=True)
def _isolated_hint_state(tmp_path, monkeypatch):
    monkeypatch.setattr("trident.practice.HINT_STATE_FILE", tmp_path / "hints.json")


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_list_labs_names_the_builtin(capsys) -> None:
    code, out, _err = _run(capsys, "practice", "--list-labs")
    assert code == 0
    assert "operation-broken-campus" in out


def test_objectives_are_listed_with_points(capsys) -> None:
    code, out, _err = _run(capsys, "practice", "operation-broken-campus", "--objectives")
    assert code == 0
    assert "pts" in out
    assert out.count("obj-") == 15


def test_objectives_do_not_reveal_expected_configuration(capsys) -> None:
    """The student-facing listing is the place a leak is most damaging."""
    code, out, _err = _run(capsys, "practice", "operation-broken-campus", "--objectives")
    assert code == 0
    for line in (
        "ip address 192.168.30.1",
        "switchport trunk native vlan 99",
        "ip route 0.0.0.0 0.0.0.0 10.0.0.2",
    ):
        assert line not in out


def test_objectives_json_is_machine_readable(capsys) -> None:
    code, out, _err = _run(
        capsys, "practice", "operation-broken-campus", "--objectives", "--json"
    )
    assert code == 0
    data = json.loads(out)
    assert len(data) == 15
    assert all({"objective_id", "title", "category", "points"} <= set(row) for row in data)


def test_hint_is_progressive_across_invocations(capsys) -> None:
    objective = "obj-trunk-native-mismatch"
    _run(capsys, "practice", "operation-broken-campus", "--hint", objective)
    code, out1, _ = _run(capsys, "practice", "operation-broken-campus", "--hint", objective)
    assert code == 0
    assert "hint 2" in out1
    code, out2, err = _run(capsys, "practice", "operation-broken-campus", "--hint", objective)
    assert code == 2
    assert "no further hints" in err


def test_submit_scores_and_writes_reports(tmp_path, capsys) -> None:
    submission = tmp_path / "sub.txt"
    submission.write_text("PC-ADMIN-1 ADDRESSING\nR1 ROUTING\n")
    out_dir = tmp_path / "reports"
    code, out, err = _run(
        capsys,
        "practice",
        "operation-broken-campus",
        "--submit",
        str(submission),
        "--out",
        str(out_dir),
    )
    assert code == 0
    assert "/ 100" in out or "/100" in out
    assert (out_dir / "practice_report.md").is_file()
    assert (out_dir / "practice_score.json").is_file()
    assert "report written" in err


def test_submit_json_hides_missed_answers(tmp_path, capsys) -> None:
    submission = tmp_path / "sub.txt"
    submission.write_text("SW-ACCESS\n")
    code, out, _err = _run(
        capsys, "practice", "operation-broken-campus", "--submit", str(submission), "--json"
    )
    assert code == 0
    data = json.loads(out)
    missed = set(data["missed"])
    for entry in data["lines"]:
        if entry["fault_id"] in missed:
            assert "expected" not in entry


def test_a_bad_submission_line_is_refused_with_a_line_number(tmp_path, capsys) -> None:
    submission = tmp_path / "bad.txt"
    submission.write_text("R1 Fa0/1 VLAN EXTRA\n")
    code, _out, err = _run(
        capsys, "practice", "operation-broken-campus", "--submit", str(submission)
    )
    assert code == 2
    assert "line 1" in err


def test_a_missing_submission_file_is_refused(tmp_path, capsys) -> None:
    code, _out, err = _run(
        capsys, "practice", "operation-broken-campus", "--submit", str(tmp_path / "nope.txt")
    )
    assert code == 2
    assert "no such submission file" in err


def test_an_unknown_lab_file_is_refused_with_a_reason(tmp_path, capsys) -> None:
    """An arbitrary .pkt has no manifest, so it cannot be scored."""
    lab = tmp_path / "random.pkt"
    lab.write_bytes(b"not really a lab")
    code, _out, err = _run(capsys, "practice", str(lab))
    assert code == 2
    assert "manifest" in err


def test_write_key_needs_an_explicit_flag(tmp_path, capsys) -> None:
    key = tmp_path / "key.json"
    code, _out, _err = _run(
        capsys, "practice", "operation-broken-campus", "--write-key", str(key)
    )
    assert code == 0
    assert key.is_file()
    data = json.loads(key.read_text())
    assert data["point_total"] == 100


def test_the_key_is_not_written_by_a_plain_submit(tmp_path, capsys) -> None:
    submission = tmp_path / "sub.txt"
    submission.write_text("R1\n")
    out_dir = tmp_path / "reports"
    _run(capsys, "practice", "operation-broken-campus", "--submit", str(submission),
         "--out", str(out_dir))
    written = {p.name for p in out_dir.iterdir()}
    assert written == {"practice_report.md", "practice_score.json"}


def test_generate_writes_a_pkt(tmp_path, capsys) -> None:
    from trident.labgen import available

    ok, why = available()
    if not ok:
        pytest.skip(why)
    code, out, _err = _run(
        capsys, "practice", "operation-broken-campus", "--generate", str(tmp_path)
    )
    assert code == 0
    assert (tmp_path / "operation-broken-campus.pkt").is_file()
    assert "sha256" in out
    # It must not claim simulator compatibility it has not established.
    assert "note:" in out or "verified" not in out.lower()


def test_parser_accepts_all_documented_flags() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "practice", "operation-broken-campus",
            "--difficulty", "advanced",
            "--objectives",
            "--json",
        ]
    )
    assert args.command == "practice"
    assert args.difficulty == "advanced"
    assert args.json is True


def test_no_subcommand_is_still_valid_for_the_server() -> None:
    """``python -m trident`` must keep starting the server."""
    args = build_parser().parse_args([])
    assert args.command is None
