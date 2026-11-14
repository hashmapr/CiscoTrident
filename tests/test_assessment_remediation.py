"""Remediation must be safe, reversible, and honest about regressions."""

from __future__ import annotations

import hashlib
import json

import pytest

from trident.assessment.remediation import (
    apply_to_copy,
    plan,
    read_only_plan,
    rollback,
    verify_remediation,
)

SOURCE = {
    "R1": [
        "hostname R1",
        "interface GigabitEthernet0/0",
        "ip address 10.0.1.1 255.255.255.0",
        "no shutdown",
        "interface GigabitEthernet0/1",
        "ip address 10.0.12.1 255.255.255.0",
        "shutdown",
        "end",
    ]
}

SHUT_FINDINGS = [
    {
        "device": "R1",
        "interface": "GigabitEthernet0/1",
        "category": "ADMIN_SHUTDOWN",
        "detail": "R1 GigabitEthernet0/1 is administratively down",
        "affected": ["PC-A -> PC-B"],
    },
    {
        "device": "R1",
        "interface": "GigabitEthernet0/1",
        "kind": "ADMIN_SHUTDOWN",
        "detail": "same root cause, another victim",
        "affected": ["PC-A -> PC-C"],
    },
]


def _sha(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_source(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(SOURCE), encoding="utf-8")
    return source


def test_plan_emits_one_change_per_root_cause_not_one_per_victim() -> None:
    changes = plan(SHUT_FINDINGS)

    assert len(changes) == 1
    assert changes[0].device == "R1"
    assert changes[0].interface == "GigabitEthernet0/1"
    assert changes[0].kind == "no_shutdown"
    assert changes[0].proposed == "no shutdown"


def test_apply_to_copy_never_touches_the_source_file(tmp_path) -> None:
    source = _write_source(tmp_path)
    before = _sha(source)
    destination = tmp_path / "remediated.json"

    path, log = apply_to_copy(source, plan(SHUT_FINDINGS), destination)

    assert path == destination
    assert _sha(source) == before
    assert log.source_unchanged is True
    assert log.source_sha256_before == log.source_sha256_after
    assert "no shutdown" in destination.read_text(encoding="utf-8")


def test_change_log_records_old_values_and_rollback_restores_them(tmp_path) -> None:
    source = _write_source(tmp_path)
    destination = tmp_path / "remediated.json"
    _, log = apply_to_copy(source, plan(SHUT_FINDINGS), destination)

    assert log.entries
    assert all(entry.old is not None for entry in log.entries)
    assert log.entries[0].old == "shutdown"
    assert log.as_dict()["entries"][0]["old"] == "shutdown"

    result = rollback(log)

    assert result["restored"] == str(destination)
    assert destination.read_bytes() == source.read_bytes()
    assert _sha(source) == log.source_sha256_before


def test_a_change_that_fixes_the_fault_counts_as_fixed() -> None:
    original = [{"device": "R1", "interface": "Gi0/1", "kind": "ADMIN_SHUTDOWN"}]

    result = verify_remediation(original, [])

    assert result["fixed"] == 1
    assert result["still_broken"] == 0
    assert result["introduced_regressions"] == 0


def test_a_change_that_introduces_a_new_finding_is_a_regression_not_fixed() -> None:
    original = [{"device": "R1", "interface": "Gi0/1", "kind": "MISSING_FORWARD_ROUTE"}]
    post = [{"device": "R1", "interface": "Gi0/2", "kind": "ACL_DENY"}]

    result = verify_remediation(original, post)

    assert result["introduced_regressions"] == 1
    assert result["fixed"] == 0
    assert result["still_broken"] == 0
    assert result["regressions"][0]["attributed_to"]["kind"] == "MISSING_FORWARD_ROUTE"


def test_read_only_plan_has_no_side_effects(tmp_path) -> None:
    source = _write_source(tmp_path)
    before = _sha(source)
    existing = set(tmp_path.iterdir())

    text = read_only_plan(SHUT_FINDINGS)

    assert isinstance(text, str)
    assert "READ-ONLY" in text
    assert "R1" in text
    assert _sha(source) == before
    assert set(tmp_path.iterdir()) == existing


def test_apply_to_copy_refuses_to_write_over_the_source(tmp_path) -> None:
    source = _write_source(tmp_path)
    before = _sha(source)

    with pytest.raises(ValueError):
        apply_to_copy(source, plan(SHUT_FINDINGS), source)

    assert _sha(source) == before


def test_apply_to_copy_works_without_a_source_bundle(tmp_path) -> None:
    """The orchestrator passes ``None`` when only findings are available."""
    destination = tmp_path / "fresh.json"

    path, log = apply_to_copy(None, plan(SHUT_FINDINGS), destination)

    assert path.exists()
    assert log.source_unchanged is True
    assert log.entries[0].old is not None
