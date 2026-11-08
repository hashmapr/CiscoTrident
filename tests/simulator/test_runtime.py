"""Runtime tests: isolation, lifecycle, budgets, capability honesty.

These tests run against the scripted backend so they are deterministic, but the
guarantees they check are the ones that matter for live operation: the source
file is never touched, every path is confined, budgets are enforced before work
happens, and a backend that cannot do something says so.
"""

from __future__ import annotations

import os

import pytest

from trident.simulator import (
    BackendKind,
    BackendUnavailable,
    Budget,
    BudgetExceeded,
    Capability,
    CapabilityUnsupported,
    DeviceAmbiguous,
    DeviceNotFound,
    IsolationError,
    ObservationKind,
    SessionClosed,
    SessionState,
    SimulatorRuntime,
    Workspace,
    sha256_file,
)
from trident.simulator.isolation import _safe_name

# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_session_copies_the_lab_and_never_touches_the_source(simulator_lab, simulator_scenario, scripted_runtime):
    before = sha256_file(simulator_lab)
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        assert session.working_copy != simulator_lab
        assert session.working_copy.exists()
        assert sha256_file(session.working_copy) == before
        assert sha256_file(simulator_lab) == before
    finally:
        status = session.close()
    assert "source=INTACT" in status
    assert sha256_file(simulator_lab) == before


def test_close_removes_the_working_directory(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    directory = session.directory
    status = session.close()
    assert "CLEANED" in status
    assert not directory.exists()


def test_source_change_during_session_is_reported(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    simulator_lab.write_bytes(b"tampered")
    status = session.close()
    assert "source=MODIFIED" in status
    assert any("SOURCE CHANGED" in note for note in session.notes)


def test_path_traversal_is_refused(tmp_path):
    workspace = Workspace(tmp_path / "ws")
    outside = tmp_path / "outside.pkt"
    outside.write_bytes(b"x")
    directory = workspace.new_session_dir()
    with pytest.raises(IsolationError):
        workspace.stage_copy(outside, directory / ".." / ".." / "escape")


def test_upload_name_cannot_traverse(simulator_lab, tmp_path):
    workspace = Workspace(tmp_path / "ws")
    directory = workspace.new_session_dir()
    target, _ = workspace.stage_copy(simulator_lab, directory, filename="../../evil.pkt")
    assert target.parent == directory.resolve()
    assert ".." not in target.name


def test_cleanup_outside_workspace_is_refused(tmp_path):
    workspace = Workspace(tmp_path / "ws")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    assert workspace.cleanup(outside) == "REFUSED_OUTSIDE_WORKSPACE"
    assert outside.exists()


def test_oversized_lab_is_rejected(tmp_path, monkeypatch):
    from trident.simulator import isolation

    monkeypatch.setattr(isolation, "MAX_LAB_BYTES", 4)
    simulator_lab = tmp_path / "big.pkt"
    simulator_lab.write_bytes(b"12345678")
    workspace = Workspace(tmp_path / "ws")
    with pytest.raises(IsolationError, match="above the"):
        workspace.stage_copy(simulator_lab, workspace.new_session_dir())


def test_safe_name_is_bounded_and_typed():
    assert _safe_name("../../x") .endswith(".pkt")
    assert len(_safe_name("a" * 400)) <= 124
    assert _safe_name("simulator_lab.PKT").endswith(".PKT")


# ---------------------------------------------------------------------------
# Backend honesty
# ---------------------------------------------------------------------------


def test_scripted_results_are_never_live(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        result = session.run_cli("R1", "show ip route")
        assert result.ok
        assert result.observed is False
        assert result.is_live is False
        assert result.provenance.backend is BackendKind.SCRIPTED
        assert any("not a simulator observation" in c for c in result.provenance.caveats)
        assert session.notes and "SCRIPTED" in session.notes[0]
    finally:
        session.close()


def test_raw_output_is_preserved_alongside_parse(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        result = session.run_cli("R1", "show ip route")
        assert "Gateway of last resort" in result.raw
        assert result.provenance.working_copy_sha256
    finally:
        session.close()


def test_reachability_success_and_failure_are_distinguished(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        ok = session.ping("PC1", "10.10.20.11")
        bad = session.ping("PC1", "10.10.20.10")
        assert ok.kind is ObservationKind.REACHABILITY_SUCCEEDED
        assert bad.kind is ObservationKind.REACHABILITY_FAILED
        assert ok.parsed["success_percent"] == 100
        assert bad.parsed["success_percent"] == 0
    finally:
        session.close()


def test_mutation_commands_are_refused(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        for command in (
            "configure terminal",
            "no ip route 0.0.0.0 0.0.0.0 203.0.113.1",
            "write memory",
            "erase startup-config",
            "reload",
            "shutdown",
            "debug ip packet",
        ):
            with pytest.raises(CapabilityUnsupported):
                session.run_cli("R1", command)
    finally:
        session.close()


def test_unsupported_command_on_backend_raises_not_fakes(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        result = session.run_cli("R1", "show version")
        assert result.ok is False
        assert result.raw == ""
        assert "no canned output" in (result.error or "")
    finally:
        session.close()


def test_unknown_device_fails_before_any_operation(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        before = session.info().operations
        with pytest.raises(DeviceNotFound):
            session.ping("R99", "10.10.20.10")
        assert session.info().operations == before
    finally:
        session.close()


def test_ambiguous_device_is_refused(simulator_lab, tmp_path, scripted_runtime):
    import json

    scenario = json.loads((tmp_path / "scenario.json").read_text()) if (tmp_path / "scenario.json").exists() else {
        "devices": [{"name": "R1-Primary", "commands": {}}, {"name": "R1-Backup", "commands": {}}]
    }
    path = tmp_path / "amb.json"
    path.write_text(json.dumps(scenario if len(scenario["devices"]) == 2 else {
        "devices": [{"name": "R1-Primary", "commands": {}}, {"name": "R1-Backup", "commands": {}}]
    }))
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=path)
    try:
        with pytest.raises(DeviceAmbiguous):
            session.resolve_device("R1")
        handle = session.resolve_device("R1-Primary")
        assert handle.matched_on == "exact"
    finally:
        session.close()


def test_capabilities_are_discovered_not_assumed(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        capabilities = session.capabilities()
        assert Capability.RUN_CLI in capabilities
        assert Capability.MUTATE_CONFIG not in capabilities
        assert session.supports(Capability.PING)
        assert not session.supports(Capability.MUTATE_CONFIG)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Budgets and lifecycle
# ---------------------------------------------------------------------------


def test_operation_budget_is_enforced(simulator_lab, simulator_scenario, tmp_path):
    runtime = SimulatorRuntime(
        workspace_root=tmp_path / "ws",
        prefer_live=False,
        budget=Budget(max_operations=2),
    )
    session = runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        session.run_cli("R1", "show ip route")
        session.run_cli("R1", "show ip interface brief")
        with pytest.raises(BudgetExceeded):
            session.run_cli("R1", "show ip route")
    finally:
        session.close()


def test_session_limit_is_enforced(simulator_lab, simulator_scenario, scripted_runtime):
    first = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        with pytest.raises(BudgetExceeded):
            scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    finally:
        first.close()
    second = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    second.close()


def test_lifetime_budget_is_enforced(simulator_lab, simulator_scenario, tmp_path, monkeypatch):
    import trident.simulator.sessions as sessions_module

    runtime = SimulatorRuntime(
        workspace_root=tmp_path / "ws",
        prefer_live=False,
        budget=Budget(session_lifetime_s=1.0),
    )
    session = runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    monkeypatch.setattr(
        sessions_module.time, "monotonic", lambda: session._started_monotonic + 5
    )
    with pytest.raises(BudgetExceeded):
        session.run_cli("R1", "show ip route")
    assert session.state is SessionState.TIMEOUT
    session.close()


def test_closed_session_refuses_further_work(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    session.close()
    with pytest.raises(SessionClosed):
        session.run_cli("R1", "show ip route")


def test_close_is_idempotent(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    first = session.close()
    second = session.close()
    assert first == second
    assert session.state is SessionState.CLOSED


def test_runtime_close_all_reports_each_session(simulator_lab, simulator_scenario, tmp_path):
    runtime = SimulatorRuntime(
        workspace_root=tmp_path / "ws", prefer_live=False, max_sessions=2
    )
    first = runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    second = runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    statuses = runtime.close_all()
    assert set(statuses) == {first.session_id, second.session_id}
    assert runtime.active_sessions == ()


def test_non_disposable_is_refused(simulator_lab, simulator_scenario, scripted_runtime):
    with pytest.raises(IsolationError, match="always disposable"):
        scripted_runtime.create_session(simulator_lab, disposable=False, scripted_scenario=simulator_scenario)


def test_failed_backend_selection_cleans_up(simulator_lab, scripted_runtime):
    """A backend that cannot start must not leave a working copy behind."""
    workspace = scripted_runtime.workspace.root
    before = set(workspace.iterdir())
    with pytest.raises(BackendUnavailable):
        scripted_runtime.create_session(simulator_lab, scripted_scenario=None)
    after = set(workspace.iterdir())
    assert before == after


def test_missing_lab_is_rejected(scripted_runtime):
    with pytest.raises(IsolationError):
        scripted_runtime.create_session("/nonexistent/simulator_lab.pkt", scripted_scenario=None)


def test_session_info_is_complete(simulator_lab, simulator_scenario, scripted_runtime):
    session = scripted_runtime.create_session(simulator_lab, scripted_scenario=simulator_scenario)
    try:
        info = session.info().as_dict()
        for key in (
            "session_id",
            "state",
            "backend",
            "simulator_version",
            "source_sha256",
            "working_copy_sha256",
            "working_copy_path",
            "source_path",
            "started_at",
            "operations",
            "cleanup_status",
        ):
            assert key in info
        assert info["backend"] == "SCRIPTED"
    finally:
        session.close()


def test_availability_reason_names_the_real_cause():
    runtime = SimulatorRuntime(workspace_root=os.environ.get("TMPDIR", "/tmp") + "/trident-avail")
    reason = runtime.availability_reason()
    assert isinstance(reason, str) and reason
    # Never claims live availability without a registered app.
    if not runtime.is_available():
        assert "registered ExApp" in reason or "not installed" in reason
