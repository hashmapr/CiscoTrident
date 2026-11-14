"""Static results survive a failed operational stage, and counts stay honest.

The simulator is optional. If it is unavailable, or if the stage that talks to
it throws, the report must still deliver everything the static engines already
computed. A failed experiment is a distinct event, never a reason to discard the
rest of the report. Experiment counts distinguish what actually ran from what
was merely planned.
"""

from __future__ import annotations

import trident.deepcore.analyze as analyze_module
from trident.deepcore.analyze import (
    analyze_network,
    merge_operational_checks,
    stream_sections,
)
from trident.deepcore.deep import OperationalCheck, RuntimeStatus
from trident.faultlab import baseline_lab, scenarios


class _Deep:
    def __init__(self, checks, available=True, reason="ok"):
        self.available = available
        self.reason = reason
        self.simulator_version = "9.0.1"
        self.source_intact = True
        self.checks = list(checks)


def _check(status: RuntimeStatus, source="R1", destination="R2", detail="") -> OperationalCheck:
    return OperationalCheck(
        name="connectivity",
        source=source,
        destination=destination,
        status=status,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Static results survive a simulator failure
# ---------------------------------------------------------------------------


def test_a_failed_operational_stage_keeps_the_static_report():
    model = next(s for s in scenarios() if s.name == "wrong-vlan").model
    report = analyze_network(model)
    before_sections = [section.name for section in report.sections]
    before_findings = list(report.network_findings)

    merge_operational_checks(report, None, error="RuntimeError: simulator died")

    assert [section.name for section in report.sections] == before_sections
    assert report.network_findings == before_findings
    assert report.overview["runtime_available"] is False
    assert "simulator died" in report.overview["runtime_stage_error"]
    assert any("did not run" in warning for warning in report.warnings)
    assert any("NOT_RUN" in item for item in report.unsupported_checks)


def test_a_failed_stage_is_not_counted_as_experiments_run():
    report = analyze_network(baseline_lab())
    merge_operational_checks(report, None, error="boom")

    assert report.overview["runtime_experiments_planned"] == 0
    assert report.overview["runtime_experiments_run"] == 0
    assert report.overview["runtime_experiments_observed"] == 0


def test_one_malformed_check_does_not_lose_the_report():
    report = analyze_network(baseline_lab())
    good = _check(RuntimeStatus.OBSERVED, detail="DELIVERED: 60 bytes")

    class _Broken:
        status = None  # accessing .value raises AttributeError
        source = "R1"
        destination = "R2"
        detail = "x"
        observed = False

    merge_operational_checks(report, _Deep([good, _Broken()]))

    assert report.sections, "the static report must survive a malformed check"
    assert any("could not be merged" in warning for warning in report.warnings)


# ---------------------------------------------------------------------------
# Counts reflect experiments actually run, not planned
# ---------------------------------------------------------------------------


def test_counts_separate_planned_from_actually_run():
    report = analyze_network(baseline_lab())
    deep = _Deep(
        [
            _check(RuntimeStatus.OBSERVED, detail="DELIVERED: 60 bytes"),
            _check(RuntimeStatus.NOT_ATTEMPTED, detail="experiment budget spent"),
            _check(RuntimeStatus.UNAVAILABLE, detail="no simulator"),
        ],
        available=False,
        reason="no simulator",
    )

    merge_operational_checks(report, deep)

    assert report.overview["runtime_experiments_planned"] == 3
    assert report.overview["runtime_experiments_run"] == 1
    assert report.overview["runtime_experiments_observed"] == 1
    assert report.overview["runtime_experiments_not_run"] == 2


def test_the_unsupported_check_count_matches_the_list_after_merge():
    """The overview count is built before merge; runtime gaps must update it."""
    report = analyze_network(baseline_lab())
    deep = _Deep(
        [
            _check(RuntimeStatus.UNAVAILABLE, detail="no simulator"),
            _check(RuntimeStatus.FAILED, detail="TimeoutError: no reply"),
        ],
        available=False,
        reason="no simulator",
    )

    merge_operational_checks(report, deep)

    assert report.overview["unsupported_checks"] == len(report.unsupported_checks)


# ---------------------------------------------------------------------------
# stream_sections: a broken section is an event, not a traceback
# ---------------------------------------------------------------------------


def test_a_broken_device_section_is_delivered_as_an_error_event(monkeypatch):
    model = baseline_lab()
    original = analyze_module.Analyzer.section

    def flaky(self, device):
        if device.name == "SW2":
            raise RuntimeError("deliberate section failure")
        return original(self, device)

    monkeypatch.setattr(analyze_module.Analyzer, "section", flaky)

    events = list(stream_sections(model))
    kinds = [kind for kind, _ in events]

    assert kinds[-2:] == ["findings", "coverage"]
    assert kinds.count("section") == len(model.devices) - 1
    errors = [payload for kind, payload in events if kind == "ERROR"]
    assert errors and errors[0]["device"] == "SW2"
    coverage = next(payload for kind, payload in events if kind == "coverage")
    assert any("deliberate section failure" in warning for warning in coverage["warnings"])


def test_a_stream_that_fails_before_any_section_reports_in_band(monkeypatch):
    model = baseline_lab()

    def explode(self, findings):
        raise RuntimeError("deliberate overview failure")

    monkeypatch.setattr(analyze_module.Analyzer, "_overview", explode)

    events = list(stream_sections(model))

    assert len(events) == 1
    kind, payload = events[0]
    assert kind == "ERROR"
    assert "deliberate overview failure" in payload["detail"]


def test_a_runtime_failure_is_a_distinct_event_without_losing_sections():
    """The simulator throwing must not cost the client the static sections."""
    model = baseline_lab()

    events = list(stream_sections(model, runtime_error="TimeoutError: no reply"))
    kinds = [kind for kind, _ in events]

    assert kinds[0] == "overview"
    assert kinds[1] == "ERROR"
    errors = [payload for kind, payload in events if kind == "ERROR"]
    assert errors[0]["scope"] == "runtime"
    assert "operational stage failed" in errors[0]["detail"]
    assert kinds.count("section") == len(model.devices)
    assert kinds[-2:] == ["findings", "coverage"]
    coverage = next(payload for kind, payload in events if kind == "coverage")
    assert any("operational stage failed" in warning for warning in coverage["warnings"])
