"""Parser adapter tests: real execution, failure isolation, and honesty.

Real-file tests skip cleanly when engines or fixtures are unavailable; they are
never faked.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from conftest import REAL_PKA, REAL_PKT, engine_available, requires_real_file

from trident.config import Settings
from trident.models import ParserState
from trident.parsers.base import AdapterResult, ParserAdapter
from trident.parsers.pka_xml import EngineAAdapter, _select_snapshot
from trident.parsers.pkt_core import EngineBAdapter
from trident.parsers.pt_convert import EngineCAdapter


class BoomAdapter(ParserAdapter):
    """Adapter that always raises — proves failures are isolated, not swallowed."""

    engine_id = "boom"
    display_name = "Boom"

    def probe(self):
        return True, "ready"

    def _extract(self, file_path, workdir):
        raise RuntimeError("simulated parser crash")


class HungAdapter(ParserAdapter):
    engine_id = "hung"
    display_name = "Hung"

    def probe(self):
        return True, "ready"

    def _extract(self, file_path, workdir):
        raise TimeoutError("simulated timeout")


class UnavailableAdapter(ParserAdapter):
    engine_id = "gone"
    display_name = "Gone"
    capabilities = ("nothing",)
    limitations = ("not installed",)

    def probe(self):
        return False, "not installed"

    def _extract(self, file_path, workdir):  # pragma: no cover - never called
        raise AssertionError("must not run when unavailable")


# 4. Parser timeout handling
def test_timeout_is_reported_not_raised():
    adapter = HungAdapter(Settings())
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "input.pkt"
        path.write_bytes(b"x" * 100)
        result = adapter.run(path, Path(td))
    assert isinstance(result, AdapterResult)
    assert result.report.state is ParserState.TIMEOUT
    assert not result.ok


# 5. Parser crash handling
def test_crash_is_reported_not_raised():
    adapter = BoomAdapter(Settings())
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "input.pkt"
        path.write_bytes(b"x" * 100)
        result = adapter.run(path, Path(td))
    assert result.report.state is ParserState.ERROR
    assert "simulated parser crash" in result.report.message
    assert not result.ok


# 6. Missing parser output
def test_unavailable_adapter_reports_unavailable():
    adapter = UnavailableAdapter(Settings())
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "input.pkt"
        path.write_bytes(b"x" * 100)
        result = adapter.run(path, Path(td))
    assert result.report.state is ParserState.UNAVAILABLE
    assert result.report.message == "not installed"
    assert result.observations == []
    assert result.devices == []


def test_engine_a_missing_library_reports_unavailable(monkeypatch):
    adapter = EngineAAdapter(Settings())
    monkeypatch.setattr(adapter, "_library_path", lambda: None)
    ok, message = adapter.probe()
    assert ok is False
    assert "libtwofish" in message


def test_engine_c_unavailable_without_directory():
    adapter = EngineCAdapter(Settings(pt_convert_dir=""))
    ok, message = adapter.probe()
    assert ok is False
    assert "TRIDENT_PT_CONVERT_DIR" in message


def test_engine_c_unavailable_with_bogus_directory():
    adapter = EngineCAdapter(Settings(pt_convert_dir="/nonexistent/pt-convert"))
    ok, message = adapter.probe()
    assert ok is False


# --- snapshot isolation ----------------------------------------------------

def test_select_snapshot_single_block():
    xml = "<ROOT><PACKETTRACER5><NETWORK><DEVICES><DEVICE/></DEVICES></NETWORK></PACKETTRACER5></ROOT>"
    snapshot, ambiguous, notes = _select_snapshot(xml)
    assert snapshot == "block0"
    assert ambiguous is False


def test_select_snapshot_reports_ambiguity_for_multiple_non_empty():
    device = "<NETWORK><DEVICES><DEVICE/></DEVICES></NETWORK>"
    xml = (
        "<ROOT>"
        f"<PACKETTRACER5>{device}</PACKETTRACER5>"
        f"<PACKETTRACER5>{device}{device}</PACKETTRACER5>"
        "</ROOT>"
    )
    snapshot, ambiguous, notes = _select_snapshot(xml)
    assert ambiguous is True
    assert snapshot == "block1"
    assert notes


def test_select_snapshot_empty_blocks():
    xml = "<ROOT><PACKETTRACER5></PACKETTRACER5><PACKETTRACER5></PACKETTRACER5></ROOT>"
    snapshot, ambiguous, notes = _select_snapshot(xml)
    assert ambiguous is False
    assert "empty" in notes[0].lower()


def test_snapshot_selection_never_reads_answer_keys():
    """The walker must not see ACTIVITY/COMPARISONS content."""
    from trident.parsers.pka_xml import _walk_xml

    xml = (
        "<ROOT><PACKETTRACER5><NETWORK><DEVICES>"
        "<DEVICE><ENGINE><NAME>R1</NAME></ENGINE></DEVICE>"
        "</DEVICES></NETWORK></PACKETTRACER5>"
        "<ACTIVITY><INSTRUCTIONS><LINE>SECRET_ANSWER_KEY</LINE></INSTRUCTIONS></ACTIVITY>"
        "<COMPARISONS><NODE>GRADING_SECRET</NODE></COMPARISONS></ROOT>"
    )
    walk = _walk_xml(xml)
    blob = str(walk)
    assert "SECRET_ANSWER_KEY" not in blob
    assert "GRADING_SECRET" not in blob
    assert walk["devices"] == ["R1"]


# --- real file execution (skipped without engines) -------------------------

@requires_real_file
@pytest.mark.skipif(not engine_available("engine_a"), reason="engine A unavailable")
def test_engine_a_real_file():
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        target = td_path / "input.pkt"
        target.write_bytes(REAL_PKT.read_bytes())
        result = EngineAAdapter(Settings()).run(target, td_path)
    assert result.report.state is ParserState.OK
    assert result.report.device_count == 7
    assert result.report.link_count == 5
    assert "R1" in result.devices
    assert "R1" in result.configs


@requires_real_file
@pytest.mark.skipif(not engine_available("engine_b"), reason="engine B unavailable")
def test_engine_b_real_file():
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        target = td_path / "input.pkt"
        target.write_bytes(REAL_PKT.read_bytes())
        result = EngineBAdapter(Settings()).run(target, td_path)
    assert result.report.state is ParserState.OK
    assert len(result.devices) == 7
    assert len(result.configs) >= 3


@requires_real_file
@pytest.mark.skipif(not engine_available("engine_c"), reason="engine C unavailable")
def test_engine_c_real_file():
    from trident.config import settings

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        target = td_path / "input.pkt"
        target.write_bytes(REAL_PKT.read_bytes())
        result = EngineCAdapter(settings).run(target, td_path)
    assert result.report.state is ParserState.OK
    assert len(result.devices) == 7
    assert len(result.links) == 5


@requires_real_file
@pytest.mark.skipif(not engine_available("engine_a"), reason="engine A unavailable")
def test_empty_activity_has_no_devices():
    """The shipped activity skeleton is genuinely empty; we must not invent devices."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        target = td_path / "input.pka"
        target.write_bytes(REAL_PKA.read_bytes())
        result = EngineAAdapter(Settings()).run(target, td_path)
    assert result.report.state is ParserState.OK
    assert result.devices == []


def test_engine_a_does_not_modify_input():
    """Read-only guarantee at the adapter level."""
    import hashlib

    if not engine_available("engine_a"):
        pytest.skip("engine A unavailable")
    original = REAL_PKT.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        target = td_path / "input.pkt"
        target.write_bytes(original)
        EngineAAdapter(Settings()).run(target, td_path)
        after = hashlib.sha256(target.read_bytes()).hexdigest()
    assert before == after
