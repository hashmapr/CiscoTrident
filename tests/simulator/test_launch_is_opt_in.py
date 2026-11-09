"""Packet Tracer must never start unless explicitly allowed.

This exists because it did start when it should not have: an operator studying
at their desk had Packet Tracer open on the desktop because a library call
defaulted to live. Starting a GUI app is intrusive, so consent is explicit and
these tests fail if that default ever flips back.
"""

from __future__ import annotations

import subprocess

import pytest

from trident.simulator import SimulatorRuntime
from trident.simulator.backends import ALLOW_LIVE_ENV, live_allowed
from trident.tools import inspect_labs


def _packet_tracer_running() -> bool:
    try:
        out = subprocess.run(
            ["pgrep", "-f", "Contents/MacOS/PacketTracer"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(out.stdout.strip())


@pytest.mark.parametrize("value", ["", "0", "false", "no", "  "])
def test_launch_is_denied_by_default(monkeypatch, value):
    monkeypatch.setenv(ALLOW_LIVE_ENV, value)
    assert live_allowed() is False


@pytest.mark.parametrize("value", ["1", "true", "yes"])
def test_launch_requires_an_affirmative_value(monkeypatch, value):
    monkeypatch.setenv(ALLOW_LIVE_ENV, value)
    assert live_allowed() is True


def test_runtime_refuses_live_without_consent(monkeypatch):
    """The runtime must report unavailability, not start the app."""
    monkeypatch.delenv(ALLOW_LIVE_ENV, raising=False)
    runtime = SimulatorRuntime()
    assert runtime.prefer_live is False
    assert runtime.is_available() is False
    assert "TRIDENT_ALLOW_LIVE_SIMULATOR" in runtime.availability_reason()


def test_explicit_prefer_live_still_needs_consent(monkeypatch):
    """A caller asking for live is not consent on its own."""
    monkeypatch.delenv(ALLOW_LIVE_ENV, raising=False)
    from trident.simulator.backends import select_backend

    try:
        select_backend(
            working_copy=__import__("pathlib").Path("/tmp/none.pkt"),
            source_sha256="x",
            session_id="s",
            workspace=__import__("pathlib").Path("/tmp"),
            prefer_live=True,
            scripted_scenario=None,
            allow_scripted=False,
        )
    except Exception as exc:  # noqa: BLE001 - the message is what matters
        assert "TRIDENT_ALLOW_LIVE_SIMULATOR" in str(exc)
    else:
        pytest.fail("select_backend started or accepted a live backend without consent")


def test_static_inspection_does_not_launch_packet_tracer(monkeypatch, capfd):
    """The safe path must stay completely offline from the GUI app."""
    monkeypatch.delenv(ALLOW_LIVE_ENV, raising=False)
    lab = __import__("pathlib").Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    assert not _packet_tracer_running(), "Packet Tracer was already running; test is inconclusive"
    code = inspect_labs.main([str(lab)])
    assert code == 0
    assert not _packet_tracer_running(), "static inspection started Packet Tracer"


def test_live_flag_is_refused_without_consent(monkeypatch, capfd):
    monkeypatch.delenv(ALLOW_LIVE_ENV, raising=False)
    lab = __import__("pathlib").Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    inspect_labs.main([str(lab), "--live"])
    captured = capfd.readouterr()
    assert "refusing to launch Packet Tracer" in captured.out
    assert not _packet_tracer_running()


def test_inspector_reports_an_empty_pka_honestly():
    """A .pka with no network must say so, not be called a failure."""
    pka = __import__("pathlib").Path(__file__).parents[1] / "fixtures" / "sample_activity.pka"
    if not pka.is_file():
        pytest.skip("sample_activity.pka fixture is not present")
    result = inspect_labs.inspect(pka)
    assert result["status"] in {"NO_NETWORK_EXTRACTED", "ANALYZED"}
    assert result["unchanged"] is True


def test_inspector_never_modifies_the_file(tmp_path):
    lab = __import__("pathlib").Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    copy = tmp_path / "copy.pkt"
    copy.write_bytes(lab.read_bytes())
    before = copy.read_bytes()
    result = inspect_labs.inspect(copy)
    assert copy.read_bytes() == before
    assert result["unchanged"] is True
    assert result["sha256_before"] == result["sha256_after"]
