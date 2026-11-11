"""Engine B must decode the container exactly once.

The container decode is pure-Python AES-EAX and dominates cost on large files:
a 30 MB activity took 215 s to decode. Engine B used to decode three times —
once for the snapshot, once for the typed model, once more in a
``pkt_core.cli.main unpack`` subprocess — so its total was ~450 s and it
exceeded the parser timeout on that fixture.

These tests hold the single-decode property without needing the 30 MB file on
every run.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from trident.config import settings
from trident.ingestion import ingest
from trident.parsers.pkt_core import EngineBAdapter

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"


def test_engine_b_does_not_shell_out_to_the_cli(monkeypatch):
    """No subprocess may run: that path decodes the container again."""
    import subprocess

    calls: list[list[str]] = []
    original = subprocess.run

    def spy(args, *rest, **kwargs):
        calls.append(args if isinstance(args, list) else [str(args)])
        return original(args, *rest, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)

    adapter = EngineBAdapter(settings)
    ok, _ = adapter.probe()
    if not ok:
        pytest.skip("pkt-core is not installed")
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    ingested = ingest(FIXTURE.name, FIXTURE.read_bytes(), settings)
    workdir = pathlib.Path(tempfile.mkdtemp())
    file_path = ingested.temp_path(workdir)
    result = adapter.run(file_path, workdir)

    assert result.report.state.value in {"OK", "ERROR"}
    assert not calls, f"engine B spawned a subprocess: {calls}"


def test_engine_b_decodes_once(monkeypatch):
    """The container must be decoded exactly once per run.

    Engine B now prefers TRIDENT's own decoder and falls back to pkt-core only
    for formats ours does not implement. The invariant is unchanged, so this
    counts *whichever* decoder runs rather than assuming pkt-core will be the
    one called.
    """
    import pkt_core


    ok_adapter = EngineBAdapter(settings)
    ok, _ = ok_adapter.probe()
    if not ok:
        pytest.skip("pkt-core is not installed")
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    calls = {"decode": 0, "open_lab": 0}
    real_decode = pkt_core.decode_bytes
    real_open = pkt_core.open_lab

    # Engine B now goes through the shared content-addressed cache, so the
    # decode to count is the cache's, not decode_bytes directly. Count the
    # cache's cold path: one miss per distinct input is exactly one decode.
    from trident.pktcrypto.cache import SHARED

    SHARED.clear()
    real_cache_decode = type(SHARED).decode

    def counting_cache_decode(self, raw):
        if self.get(raw) is None:
            calls["decode"] += 1
        return real_cache_decode(self, raw)

    monkeypatch.setattr(type(SHARED), "decode", counting_cache_decode)

    def counting_decode(*args, **kwargs):
        calls["decode"] += 1
        return real_decode(*args, **kwargs)

    def counting_open(*args, **kwargs):
        calls["open_lab"] += 1
        return real_open(*args, **kwargs)

    monkeypatch.setattr(pkt_core, "decode_bytes", counting_decode)
    monkeypatch.setattr(pkt_core, "open_lab", counting_open)

    ingested = ingest(FIXTURE.name, FIXTURE.read_bytes(), settings)
    workdir = pathlib.Path(tempfile.mkdtemp())
    file_path = ingested.temp_path(workdir)
    EngineBAdapter(settings).run(file_path, workdir)

    assert calls["decode"] == 1, f"decoded {calls['decode']} times"
    assert calls["open_lab"] == 0, "open_lab decodes again; use the decoded bytes"


def test_engine_b_still_extracts_devices_and_configs():
    """The optimisation must not change what Engine B produces."""
    adapter = EngineBAdapter(settings)
    ok, _ = adapter.probe()
    if not ok:
        pytest.skip("pkt-core is not installed")
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    ingested = ingest(FIXTURE.name, FIXTURE.read_bytes(), settings)
    workdir = pathlib.Path(tempfile.mkdtemp())
    result = adapter.run(ingested.temp_path(workdir), workdir)

    assert result.report.state.value == "OK"
    assert result.devices, "devices must still be extracted"
    assert result.configs, "configs must still be extracted"
    assert result.report.interface_count > 0


#: Resolved from the repository root, not the process working directory. With a
#: relative path this performance test silently skipped whenever pytest ran from
#: anywhere but the repo root, so the timing claim went untested.
LARGE_LAB = pathlib.Path(__file__).parents[1] / "test-labs" / "incoming" / "Modules_1-13_Image.pka"


@pytest.mark.skipif(
    not LARGE_LAB.is_file(),
    reason="the 30MB activity fixture is not present locally",
)
def test_large_fixture_completes_within_a_bounded_time():
    """The file that used to exceed the timeout must now finish."""
    import time

    big = LARGE_LAB
    adapter = EngineBAdapter(settings)
    ok, _ = adapter.probe()
    if not ok:
        pytest.skip("pkt-core is not installed")

    ingested = ingest(big.name, big.read_bytes(), settings)
    workdir = pathlib.Path(tempfile.mkdtemp())
    started = time.monotonic()
    result = adapter.run(ingested.temp_path(workdir), workdir)
    elapsed = time.monotonic() - started

    assert result.report.state.value == "OK", result.report.message
    assert result.report.device_count > 0
    # One decode of 30 MB costs ~220 s on this machine. Three would be ~660 s.
    assert elapsed < 480, f"took {elapsed:.0f}s; the third decode is probably back"
