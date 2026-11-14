"""Regression tests for parser input validation on mislabelled files.

Defect pinned here: Engine B trusts a ``.xml`` suffix and hands the bytes to
pkt-core's XML parser. Given container bytes, that parser never returned
(>100 s on the 81 KB fixture) instead of raising, so a renamed ``.pkt`` could
stall a parse until the timeout. A cheap content sniff now fails fast with
ERROR.
"""

from __future__ import annotations

import pathlib
import tempfile
import time

import pytest
from conftest import REAL_PKT, engine_available

from trident.config import Settings
from trident.parsers.pkt_core import EngineBAdapter

pytestmark = pytest.mark.skipif(
    not REAL_PKT.exists(), reason=f"fixture not present: {REAL_PKT}"
)


@pytest.mark.skipif(not engine_available("engine_b"), reason="engine B unavailable")
def test_container_renamed_to_xml_fails_fast_not_hang():
    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td)
        target = work / "input.xml"
        target.write_bytes(REAL_PKT.read_bytes())
        started = time.monotonic()
        result = EngineBAdapter(Settings()).run(target, work)
        elapsed = time.monotonic() - started

    assert result.report.state.value == "ERROR", result.report.message
    assert "not XML" in result.report.message
    assert elapsed < 5.0, f"refusing a renamed container took {elapsed:.1f}s"
