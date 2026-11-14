"""End-to-end running-config extraction from the shipped fixtures.

Covers the two fixtures the integration work depends on:

* ``sample_lab.pkt`` -- a real single-network lab with devices, links and
  running configs;
* ``sample_activity.pka`` -- an activity *skeleton* with three empty
  ``<PACKETTRACER5>`` blocks. It must abstain honestly, never invent devices.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest
from conftest import REAL_PKA, REAL_PKT, engine_available

from trident.config import Settings
from trident.normalization.configs import parse_running_config
from trident.parsers.pka_xml import EngineAAdapter
from trident.parsers.pkt_core import EngineBAdapter

ENGINES = [
    pytest.param(EngineAAdapter, "engine_a", id="engine-a"),
    pytest.param(EngineBAdapter, "engine_b", id="engine-b"),
]


def _run(adapter_cls, source: pathlib.Path):
    raw = source.read_bytes()
    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td)
        target = work / f"input{source.suffix}"
        target.write_bytes(raw)
        return adapter_cls(Settings()).run(target, work)


def _skip_if(engine_id: str):
    return pytest.mark.skipif(
        not engine_available(engine_id), reason=f"{engine_id} unavailable"
    )


@_skip_if("engine_a")
@_skip_if("engine_b")
@pytest.mark.parametrize("adapter_cls,engine_id", ENGINES)
def test_running_config_extracts_end_to_end(adapter_cls, engine_id):
    if not REAL_PKT.exists():
        pytest.skip(f"fixture not present: {REAL_PKT}")
    result = _run(adapter_cls, REAL_PKT)
    assert result.report.state.value == "OK"
    assert {"R1", "R2", "SW1"} <= set(result.configs), sorted(result.configs)

    r1 = parse_running_config(result.configs["R1"])
    assert r1.hostname
    addrs = {
        i.name.lower(): i.ipv4_address
        for i in r1.interfaces.values()
        if i.ipv4_address
    }
    assert addrs.get("gigabitethernet0/0") == "192.168.1.1"
    assert addrs.get("gigabitethernet0/1") == "192.168.2.1"


@_skip_if("engine_a")
@_skip_if("engine_b")
def test_startup_config_is_not_merged_into_running():
    """Only the running configuration is authoritative for the live network."""
    if not REAL_PKT.exists():
        pytest.skip(f"fixture not present: {REAL_PKT}")
    a = _run(EngineAAdapter, REAL_PKT)
    b = _run(EngineBAdapter, REAL_PKT)
    for result in (a, b):
        text = "\n".join(result.configs["R1"])
        # The lab's running config uses 192.168.1.1; a merged startup copy
        # would add a second hostname/address set.
        assert text.count("hostname R1") == 1


@_skip_if("engine_a")
@_skip_if("engine_b")
def test_engines_agree_on_config_meaning():
    """Indentation differs; the extracted IOS meaning must not."""
    if not REAL_PKT.exists():
        pytest.skip(f"fixture not present: {REAL_PKT}")
    a = _run(EngineAAdapter, REAL_PKT).configs
    b = _run(EngineBAdapter, REAL_PKT).configs
    assert set(a) == set(b)
    for name in a:
        assert [ln.strip() for ln in a[name]] == [ln.strip() for ln in b[name]], name


@_skip_if("engine_a")
def test_empty_activity_abstains_and_says_why():
    if not REAL_PKA.exists():
        pytest.skip(f"fixture not present: {REAL_PKA}")
    result = _run(EngineAAdapter, REAL_PKA)
    assert result.devices == []
    assert result.links == []
    assert result.raw["snapshot_abstained"] is True
    assert "empty" in result.report.message.lower()


@_skip_if("engine_b")
def test_engine_b_empty_activity_abstains_honestly():
    if not REAL_PKA.exists():
        pytest.skip(f"fixture not present: {REAL_PKA}")
    result = _run(EngineBAdapter, REAL_PKA)
    assert result.devices == []
    assert result.links == []
    assert result.raw["snapshot_abstained"] is True
    assert any("empty" in note.lower() for note in result.raw["snapshot_notes"])
