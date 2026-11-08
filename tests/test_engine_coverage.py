"""Regression tests: every engine must independently supply IOS configuration.

The four-network benchmark exposed 31 correct answers stuck at INCOMPLETE because
only one engine produced per-field observations. The root causes were:

* Engine B refused a decoded ``.xml`` input outright, then still ran the
  container-only CLI and timed out after 300 s.
* Engine C's bridge had no XML path and skipped entirely.

These tests pin the corrected behaviour. They must not be satisfied by copying
Engine A's data -- each engine parses its own document.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from trident.config import Settings
from trident.normalization.configs import parse_running_config
from trident.parsers.pkt_core import EngineBAdapter
from trident.parsers.pt_convert import EngineCAdapter

CORPUS = pathlib.Path.home() / "Downloads" / "TRIDENT_4_Network_Benchmark_Pack" / "source_xml"
CCNA2 = CORPUS / "CCNA 2 Practice PTSA P2.xml"

pytestmark = pytest.mark.skipif(
    not CCNA2.exists(), reason=f"benchmark corpus not present: {CCNA2}"
)


def _run(adapter_cls, source: pathlib.Path):
    raw = source.read_bytes()
    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td)
        target = work / f"input{source.suffix}"
        target.write_bytes(raw)
        return adapter_cls(Settings()).run(target, work)


# --- Engine B -------------------------------------------------------------

def test_engine_b_parses_decoded_xml():
    """Engine B must use its own parser on XML, not refuse the input."""
    result = _run(EngineBAdapter, CCNA2)
    assert result.report.state.value == "OK"
    assert len(result.devices) == 24, result.report.message
    assert result.extraction_family == "pkt-core"


def test_engine_b_supplies_device_configs_for_xml():
    """Engine B must yield its own IOS configs, not zero."""
    result = _run(EngineBAdapter, CCNA2)
    assert len(result.configs) >= 9, f"got {len(result.configs)} configs"


def test_engine_b_configs_parse_into_observations():
    """A device config from Engine B must parse to interfaces/hostname."""
    result = _run(EngineBAdapter, CCNA2)
    assert "Central" in result.configs, sorted(result.configs)
    parsed = parse_running_config(result.configs["Central"])
    assert parsed.hostname, "hostname must parse from Engine B's config"
    assert parsed.interfaces, "interfaces must parse from Engine B's config"
    with_addr = [i for i in parsed.interfaces.values() if i.ipv4_address]
    assert with_addr, "at least one interface must carry an address"


def test_engine_b_does_not_run_the_container_cli_on_xml():
    """The CLI can only unpack containers; running it on XML wastes the timeout."""
    result = _run(EngineBAdapter, CCNA2)
    assert result.report.duration_ms < 180_000, (
        "engine B should parse XML directly, not wait on the container CLI"
    )


# --- Engine C -------------------------------------------------------------

def test_engine_c_parses_decoded_xml():
    """Engine C's bridge must accept XML and still run its own simplifier."""
    result = _run(EngineCAdapter, CCNA2)
    assert result.report.state.value == "OK"
    assert len(result.devices) == 24, result.report.message
    assert result.extraction_family == "pt-convert"


def test_engine_c_supplies_device_configs_for_xml():
    result = _run(EngineCAdapter, CCNA2)
    assert len(result.configs) >= 9, f"got {len(result.configs)} configs"


def test_engine_c_configs_parse_into_observations():
    result = _run(EngineCAdapter, CCNA2)
    assert "Central" in result.configs, sorted(result.configs)
    parsed = parse_running_config(result.configs["Central"])
    assert parsed.hostname
    assert any(i.ipv4_address for i in parsed.interfaces.values())


# --- the point of all of this: three independent families -----------------

def test_all_three_families_supply_the_same_address_independently():
    """Each engine's OWN parse must produce the same address for one interface.

    This is the property consensus depends on. It is not synthesised: each
    engine's config text is parsed separately here.
    """
    from trident.parsers.pka_xml import EngineAAdapter

    a = _run(EngineAAdapter, CCNA2)
    b = _run(EngineBAdapter, CCNA2)
    c = _run(EngineCAdapter, CCNA2)

    def addr(result, device: str, iface: str) -> str | None:
        lines = result.configs.get(device)
        if not lines:
            return None
        parsed = parse_running_config(lines)
        for info in parsed.interfaces.values():
            if info.name.lower() == iface.lower():
                return info.ipv4_address
        return None

    a_addr = addr(a, "Central", "GigabitEthernet0/0/0")
    b_addr = addr(b, "Central", "GigabitEthernet0/0/0")
    c_addr = addr(c, "Central", "GigabitEthernet0/0/0")

    assert a_addr, "engine A must supply the address"
    assert b_addr, "engine B must supply the address independently"
    assert c_addr, "engine C must supply the address independently"
    assert a_addr == b_addr == c_addr == "192.168.1.1"
