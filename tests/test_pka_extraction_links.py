"""Regression tests for physical-link extraction and its honesty reporting.

Defect pinned here: Engine B stopped running pkt-core's container CLI (to stay
inside its timeout), but links were read only from that CLI's DOT export. The
DOT file was therefore never produced, so ``link_count`` was silently zero on
every file -- including files whose typed model carried the links all along.

The tests also pin that a zero/near-zero link result is *reported*, not hidden:
an omitted link must leave a note, and an empty snapshot must say why.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest
from conftest import REAL_PKT, engine_available

from trident.config import Settings
from trident.parsers.pka_xml import EngineAAdapter, _walk_xml
from trident.parsers.pkt_core import EngineBAdapter, _links_from_lab

pytestmark = pytest.mark.skipif(
    not REAL_PKT.exists(), reason=f"fixture not present: {REAL_PKT}"
)


def _run(adapter_cls, source: pathlib.Path, suffix: str | None = None):
    raw = source.read_bytes()
    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td)
        target = work / f"input{suffix or source.suffix}"
        target.write_bytes(raw)
        return adapter_cls(Settings()).run(target, work)


@pytest.mark.skipif(not engine_available("engine_b"), reason="engine B unavailable")
def test_engine_b_extracts_links_from_its_own_model():
    """Engine B must report the physical links its typed model already parsed."""
    result = _run(EngineBAdapter, REAL_PKT)
    assert result.report.state.value == "OK"
    assert len(result.links) == 5, result.report.message
    assert result.report.link_count == 5


@pytest.mark.skipif(not engine_available("engine_b"), reason="engine B unavailable")
@pytest.mark.skipif(not engine_available("engine_a"), reason="engine A unavailable")
def test_engine_b_and_engine_a_agree_on_the_link_set():
    """The two independent parsers must derive the same physical topology."""
    a = _run(EngineAAdapter, REAL_PKT)
    b = _run(EngineBAdapter, REAL_PKT)
    assert set(a.links) == set(b.links), (
        f"A={sorted(a.links)} B={sorted(b.links)}"
    )
    assert len(a.links) == len(b.links) == 5


@pytest.mark.skipif(not engine_available("engine_b"), reason="engine B unavailable")
def test_engine_b_links_survive_decoded_xml_input():
    """The XML input path must extract the same links as the container path."""
    from trident.pktcrypto.cache import SHARED

    xml = SHARED.decode(REAL_PKT.read_bytes())
    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td)
        target = work / "input.xml"
        target.write_bytes(xml)
        result = EngineBAdapter(Settings()).run(target, work)
    assert len(result.links) == 5, result.report.message


def test_engine_b_unusable_links_are_reported_not_silent():
    """If the model had links but none resolve, say so instead of returning [].

    Uses small stand-ins for pkt-core objects so the honesty branch is exercised
    without depending on a particular pkt-core version's internals.
    """

    class _Ref:
        def __init__(self, text):
            self.text = text

    class _Engine:
        def find(self, tag):
            return _Ref("save-ref-id:1") if tag == "SAVE_REF_ID" else None

    class _DeviceElement:
        def find(self, tag):
            return _Engine() if tag == "ENGINE" else None

    class _Device:
        name = "R1"
        element = _DeviceElement()

    class _Link:
        endpoints = ("save-ref-id:unknown", "save-ref-id:also-unknown")
        port_names = ("GigabitEthernet0/0", "GigabitEthernet0/1")
        type = "eCopper"

    class _Lab:
        devices = (_Device(),)
        links = (_Link(),)

    messages: list[str] = []
    # Endpoints do not resolve to a device inside the selected snapshot.
    links = _links_from_lab(_Lab(), {}, {"R1"}, messages)
    assert links == []
    assert any("links: 0 of 1 usable" in m for m in messages), messages


def test_engine_a_omitted_links_are_counted():
    """A LINK stanza that cannot resolve to a device must be counted, not dropped."""
    xml = """<PACKETTRACER5>
<DEVICE><ENGINE><NAME>R1</NAME><SAVE_REF_ID>r1</SAVE_REF_ID></ENGINE></DEVICE>
<DEVICE><ENGINE><NAME>R2</NAME><SAVE_REF_ID>r2</SAVE_REF_ID></ENGINE></DEVICE>
<LINK><FROM>r1</FROM><PORT>GigabitEthernet0/0</PORT><TO>r2</TO><PORT>GigabitEthernet0/0</PORT></LINK>
<LINK><FROM>r1</FROM><PORT>GigabitEthernet0/1</PORT><TO>ghost</TO>
<PORT>GigabitEthernet0/1</PORT></LINK>
</PACKETTRACER5>"""
    walk = _walk_xml(xml)
    assert len(walk["links"]) == 1
    assert walk["dropped_links"] == 1
