"""Tests for the Engine B (pkt_core) authoring adapter.

Offline: no Packet Tracer, no network. The whole module is skipped when the
GPL-3.0 ``pkt_core`` distribution is not installed in the active interpreter.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

pkt_core = pytest.importorskip("pkt_core", reason="pkt_core (Engine B) not installed")

from trident.labgen.pktcore_adapter import (
    _GATEWAY_CLOSE,
    _engine_gateway,
    _scan_engine_gateways,
    gateway_support,
    postprocess_endhost_gateways,
    roundtrip_ok,
    semantic_compare,
)

PC_GATEWAY = "10.20.30.1"


def _build_pc_lab(*, gateway: str = PC_GATEWAY, with_link: bool = False):
    lab = pkt_core.Lab()
    lab.add_device("PC-PT", "PC1", 100, 100, pc_ip=["10.20.30.10", "255.255.255.0", gateway])
    lab.add_device("PC-PT", "PC2", 100, 300, pc_ip=["10.20.30.11", "255.255.255.0", gateway])
    lab.add_device("2960-24TT", "SW1", 300, 200)
    if with_link:
        lab.link("PC1", "FastEthernet0", "SW1", "FastEthernet0/1")
    return lab


def _build_router_lab(extra: list[str] | None = None):
    lab = pkt_core.Lab()
    lab.add_device(
        "2911",
        "R1",
        100,
        100,
        ios_config=[
            "hostname R1",
            "interface GigabitEthernet0/0",
            " ip address 10.1.1.1 255.255.255.0",
            " no shutdown",
        ]
        + list(extra or []),
    )
    return lab


def _mask_gateway_elements(xml: bytes) -> bytes:
    """Replace every ENGINE gateway element with a constant, keeping tags.

    Used to prove that all differences between two documents are confined to
    gateway elements: if the masked documents are byte-identical, nothing else
    moved.
    """
    spans = _scan_engine_gateways(xml)
    masked = xml
    for span in reversed(spans):
        full_end = span.end + (0 if span.empty else len(_GATEWAY_CLOSE))
        masked = masked[: span.start] + b"<GATEWAY>@</GATEWAY>" + masked[full_end:]
    return masked


def _device_inventory(xml: bytes) -> list[tuple[str, str]]:
    root = ET.fromstring(xml)
    out = []
    for dev in root.iter("DEVICE"):
        engine = dev.find("ENGINE")
        if engine is None:
            continue
        type_node = engine.find("TYPE")
        model = (type_node.get("model") or "") if type_node is not None else ""
        out.append(((engine.findtext("NAME") or "").strip(), model))
    return sorted(out)


def _running_config(xml: bytes) -> dict[str, list[str]]:
    root = ET.fromstring(xml)
    configs: dict[str, list[str]] = {}
    for dev in root.iter("DEVICE"):
        engine = dev.find("ENGINE")
        if engine is None:
            continue
        name = (engine.findtext("NAME") or "").strip()
        node = engine.find("RUNNINGCONFIG")
        configs[name] = [line.text or "" for line in (list(node) if node is not None else [])]
    return configs


def test_gateway_support_is_measured():
    ok, reason = gateway_support()

    assert isinstance(ok, bool)
    assert isinstance(reason, str) and reason
    assert "pkt_core" in reason
    assert getattr(pkt_core, "__version__", "unknown") in reason
    # The reason must state what was actually observed, not a claim.
    if ok:
        assert "matches" in reason
    else:
        assert "PORT_GATEWAY" in reason and "required" in reason


def test_postprocess_changes_only_gateway_elements():
    xml = _build_pc_lab().to_xml()
    hosts = {"PC1": PC_GATEWAY, "PC2": PC_GATEWAY}

    fixed = postprocess_endhost_gateways(xml, hosts)

    # All differences are inside ENGINE gateway elements.
    assert _mask_gateway_elements(fixed) == _mask_gateway_elements(xml)

    # Exactly the two named PCs are now correct.
    assert _engine_gateway(fixed, "PC1") == PC_GATEWAY
    assert _engine_gateway(fixed, "PC2") == PC_GATEWAY
    spans = [s for s in _scan_engine_gateways(fixed) if s.device in hosts]
    assert len(spans) == 2

    # Nothing else changed: same devices, same running config.
    assert _device_inventory(fixed) == _device_inventory(xml)
    assert _running_config(fixed) == _running_config(xml)

    # Idempotent: a second pass rewrites nothing.
    assert postprocess_endhost_gateways(fixed, hosts) == fixed


def test_postprocess_rejects_unknown_device():
    xml = _build_pc_lab().to_xml()
    with pytest.raises(KeyError):
        postprocess_endhost_gateways(xml, {"NO-SUCH-PC": PC_GATEWAY})


def test_fixup_survives_container_roundtrip(tmp_path):
    lab = _build_pc_lab(gateway="192.168.99.1")
    original = tmp_path / "original.pkt"
    lab.save(original)

    container = pkt_core.decode(original)
    fixed_xml = postprocess_endhost_gateways(container.xml, {"PC1": PC_GATEWAY, "PC2": PC_GATEWAY})
    rebuilt = pkt_core.encode_bytes(fixed_xml, container.format_name)
    fixed_path = tmp_path / "fixed.pkt"
    fixed_path.write_bytes(rebuilt)

    decoded = pkt_core.decode(fixed_path)
    assert _engine_gateway(decoded.xml, "PC1") == PC_GATEWAY
    assert _engine_gateway(decoded.xml, "PC2") == PC_GATEWAY

    # The rest of the document (configs, inventory) survived the fixup.
    assert _device_inventory(decoded.xml) == _device_inventory(container.xml)
    assert _running_config(decoded.xml) == _running_config(container.xml)


def test_semantic_compare_detects_config_change(tmp_path):
    base = tmp_path / "base.pkt"
    changed = tmp_path / "changed.pkt"
    _build_router_lab().save(base)
    _build_router_lab(["interface GigabitEthernet0/1", " shutdown"]).save(changed)

    diff = semantic_compare(base, changed)

    assert diff["error"] is None
    assert diff["identical"] is False
    assert diff["configs"], diff
    added = [line for entry in diff["configs"] for line in entry["added"]]
    assert any("GigabitEthernet0/1" in line for line in added)
    assert any("shutdown" in line for line in added)


def test_semantic_compare_reports_no_diff_for_identical_builds(tmp_path):
    first = tmp_path / "first.pkt"
    second = tmp_path / "second.pkt"
    _build_pc_lab(with_link=True).save(first)
    _build_pc_lab(with_link=True).save(second)

    diff = semantic_compare(first, second)

    assert diff["error"] is None
    assert diff["identical"] is True
    assert diff["devices"] == []
    assert diff["links"] == []
    assert diff["interfaces"] == []
    assert diff["configs"] == []
    assert diff["meta"] == {}


def test_semantic_compare_detects_gateway_difference(tmp_path):
    lab = _build_pc_lab(gateway="192.168.99.1")
    before = tmp_path / "before.pkt"
    after = tmp_path / "after.pkt"
    lab.save(before)

    container = pkt_core.decode(before)
    fixed = postprocess_endhost_gateways(container.xml, {"PC1": PC_GATEWAY, "PC2": PC_GATEWAY})
    after.write_bytes(pkt_core.encode_bytes(fixed, container.format_name))

    diff = semantic_compare(before, after)

    assert diff["error"] is None
    assert diff["identical"] is False
    assert diff["interfaces"], diff
    engine_rows = [entry for entry in diff["interfaces"] if entry.get("port") == 0]
    assert len(engine_rows) == 2
    for entry in engine_rows:
        assert entry["changes"]["GATEWAY"][1] == PC_GATEWAY


def test_roundtrip_ok_on_generated_lab(tmp_path):
    path = tmp_path / "roundtrip.pkt"
    _build_pc_lab().save(path)

    ok, reason = roundtrip_ok(path)

    assert ok is True, reason
    assert "lossless" in reason
    assert "pkt" in reason


def test_roundtrip_ok_reports_non_container(tmp_path):
    bad = tmp_path / "not-a-pkt.pkt"
    bad.write_bytes(b"not a container")

    ok, reason = roundtrip_ok(bad)

    assert ok is False
    assert reason
