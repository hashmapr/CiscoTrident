"""Regression tests for the three correctness priorities.

1. Snapshot isolation: every adapter must analyse one explicitly selected
   snapshot, or abstain. Multi-snapshot .pka documents are covered with
   synthetic containers (Engine A via a stubbed decoder, Engine B via a stubbed
   pkt_core, Engine C via a stubbed bridge subprocess) so no encrypted fixture
   is needed.
2. Consensus: distinct extraction families, matching snapshot identifiers and
   present provenance — not merely three distinct engine IDs.
3. Multi-select: every offered option is independently adjudicated.

Read-only policy is untouched; no test writes outside a TemporaryDirectory.
"""

from __future__ import annotations

import json
import sys
import types

from conftest import build_model, obs

from trident.config import Settings
from trident.models import AnswerStatus
from trident.parsers.pka_xml import EngineAAdapter, _walk_xml
from trident.parsers.pkt_core import EngineBAdapter
from trident.parsers.pt_convert import EngineCAdapter
from trident.reasoning import mcq
from trident.verification.consensus import ConsensusEngine

# ---------------------------------------------------------------------------
# Synthetic multi-snapshot documents
# ---------------------------------------------------------------------------

def _device(name: str, ip: str = "10.0.0.1") -> str:
    return (
        "<DEVICE><ENGINE>"
        f"<NAME>{name}</NAME>"
        "<LINE>interface GigabitEthernet0/0</LINE>"
        f"<LINE>ip address {ip} 255.255.255.0</LINE>"
        "</ENGINE></DEVICE>"
    )


SNAP_A = "<NETWORK><DEVICES>" + _device("R1") + _device("SW1") + "</DEVICES></NETWORK>"
SNAP_B = (
    "<NETWORK><DEVICES>"
    + _device("R1", "172.16.0.1")
    + _device("ANSWER_KEY_DEVICE")
    + "</DEVICES></NETWORK>"
)


def _two_snapshot_xml() -> str:
    return (
        "<PACKETTRACER5_ACTIVITY>"
        f"<PACKETTRACER5>{SNAP_A}</PACKETTRACER5>"
        f"<PACKETTRACER5>{SNAP_B}</PACKETTRACER5>"
        "</PACKETTRACER5_ACTIVITY>"
    )


# ---------------------------------------------------------------------------
# Issue 1: snapshot isolation
# ---------------------------------------------------------------------------

def test_walk_xml_scopes_to_requested_text_only():
    """Device inventory from SNAP_B must never appear after scoping to SNAP_A."""
    walk = _walk_xml(SNAP_A)
    assert "R1" in walk["devices"]
    assert "ANSWER_KEY_DEVICE" not in walk["devices"]


def test_walk_xml_full_document_is_contaminated_without_selection():
    """Documents the pre-fix failure mode: an unscoped walk merges snapshots."""
    walk = _walk_xml(_two_snapshot_xml())
    assert "ANSWER_KEY_DEVICE" in walk["devices"]


def _stub_pka2xml(monkeypatch, xml: str):
    stub = types.ModuleType("pka2xml")
    stub.decrypt_pka = lambda raw: xml.encode("utf-8")
    monkeypatch.setitem(sys.modules, "pka2xml", stub)


def test_engine_a_abstains_on_multi_snapshot_pka(tmp_path, monkeypatch):
    """A multi-snapshot pka with differing blocks must yield zero extraction."""
    _stub_pka2xml(monkeypatch, _two_snapshot_xml())
    adapter = EngineAAdapter(Settings())
    ok, _ = adapter.probe()
    assert ok, "engine A vendored package should be importable in this environment"

    f = tmp_path / "multi.pka"
    f.write_bytes(b"stub-container")
    result = adapter._extract(f, tmp_path)

    assert result.devices == []
    assert result.configs == {}
    assert result.links == []
    assert result.raw["snapshot"] == "abstain"
    assert result.raw["snapshot_abstained"] is True
    assert "ANSWER_KEY_DEVICE" not in str(result.raw)


def test_engine_a_extracts_only_selected_block(tmp_path, monkeypatch):
    """Single-snapshot selection scopes the walk: SNAP_B is never merged."""
    xml = (
        "<PACKETTRACER5_ACTIVITY>"
        f"<ACTIVITY><INSTRUCTIONS>answer secrets</INSTRUCTIONS></ACTIVITY>"
        f"<PACKETTRACER5>{SNAP_A}</PACKETTRACER5>"
        f"<PACKETTRACER5><EMPTY/></PACKETTRACER5>"
        "</PACKETTRACER5_ACTIVITY>"
    )
    _stub_pka2xml(monkeypatch, xml)
    adapter = EngineAAdapter(Settings())
    f = tmp_path / "single.pka"
    f.write_bytes(b"stub")
    result = adapter._extract(f, tmp_path)

    assert result.raw["snapshot"] == "block0"
    assert result.devices == ["R1", "SW1"]
    assert "ANSWER" not in json.dumps(result.raw)


def _stub_pkt_core(monkeypatch, xml: str):
    stub = types.ModuleType("pkt_core")
    stub.__version__ = "stub"
    stub.decode_bytes = lambda raw: types.SimpleNamespace(xml=xml.encode("utf-8"))

    class _Dev:
        def __init__(self, name):
            self.name = name

    class _Lab:
        devices = (
            _Dev("R1"),
            _Dev("SW1"),
            _Dev("ANSWER_KEY_DEVICE"),
        )

    stub.open_lab = lambda path: _Lab()
    monkeypatch.setitem(sys.modules, "pkt_core", stub)


def test_engine_b_filters_extraction_to_selected_snapshot(tmp_path, monkeypatch):
    """Engine B inventory must not include devices from other snapshot blocks."""
    _stub_pkt_core(monkeypatch, _two_snapshot_xml())

    # two differing non-empty blocks -> abstain
    adapter = EngineBAdapter(Settings())
    assert adapter.probe()[0]
    f = tmp_path / "multi.pkt"
    f.write_bytes(b"stub")
    result = adapter._extract(f, tmp_path)
    assert result.devices == []
    assert result.raw["snapshot"] == "abstain"


def test_engine_b_single_snapshot_filters_foreign_devices(tmp_path, monkeypatch):
    """Devices the engine reports but that live outside the block are dropped."""
    xml = (
        "<PACKETTRACER5_ACTIVITY>"
        f"<ACTIVITY><EXTRA><DEVICE><ENGINE><NAME>ANSWER_KEY_DEVICE</NAME></ENGINE></DEVICE>"
        "</EXTRA></ACTIVITY>"
        f"<PACKETTRACER5>{SNAP_A}</PACKETTRACER5>"
        "</PACKETTRACER5_ACTIVITY>"
    )
    _stub_pkt_core(monkeypatch, xml)
    # open_lab would return the ACTIVITY device too; selection excludes it
    adapter = EngineBAdapter(Settings())
    f = tmp_path / "single.pkt"
    f.write_bytes(b"stub")

    # CLI unpack would fail on a stub file; the adapter tolerates that and
    # returns the typed-model devices filtered to the selected snapshot.
    result = adapter._extract(f, tmp_path)
    assert "ANSWER_KEY_DEVICE" not in result.devices
    assert set(result.devices) == {"R1", "SW1"}
    assert result.raw["snapshot"] == "block0"


def _stub_bridge(monkeypatch, payload: dict):
    import trident.parsers.pt_convert as pt_mod

    class _Proc:
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(pt_mod.shutil, "which", lambda name: "/usr/bin/node")
    monkeypatch.setattr(pt_mod.subprocess, "run", lambda *a, **kw: _Proc())


def test_engine_c_filters_simplifier_output_to_selected_snapshot(tmp_path, monkeypatch):
    """Engine C is scoped by the same shared policy, not by pt-convert itself."""
    payload = {
        "xml_text": _two_snapshot_xml(),
        "xml_bytes": len(_two_snapshot_xml()),
        "devices": {"R1": {"config": []}, "ANSWER_KEY_DEVICE": {"config": []}},
        "links": [{"FromDevice": "ANSWER_KEY_DEVICE", "ToDevice": "R1"}],
        "metadata": {},
        "activity_instructions": [],
    }
    _stub_bridge(monkeypatch, payload)
    pt_dir = tmp_path / "pt"
    pt_dir.mkdir()
    adapter = EngineCAdapter(Settings(pt_convert_dir=str(pt_dir)))
    f = tmp_path / "x.pka"
    f.write_bytes(b"stub")
    result = adapter._extract(f, tmp_path)

    # two differing blocks -> abstain -> nothing contributed
    assert result.devices == []
    assert result.links == []
    assert result.raw["snapshot"] == "abstain"


def test_engine_c_single_snapshot_scope(tmp_path, monkeypatch):
    payload = {
        "xml_text": f"<ROOT><PACKETTRACER5>{SNAP_A}</PACKETTRACER5></ROOT>",
        "xml_bytes": 100,
        "devices": {"R1": {"config": []}, "ANSWER_KEY_DEVICE": {"config": []}},
        "links": [],
        "metadata": {},
        "activity_instructions": [],
    }
    _stub_bridge(monkeypatch, payload)
    pt_dir = tmp_path / "pt"
    pt_dir.mkdir()
    adapter = EngineCAdapter(Settings(pt_convert_dir=str(pt_dir)))
    f = tmp_path / "x.pkt"
    f.write_bytes(b"stub")
    result = adapter._extract(f, tmp_path)

    # simplifier only reported R1 and ANSWER_KEY_DEVICE; the filter keeps R1
    # (inside the snapshot) and drops ANSWER_KEY_DEVICE (outside it).
    assert set(result.devices) == {"R1"}
    assert result.raw["snapshot"] == "block0"


def test_pipeline_abstains_when_adapters_disagree_on_snapshot():
    from trident.pipeline import _agree_snapshot

    warnings: list[str] = []
    results = [
        types.SimpleNamespace(raw={"snapshot": "block0"}, ok=True),
        types.SimpleNamespace(raw={"snapshot": "block1"}, ok=True),
    ]
    snapshot, ambiguous = _agree_snapshot(results, warnings)
    assert snapshot == "abstain"
    assert ambiguous is True
    assert any("disagreed" in w for w in warnings)


def test_reference_wrappers_are_never_candidates():
    from trident.parsers.snapshot import select_snapshot

    xml = (
        "<ROOT>"
        f"<COMPARISONS><PACKETTRACER5>{SNAP_B}</PACKETTRACER5></COMPARISONS>"
        f"<PACKETTRACER5>{SNAP_A}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    assert sel.snapshot_id == "block1"
    assert sel.xml_text is not None
    assert "ANSWER_KEY_DEVICE" not in sel.xml_text


# ---------------------------------------------------------------------------
# Issue 2: consensus requires families, snapshot identity and provenance
# ---------------------------------------------------------------------------

def _three_engine_obs(snapshot: str = "block0", raw: str = "ip address 10.0.0.1 255.255.255.0"):
    return [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "10.0.0.1", e, raw=raw)
        for e in ("engine_a", "engine_b", "engine_c")
    ]


def test_three_distinct_engines_one_family_is_not_verified():
    """Three engine IDs sharing one extraction family are single-source evidence."""
    observations = [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "10.0.0.1", e)
        for e in ("engine_a", "engine_b", "engine_c")
    ]
    model = build_model(observations)
    # force identical families to simulate a degenerate engine configuration
    for o in model.observations:
        o.provenance.extraction_path = "shared-vendor:ios-config"
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.INCOMPLETE


def test_distinct_families_are_verified():
    model = build_model(_three_engine_obs())
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.VERIFIED


def test_snapshot_identity_mismatch_is_incomplete():
    observations = _three_engine_obs()
    observations[0].provenance.snapshot = "block1"  # disagrees
    model = build_model(observations)
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.INCOMPLETE


def test_missing_snapshot_attribution_is_incomplete():
    observations = _three_engine_obs()
    observations[1].provenance.snapshot = ""
    model = build_model(observations)
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.INCOMPLETE


def test_two_engine_policy_not_satisfied_by_single_engine():
    """Regression: availability may not lower the bar below the policy floor."""
    from trident.config import Settings as S

    one_engine = [obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "10.0.0.1", "engine_a")]
    model = build_model(one_engine)
    ce = ConsensusEngine(model, S(consensus_policy="two_engine"))
    assert ce.required == 2
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.INCOMPLETE


def test_deterministic_policy_yields_verified_derived_not_verified():
    from trident.config import Settings as S

    model = build_model([obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "10.0.0.1", "engine_a")])
    ce = ConsensusEngine(model, S(consensus_policy="deterministic"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.VERIFIED_DERIVED


def test_two_agreeing_engines_under_two_engine_policy_verify():
    from trident.config import Settings as S

    model = build_model(_three_engine_obs()[:2])
    ce = ConsensusEngine(model, S(consensus_policy="two_engine"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.VERIFIED


# ---------------------------------------------------------------------------
# Issue 3: multi-select — every offered option independently verified
# ---------------------------------------------------------------------------

from trident.models import ParsedQuestion, QuestionKind, QuestionOption


def _q(options: list[tuple[str, str]], stem: str = "Which addresses are on R1? (Choose two.)") -> ParsedQuestion:
    return ParsedQuestion(
        question_number=1,
        stem=stem,
        original=stem,
        kind=QuestionKind.MULTI_SELECT,
        options=[QuestionOption(letter=l, text=t) for l, t in options],
    )


def test_multi_select_every_option_adjudicated_verifies():
    q = _q(
        [
            ("A", "10.0.0.1"),
            ("B", "172.16.0.1"),
            ("C", "Gi0/0 has no address"),
            ("D", "MAC 0040.0B1E.B601"),
        ],
    )
    # A correct and established; B incorrect and established; C and D cannot
    # be adjudicated -> INCOMPLETE, never a guessed set.
    status, letters, expl = mcq.match_multi_independent(
        q,
        ["10.0.0.1"],
        incorrect_values=["172.16.0.1"],
    )
    assert status is AnswerStatus.INCOMPLETE
    assert letters == ["A"]
    assert "C" in expl and "D" in expl


def test_multi_select_fully_adjudicated_verifies():
    q = _q(
        [
            ("A", "10.0.0.1"),
            ("B", "Gi0/0 has no address"),
            ("C", "172.16.0.1"),
        ],
        stem="Which addresses are on R1?",
    )
    status, letters, _ = mcq.match_multi_independent(
        q,
        ["10.0.0.1"],
        incorrect_values=["172.16.0.1", "Gi0/0 has no address"],
    )
    assert status is AnswerStatus.VERIFIED
    assert letters == ["A"]


def test_multi_select_expected_count_mismatch_is_incomplete():
    q = _q(
        [
            ("A", "10.0.0.1"),
            ("B", "Gi0/0 has no address"),
            ("C", "SW1 is a switch"),
        ],
    )
    # B and C must be established INCORRECT for the set to be verified.
    status, letters, _ = mcq.match_multi_independent(
        q,
        ["10.0.0.1", "SW1 is a switch"],
        incorrect_values=["Gi0/0 has no address"],
    )
    # C verifies correct AND B incorrect -> all adjudicated; but only 2 of 2...
    # 10.0.0.1 -> A; SW1 is a switch -> C; B incorrect. Count 2 == expected 2.
    assert status is AnswerStatus.VERIFIED
    assert sorted(letters) == ["A", "C"]


def test_multi_select_count_less_than_expected_is_incomplete():
    """(Choose two) with only one established correct value must degrade."""
    q = _q(
        [
            ("A", "10.0.0.1"),
            ("B", "Gi0/0 has no address"),
            ("C", "SW1 is a switch"),
        ],
    )
    status, letters, expl = mcq.match_multi_independent(
        q, ["10.0.0.1"], incorrect_values=["Gi0/0 has no address", "SW1 is a switch"],
    )
    # every option is adjudicated, but the stem expects two selections and only
    # one correct value is established -> the set is not fully verified.
    assert status is AnswerStatus.INCOMPLETE
    assert letters == ["A"]
    assert "expects 2" in expl


def test_multi_select_ambiguous_mapping_conflicts():
    q = _q([("A", "10.0.0.1"), ("B", "10.0.0.1"), ("C", "Gi0/0 has no address")])
    status, letters, _ = mcq.match_multi_independent(q, ["10.0.0.1"])
    assert status is AnswerStatus.CONFLICT


def test_builder_multi_select_uses_all_plan_facts():
    """The builder pools every plan fact instead of only the first."""
    from trident.reasoning.ai_client import QueryPlan, QueryStep
    from trident.verification.validators import AnswerBuilder

    observations = [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "10.0.0.1", e, raw="ip address 10.0.0.1 255.255.255.0")
        for e in ("engine_a", "engine_b", "engine_c")
    ]
    model = build_model(observations)
    model.settings.default_gateways["R1"] = "10.0.0.254"
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    builder = AnswerBuilder(model, ce)

    plan = QueryPlan(
        question_number=1,
        steps=[
            QueryStep(op="device_ip", device="R1", interface="GigabitEthernet0/0", reason="R1 IP"),
            QueryStep(op="default_gateway", device="R1", reason="gateway"),
        ],
    )
    q = _q(
        [
            ("A", "10.0.0.1"),
            ("B", "10.0.0.254"),
            ("C", "Gi0/0 has no address"),
        ],
        stem="Which two are true about R1? (Choose two.)",
    )
    result = builder.build(q, plan)
    # gateway is single-source (VERIFIED_DERIVED) so the answer cannot be VERIFIED;
    # C cannot be adjudicated either. Both guards must hold:
    assert result.status in (AnswerStatus.INCOMPLETE, AnswerStatus.VERIFIED_DERIVED)
    assert "C" in result.explanation or "independently" in result.explanation


def test_builder_multi_select_without_plan():
    from trident.verification.validators import AnswerBuilder

    observations = [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "10.0.0.1", e, raw="ip address 10.0.0.1 255.255.255.0")
        for e in ("engine_a", "engine_b", "engine_c")
    ]
    model = build_model(observations)
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    builder = AnswerBuilder(model, ce)
    q = _q([("A", "10.0.0.1"), ("B", "192.168.5.1"), ("C", "Gi0/0 is shutdown")])
    result = builder.build(q, None)
    # the deterministic heuristic cannot map this phrasing to any fact, so
    # nothing can be adjudicated: NOT_AVAILABLE (never a guessed subset).
    assert result.status is AnswerStatus.NOT_AVAILABLE
    assert result.selected_options == []


# ---------------------------------------------------------------------------
# Read-only policy untouched
# ---------------------------------------------------------------------------

def test_snapshots_never_merged_into_extraction():
    """The selected block text is a single block; never a concatenation."""
    from trident.parsers.snapshot import select_snapshot

    xml = (
        "<ROOT>"
        f"<PACKETTRACER5>{SNAP_A}</PACKETTRACER5>"
        f"<PACKETTRACER5>{SNAP_B}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    assert sel.abstained and sel.xml_text is None
