"""Three-engine consensus invariants.

These tests pin the properties the strict policy relies on:

* verification is gated on **distinct extraction families**, not just engine IDs;
* a duplicate observation from one family cannot inflate the agreement count;
* ``strict`` keeps ``required=3`` even when only two families exist;
* ``VERIFIED`` is only returned at or above ``required``;
* a missing family in provenance blocks verification;
* an absent engine reports ``UNAVAILABLE`` and never promotes ``INCOMPLETE``.

All observations are synthetic: no engine, Packet Tracer, or real file is needed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import build_model

from trident.config import Settings
from trident.models import (
    AnswerStatus,
    Observation,
    ParserState,
    Provenance,
)
from trident.parsers.pt_convert import EngineCAdapter
from trident.verification.consensus import ConsensusEngine, _extraction_family

DEVICE = "R1"
IFACE = "GigabitEthernet0/0"
ENTITY_ID = f"{DEVICE}:{IFACE}"
FIELD = "ipv4_address"

#: The families the real adapters declare (see conftest and the adapters).
FAMILY_A = "raw-xml-walk"
FAMILY_B = "pkt-core"
FAMILY_C = "pt-convert"


def prov(
    engine: str,
    family: str,
    *,
    path: str = "ios-config",
    decoder: str = "",
    snapshot: str = "block0",
) -> Provenance:
    """Provenance shaped like production output, with an explicit family."""
    return Provenance(
        engine=engine,
        extraction_path=f"{family}:{path}" if family else "",
        snapshot=snapshot,
        extraction_family=family,
        decoder=decoder,
    )


def ob(
    engine: str,
    family: str,
    value: str = "192.168.1.1",
    *,
    raw: str = "",
    path: str = "ios-config",
    decoder: str = "",
) -> Observation:
    return Observation(
        field=FIELD,
        entity_type="interface",
        entity_id=ENTITY_ID,
        value=value,
        provenance=prov(engine, family, path=path, decoder=decoder),
        raw_evidence=raw,
    )


def consensus(observations: list[Observation], policy: str = "strict"):
    model = build_model(observations)
    engine = ConsensusEngine(model, Settings(consensus_policy=policy))
    return engine.verify_interface_field(DEVICE, IFACE, FIELD)


# ---------------------------------------------------------------------------
# (a) Verification is gated on distinct extraction families, not engine IDs.
# ---------------------------------------------------------------------------


def test_three_distinct_families_are_verified():
    fc = consensus(
        [
            ob("engine_a", FAMILY_A),
            ob("engine_b", FAMILY_B),
            ob("engine_c", FAMILY_C),
        ]
    )
    assert fc.status is AnswerStatus.VERIFIED
    assert fc.value == "192.168.1.1"
    assert len(fc.agreeing_engines) == 3


def test_three_engines_two_families_are_incomplete():
    """Three engine IDs from two families are still single-source evidence."""
    observations = [
        ob("engine_a", FAMILY_A),
        ob("engine_b", FAMILY_B),
        ob("engine_c", FAMILY_A),
    ]
    fc = consensus(observations)

    # The engine count is three, but the independent family count is two.
    assert len(fc.agreeing_engines) == 3
    assert len({_extraction_family(o) for o in observations}) == 2
    assert fc.status is AnswerStatus.INCOMPLETE
    assert fc.status is not AnswerStatus.VERIFIED


def test_two_engines_one_family_are_incomplete_even_under_two_engine_policy():
    """The family gate binds under every policy, not only strict."""
    fc = consensus(
        [
            ob("engine_a", FAMILY_A),
            ob("engine_b", FAMILY_A),
        ],
        policy="two_engine",
    )
    assert len(fc.agreeing_engines) == 2
    assert fc.status is AnswerStatus.INCOMPLETE


def test_one_engine_one_family_is_incomplete():
    fc = consensus([ob("engine_a", FAMILY_A)])
    assert fc.status is AnswerStatus.INCOMPLETE
    assert fc.value == "192.168.1.1"


def test_two_engines_cannot_pad_the_family_count():
    """One engine emitting two family labels cannot pose as two pipelines."""
    fc = consensus(
        [
            ob("engine_a", FAMILY_A),
            ob("engine_a", FAMILY_B),
            ob("engine_b", FAMILY_C),
        ]
    )
    # Three family labels, but only two engines produced them.
    assert len({_extraction_family(o) for o in fc.observations}) == 3
    assert len(fc.agreeing_engines) == 2
    assert fc.status is AnswerStatus.INCOMPLETE


# ---------------------------------------------------------------------------
# (b) A duplicate observation from one family cannot inflate the count.
# ---------------------------------------------------------------------------


def test_same_engine_same_value_twice_counts_once():
    """A single engine repeating the same value is one observation, not two."""
    fc = consensus(
        [
            ob("engine_a", FAMILY_A),
            ob("engine_a", FAMILY_A),
        ]
    )
    summary = fc.summary()
    assert len(fc.agreeing_engines) == 1
    assert summary.agree == 1
    assert summary.available == 1
    assert fc.status is AnswerStatus.INCOMPLETE


def test_duplicate_does_not_inflate_a_two_family_agreement():
    """One engine twice plus one other engine is still two families, not three."""
    observations = [
        ob("engine_a", FAMILY_A),
        ob("engine_a", FAMILY_A),
        ob("engine_b", FAMILY_B),
    ]
    fc = consensus(observations)
    assert len(fc.agreeing_engines) == 2
    assert len({_extraction_family(o) for o in observations}) == 2
    assert fc.status is AnswerStatus.INCOMPLETE


def test_duplicate_from_a_third_engine_does_not_create_a_new_family():
    """Duplicating engine_c's observation must not manufacture a third family."""
    observations = [
        ob("engine_a", FAMILY_A),
        ob("engine_b", FAMILY_B),
        ob("engine_c", FAMILY_B),
        ob("engine_c", FAMILY_B),
    ]
    fc = consensus(observations)
    assert len({_extraction_family(o) for o in observations}) == 2
    assert fc.status is AnswerStatus.INCOMPLETE


# ---------------------------------------------------------------------------
# (c)/(d) strict keeps required=3; VERIFIED only at or above required.
# ---------------------------------------------------------------------------


def test_strict_required_stays_three_with_only_two_families():
    """The Q54 shape: two families agree, but strict still demands three."""
    fc = consensus(
        [
            ob("engine_a", FAMILY_A),
            ob("engine_b", FAMILY_B),
        ],
        policy="strict",
    )
    summary = fc.summary()
    assert (summary.agree, summary.available, summary.required) == (2, 2, 3)
    assert summary.policy == "strict"
    assert fc.status is AnswerStatus.INCOMPLETE
    assert fc.status is not AnswerStatus.VERIFIED


@pytest.mark.parametrize(
    ("observations", "expected"),
    [
        ([ob("engine_a", FAMILY_A)], AnswerStatus.INCOMPLETE),
        (
            [ob("engine_a", FAMILY_A), ob("engine_b", FAMILY_B)],
            AnswerStatus.INCOMPLETE,
        ),
        (
            [
                ob("engine_a", FAMILY_A),
                ob("engine_b", FAMILY_B),
                ob("engine_c", FAMILY_C),
            ],
            AnswerStatus.VERIFIED,
        ),
    ],
    ids=["one-family", "two-families", "three-families"],
)
def test_verified_only_at_or_above_required(observations, expected):
    fc = consensus(observations)
    assert fc.required == 3
    assert fc.status is expected


def test_two_families_that_disagree_are_a_conflict():
    fc = consensus(
        [
            ob("engine_a", FAMILY_A, "192.168.1.1"),
            ob("engine_b", FAMILY_B, "10.0.0.1"),
        ]
    )
    assert fc.status is AnswerStatus.CONFLICT
    assert fc.value is None
    assert fc.agreeing_engines == []
    assert fc.conflicts


# ---------------------------------------------------------------------------
# Missing provenance family cannot participate in verification.
# ---------------------------------------------------------------------------


def test_missing_family_in_provenance_blocks_verification():
    missing = Observation(
        field=FIELD,
        entity_type="interface",
        entity_id=ENTITY_ID,
        value="192.168.1.1",
        provenance=Provenance(
            engine="engine_c",
            extraction_path="",
            snapshot="block0",
            extraction_family="",
        ),
    )
    observations = [
        ob("engine_a", FAMILY_A),
        ob("engine_b", FAMILY_B),
        missing,
    ]
    fc = consensus(observations)
    assert "" in {_extraction_family(o) for o in observations}
    assert fc.status is AnswerStatus.INCOMPLETE
    assert fc.status is not AnswerStatus.VERIFIED


def test_all_missing_families_block_verification():
    observations = [
        Observation(
            field=FIELD,
            entity_type="interface",
            entity_id=ENTITY_ID,
            value="192.168.1.1",
            provenance=Provenance(
                engine=engine,
                extraction_path="",
                snapshot="block0",
                extraction_family="",
            ),
        )
        for engine in ("engine_a", "engine_b", "engine_c")
    ]
    fc = consensus(observations)
    assert fc.status is AnswerStatus.INCOMPLETE


# ---------------------------------------------------------------------------
# (4) An absent engine is UNAVAILABLE and never promotes INCOMPLETE.
# ---------------------------------------------------------------------------


def _fake_engine_c_checkout(tmp_path: Path) -> Path:
    """A checkout whose dependencies exist but whose src/lib modules do not."""
    root = tmp_path / "pt-convert"
    (root / "src" / "lib").mkdir(parents=True)
    (root / "node_modules").mkdir()
    (root / "node_modules" / "twofish").mkdir()
    return root


def test_engine_c_probe_reports_missing_src_lib(tmp_path: Path, monkeypatch):
    checkout = _fake_engine_c_checkout(tmp_path)
    adapter = EngineCAdapter(Settings(pt_convert_dir=str(checkout)))
    # Make the probe independent of whether Node.js is installed on the host.
    monkeypatch.setattr(adapter, "_node", lambda: "/usr/bin/node")

    available, message = adapter.probe()
    assert available is False
    assert message == "pt-convert checkout missing src/lib/packet-crypto.ts"


def test_absent_engine_is_unavailable_and_contributes_nothing(tmp_path: Path, monkeypatch):
    checkout = _fake_engine_c_checkout(tmp_path)
    cfg = Settings(pt_convert_dir=str(checkout))
    adapter = EngineCAdapter(cfg)
    monkeypatch.setattr(adapter, "_node", lambda: "/usr/bin/node")

    result = adapter.run(tmp_path / "input.pkt", tmp_path)
    assert result.report.state is ParserState.UNAVAILABLE
    assert result.observations == []
    assert result.extraction_family == ""


def test_absent_engine_never_promotes_incomplete_to_verified():
    """engine_a + engine_b agree; an unavailable engine_c must not become a vote."""
    model = build_model([ob("engine_a", FAMILY_A), ob("engine_b", FAMILY_B)])
    engine = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = engine.verify_interface_field(DEVICE, IFACE, FIELD)

    assert engine.available_engines() == 2
    assert engine.required == 3
    summary = fc.summary()
    assert (summary.agree, summary.available, summary.required) == (2, 2, 3)
    assert fc.status is AnswerStatus.INCOMPLETE
    assert fc.status is not AnswerStatus.VERIFIED
