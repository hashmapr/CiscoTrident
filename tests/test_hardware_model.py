"""Adversarial tests for hardware-model extraction and verification.

`<TYPE model="2911">Router</TYPE>` carries TWO distinct facts: the category
(Router) and the model (2911). Conflating them is the defect these tests pin.
"""

from __future__ import annotations

from trident.config import Settings
from trident.models import (
    AnswerStatus,
    DeviceInfo,
    NetworkModel,
    Observation,
    Provenance,
)
from trident.normalization.devices import Normalizer
from trident.parsers.base import AdapterResult
from trident.parsers.pka_xml import _walk_xml
from trident.reasoning import operations as ops
from trident.verification.consensus import ConsensusEngine


def _prov(engine: str) -> Provenance:
    return Provenance(
        engine=engine,
        extraction_path=f"{engine}:structural-type",
        snapshot="block0",
        extraction_family=engine,
        decoder="twofish-eax-qcompress-shared",
        interpretation_family="trident.parse_running_config",
    )


def _device_block(name: str, model: str, category: str = "Router") -> str:
    return (
        "<DEVICE><ENGINE>"
        f'<TYPE model="{model}" customModel="">{category}</TYPE>'
        f"<NAME>{name}</NAME>"
        "</ENGINE></DEVICE>"
    )


# --- extraction ------------------------------------------------------------

def test_engine_a_extracts_model_attribute_not_category():
    """The model comes from @model; 'Router' is the category, not the model."""
    walk = _walk_xml(f"<ROOT>{_device_block('R1', '2911')}</ROOT>")
    assert walk["models"]["R1"] == "2911"
    assert walk["models"]["R1"] != "Router"


def test_engine_a_handles_custom_model_attribute():
    walk = _walk_xml(
        f"<ROOT>{_device_block('SW1', '2960-24TT', 'Switch')}</ROOT>"
    )
    # customModel is the IOS image label, not the hardware model
    assert walk["models"]["SW1"] == "2960-24TT"


def test_missing_model_attribute_yields_no_model():
    xml = "<ROOT><DEVICE><ENGINE><NAME>R1</NAME></ENGINE></DEVICE></ROOT>"
    walk = _walk_xml(xml)
    assert "R1" not in walk["models"]


def test_power_distribution_is_not_a_hardware_model_for_answers():
    walk = _walk_xml(f"<ROOT>{_device_block('PDU', 'Power Distribution Device', 'Power Distribution Device')}</ROOT>")
    assert "PDU" not in walk["models"]


# --- consensus -------------------------------------------------------------

def _model_with(models: dict[str, str], engines: tuple[str, ...]) -> NetworkModel:
    observations = [
        Observation(
            field="hardware_model",
            entity_type="device",
            entity_id=name,
            value=value,
            provenance=_prov(engine),
        )
        for name, value in models.items()
        for engine in engines
    ]
    model = NetworkModel(
        devices={
            name: DeviceInfo(id=name, name=name, hostname=name, model=value)
            for name, value in models.items()
        },
        observations=observations,
        snapshot_id="block0",
    )
    return model


def test_three_families_verify():
    model = _model_with({"R1": "2911"}, ("engine_a", "engine_b", "engine_c"))
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.field("device", "R1", "hardware_model")
    assert fc.status is AnswerStatus.VERIFIED
    assert len(fc.agreeing_engines) == 3


def test_one_family_is_incomplete_not_verified():
    model = _model_with({"R1": "2911"}, ("engine_a",))
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.field("device", "R1", "hardware_model")
    assert fc.status is AnswerStatus.INCOMPLETE


def test_two_families_is_incomplete_under_strict():
    model = _model_with({"R1": "2911"}, ("engine_a", "engine_b"))
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.field("device", "R1", "hardware_model")
    assert fc.status is AnswerStatus.INCOMPLETE


def test_conflicting_models_conflict():
    model = _model_with({"R1": "2911"}, ("engine_a", "engine_b", "engine_c"))
    model.observations.append(
        Observation(
            field="hardware_model",
            entity_type="device",
            entity_id="R1",
            value="1941",
            provenance=_prov("engine_c"),
        )
    )
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.field("device", "R1", "hardware_model")
    assert fc.status is AnswerStatus.CONFLICT


def test_duplicate_evidence_from_one_family_does_not_inflate_agreement():
    """Three observations from ONE engine are still one family."""
    model = _model_with({"R1": "2911"}, ("engine_a", "engine_a", "engine_a"))
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.field("device", "R1", "hardware_model")
    assert len(fc.agreeing_engines) == 1
    assert fc.status is AnswerStatus.INCOMPLETE


# --- operation -------------------------------------------------------------

def test_model_operation_rejects_wrong_device():
    model = _model_with({"R1": "2911", "R2": "1941"}, ("engine_a", "engine_b", "engine_c"))
    r = ops.run_operation(model, "get_device_model", {"device": "R2"})
    assert r.status is ops.OpStatus.OK
    assert r.value == "1941", "must return the named device's model"


def test_model_operation_unknown_device_is_not_available():
    model = _model_with({"R1": "2911"}, ("engine_a",))
    r = ops.run_operation(model, "get_device_model", {"device": "R99"})
    assert r.status is not ops.OpStatus.OK


def test_model_answer_type_is_text_not_device():
    spec = ops.SPECS["get_device_model"]
    assert spec.answer_type is ops.AnswerType.TEXT
    assert spec.cardinality is ops.Cardinality.ONE


def test_removing_evidence_never_increases_confidence():
    """Dropping one engine's observation must not raise the status."""
    full = _model_with({"R1": "2911"}, ("engine_a", "engine_b", "engine_c"))
    ce_full = ConsensusEngine(full, Settings(consensus_policy="strict"))
    assert ce_full.field("device", "R1", "hardware_model").status is AnswerStatus.VERIFIED

    partial = _model_with({"R1": "2911"}, ("engine_a", "engine_b"))
    ce_partial = ConsensusEngine(partial, Settings(consensus_policy="strict"))
    assert ce_partial.field("device", "R1", "hardware_model").status is AnswerStatus.INCOMPLETE


# --- normalizer wiring -----------------------------------------------------

def _result(engine: str, models: dict[str, str]) -> AdapterResult:
    from trident.models import ParserReport, ParserState

    return AdapterResult(
        engine_id=engine,
        report=ParserReport(engine=engine, state=ParserState.OK),
        devices=sorted(models),
        extraction_family=engine,
        raw={"models": models, "snapshot": "block0"},
    )


def test_normalizer_records_hardware_model_per_engine():
    results = [
        _result("engine_a", {"R1": "2911"}),
        _result("engine_b", {"R1": "2911"}),
        _result("engine_c", {"R1": "2911"}),
    ]
    model = Normalizer(results, snapshot_id="block0").build()
    obs = [o for o in model.observations if o.field == "hardware_model"]
    assert len(obs) == 3
    assert {o.provenance.engine for o in obs} == {"engine_a", "engine_b", "engine_c"}
    assert all(o.provenance.snapshot == "block0" for o in obs)


def test_normalizer_keeps_conflicting_models_distinct():
    results = [
        _result("engine_a", {"R1": "2911"}),
        _result("engine_b", {"R1": "1941"}),
        _result("engine_c", {"R1": "2911"}),
    ]
    model = Normalizer(results, snapshot_id="block0").build()
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    assert ce.field("device", "R1", "hardware_model").status is AnswerStatus.CONFLICT


def test_normalizer_without_models_emits_nothing():
    results = [_result("engine_a", {})]
    model = Normalizer(results, snapshot_id="block0").build()
    assert not [o for o in model.observations if o.field == "hardware_model"]
