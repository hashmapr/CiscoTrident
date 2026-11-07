"""Shared fixtures. Synthetic observations are used for unit tests so the suite
runs without any engine; real-file tests are marked and skip when a fixture or
engine is unavailable."""

from __future__ import annotations

from pathlib import Path

import pytest

from trident.config import Settings
from trident.models import (
    DeviceInfo,
    InterfaceInfo,
    NetworkModel,
    Observation,
    Provenance,
)

FIXTURES = Path(__file__).parent / "fixtures"
REAL_PKT = FIXTURES / "sample_lab.pkt"
REAL_PKA = FIXTURES / "sample_activity.pka"


def make_prov(engine: str, path: str = "ios-config") -> Provenance:
    return Provenance(engine=engine, extraction_path=path, snapshot="block0")


def obs(
    entity_type: str,
    entity_id: str,
    field: str,
    value: str,
    engine: str,
    path: str = "ios-config",
    raw: str = "",
) -> Observation:
    return Observation(
        field=field,
        entity_type=entity_type,
        entity_id=entity_id,
        value=value,
        provenance=make_prov(engine, path),
        raw_evidence=raw,
    )


def build_model(observations: list[Observation], with_device: str = "R1") -> NetworkModel:
    model = NetworkModel(
        devices={
            with_device: DeviceInfo(
                id=with_device,
                name=with_device,
                hostname=with_device,
                interfaces=["GigabitEthernet0/0"],
            )
        },
        interfaces={
            f"{with_device}:GigabitEthernet0/0": InterfaceInfo(
                device=with_device,
                name="GigabitEthernet0/0",
                canonical_name="GigabitEthernet0/0",
                ipv4_address="192.168.1.1",
                subnet_mask="255.255.255.0",
                prefix_length=24,
            )
        },
        observations=observations,
        snapshot_id="block0",
    )
    return model


@pytest.fixture
def strict_cfg() -> Settings:
    return Settings(consensus_policy="strict")


@pytest.fixture
def three_engine_model() -> NetworkModel:
    """A model where one field is agreed by all three engines."""
    observations = [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_c"),
    ]
    return build_model(observations)


@pytest.fixture
def two_engine_model() -> NetworkModel:
    observations = [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
    ]
    return build_model(observations)


@pytest.fixture
def conflicting_model() -> NetworkModel:
    observations = [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "10.0.0.1", "engine_c"),
    ]
    return build_model(observations)


def engine_available(engine_id: str) -> bool:
    from trident.config import settings
    from trident.pipeline import build_adapters

    for adapter in build_adapters(settings):
        if adapter.engine_id == engine_id:
            ok, _ = adapter.probe()
            return ok
    return False


def all_engines_available() -> bool:
    return all(engine_available(e) for e in ("engine_a", "engine_b", "engine_c"))


requires_real_file = pytest.mark.skipif(
    not REAL_PKT.exists(), reason="real .pkt fixture not present"
)
requires_all_engines = pytest.mark.skipif(
    not all_engines_available(), reason="not all three engines are available in this environment"
)
