"""Offline regression over the six built gauntlet labs.

These tests are *regression*, not accuracy. They assert that trident can still
parse each shipped lab and that the analysis stays inside its time budget. They
say nothing about which faults are present or whether the reported ones are
correct — see ``docs/gauntlet/BLIND_RUN.md`` for the blind measurement.

No Packet Tracer, no network. Each lab is skipped when the built file is absent,
so the default suite on a machine without the gauntlet bundle stays green.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from trident.config import settings
from trident.diagnostics import diagnose
from trident.ingestion import ingest
from trident.pipeline import analyze

LAB_DIR = Path(
    os.environ.get(
        "TRIDENT_GAUNTLET_DIR",
        "/Users/tanayshah/Downloads/trident_gauntlet_complete/built",
    )
)

# Declared in gauntlet_index.json. Kept literal so a changed bundle cannot
# silently move the goalposts for this regression.
EXPECTED = [
    ("01_easy", 3, 2),
    ("02_basic", 5, 4),
    ("03_intermediate", 8, 7),
    ("04_advanced", 11, 11),
    ("05_expert", 17, 17),
    ("06_insane", 26, 26),
]

TIME_LIMIT_SECONDS = 120.0


def _pkt(level: str) -> Path:
    return LAB_DIR / f"{level}.pkt"


@pytest.mark.parametrize(("level", "devices", "links"), EXPECTED, ids=[e[0] for e in EXPECTED])
def test_gauntlet_lab_parses_with_expected_shape(level: str, devices: int, links: int) -> None:
    path = _pkt(level)
    if not path.is_file():
        pytest.skip(f"built lab absent: {path}")

    data = path.read_bytes()
    ingested = ingest(path.name, data)

    started = time.perf_counter()
    outcome = asyncio.run(
        analyze(
            ingested,
            "1. What is the hostname of the first router?",
            cfg=settings,
            use_ai=False,
        )
    )
    elapsed = time.perf_counter() - started

    model = outcome.model
    assert len(model.devices) == devices, (
        f"{level}: devices={len(model.devices)} expected {devices} ({sorted(model.devices)})"
    )
    assert len(model.links) == links, f"{level}: links={len(model.links)} expected {links}"
    assert elapsed < TIME_LIMIT_SECONDS, f"{level}: analysis took {elapsed:.1f}s"

    # Diagnosis must run and be internally well formed. It is allowed to be
    # empty: silence is a valid measurement, not a failure.
    diag = diagnose(model)
    assert isinstance(diag.to_report_dicts(), list)
    for finding in diag.to_report_dicts():
        assert finding["status"] in {"CONFIRMED_DEFECT", "SUSPECTED"}
        assert finding["confidence"] in {"HIGH", "MEDIUM", "LOW"}
        assert finding["kind"]
