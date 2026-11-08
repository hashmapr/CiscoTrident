"""Phase 3 API surface: read-out of what Phase 3 computed.

This router is deliberately thin. The heavy lifting (parsing, investigation,
auditing, what-if) lives in the pipeline and the phase-3 packages; the endpoints
present results and enforce two rules:

* every response that could involve operational evidence states its
  ``evidence_tier``, so a scripted run is never mistaken for a live one;
* ``/simulator/status`` never starts Packet Tracer. It reports availability and
  the real reason, which is what lets the UI degrade honestly.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from .investigation import Auditor, Budget_, Investigator, Mode
from .models import AnswerStatus, NetworkModel
from .simulator import SimulatorRuntime
from .simulator.contracts import Budget

logger = logging.getLogger("trident.phase3")

router = APIRouter(prefix="/api/phase3", tags=["phase3"])

#: One runtime per process. Concurrency stays at one live session, the tested
#: configuration; a second request is told to wait rather than sharing mutable
#: simulator state.
_RUNTIME: SimulatorRuntime | None = None


def runtime() -> SimulatorRuntime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = SimulatorRuntime(budget=Budget(), max_sessions=1)
    return _RUNTIME


@router.get("/simulator/status")
async def simulator_status() -> dict[str, Any]:
    """Whether operational simulation is usable, and why. Never launches PT."""
    rt = runtime()
    available = rt.is_available()
    return {
        "available": available,
        "reason": rt.availability_reason(),
        "mode": "live" if available else "static-only",
        "note": (
            "Operational simulation is available."
            if available
            else (
                "Static analysis works normally. Operational simulation needs a "
                "registered Packet Tracer ExApp; see docs/HEADLESS_RUNTIME_FEASIBILITY.md."
            )
        ),
    }


@router.get("/modes")
async def modes() -> dict[str, Any]:
    return {
        "modes": [
            {
                "id": Mode.SMART.value,
                "label": "Smart Investigation",
                "default": True,
                "description": (
                    "Answers from static evidence first and only escalates testable "
                    "uncertainties to the simulator."
                ),
            },
            {
                "id": Mode.DOUBLE_CHECK.value,
                "label": "Double-Check",
                "default": False,
                "description": (
                    "Re-validates the whole network independently and reports exactly "
                    "what could and could not be checked."
                ),
            },
        ]
    }


def diagnose_payload(model: NetworkModel, mode: Mode = Mode.SMART) -> dict[str, Any]:
    """Static diagnosis as a phase-3 shaped payload.

    Separated from the HTTP layer so the pipeline can reuse it without a request
    object, and so tests can call it directly.
    """
    investigator = Investigator(model, mode=mode, runtime_available=False)
    return investigator.diagnose_network()


def audit_payload(model: NetworkModel, max_checks: int = 20) -> dict[str, Any]:
    auditor = Auditor(model, runtime_available=False, max_checks=max_checks)
    return auditor.audit().as_dict()


def investigate_payload(
    model: NetworkModel,
    questions: list[tuple[str, AnswerStatus, list[str]]],
    *,
    mode: Mode = Mode.SMART,
    runtime_available: bool = False,
    runtime_reason: str = "",
    budget: Budget_ | None = None,
) -> dict[str, Any]:
    investigator = Investigator(
        model,
        mode=mode,
        runtime_available=runtime_available,
        runtime_reason=runtime_reason,
        budget=budget or Budget_(),
    )
    return investigator.investigate(questions).as_dict()
