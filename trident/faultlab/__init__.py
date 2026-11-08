"""Fault-injection practice laboratory for TRIDENT.

The lab manufactures synthetic networks that contain **known** defects, and
grades a diagnostic engine on whether it reports the true root cause. It exists
so that a diagnostics engine can be measured instead of trusted.

Two rules make the laboratory honest:

1. **The answer key is not on the wire.** A solver receives ``Scenario.model``
   only. ``Scenario.faults`` is the manifest and is never encoded into the
   model: no attribute, warning, snapshot note or provenance string names the
   injected defect.
2. **Precision is scored as strictly as recall.** Every reported kind that is
   not in the manifest lowers the score, so an engine cannot win by shouting
   every possibility.

The scenarios are synthetic. They are built in memory from
:func:`baseline_lab`; they are not Packet Tracer ``.pkt``/``.pka`` files, not
captures of real devices and not parser fixtures.

Quick start::

    from trident.faultlab import baseline_lab, grade, scenarios

    for scenario in scenarios():
        model = scenario.model                  # hand only this to the analyser
        report = my_engine.diagnose(model)      # list[dict] with a "kind" field
        result = grade(scenario, report)
        print(scenario.name, result.score, result.exact_match)
"""

from .baseline import BASELINE_SNAPSHOT, baseline_lab
from .grade import grade
from .inject import InjectionError, inject, inject_many
from .scenarios import scenarios
from .types import Fault, FaultKind, Grade, Scenario

__all__ = [
    "BASELINE_SNAPSHOT",
    "Fault",
    "FaultKind",
    "Grade",
    "InjectionError",
    "Scenario",
    "baseline_lab",
    "grade",
    "inject",
    "inject_many",
    "scenarios",
]
