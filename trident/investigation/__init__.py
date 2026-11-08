"""Autonomous investigation: gaps, hypotheses, experiments, stopping.

Public surface:

* :class:`Investigator` — runs the loop for one network and a question set.
* :func:`should_escalate` — the deterministic policy that decides whether the
  simulator is worth starting at all.
* :class:`Mode` — ``SMART`` (default) or ``DOUBLE_CHECK``.

Read :mod:`trident.investigation.escalation` for the policy rules and
:mod:`trident.investigation.hypotheses` for experiment selection.
"""

from .doublecheck import Auditor, AuditReport, Check, Coverage, Verdict
from .engine import (
    Budget_,
    InvestigationReport,
    Investigator,
    QuestionOutcome,
    StopReason,
    TimelineEntry,
)
from .escalation import (
    EscalationDecision,
    Mode,
    Testability,
    classify_testability,
    expected_information_gain,
    should_escalate,
)
from .hypotheses import (
    Experiment,
    Hypothesis,
    Mutation,
    experiments_for,
    select_experiment,
)
from .whatif import Candidate, Outcome, WhatIfResult, evaluate

__all__ = [
    "AuditReport",
    "Auditor",
    "Budget_",
    "Candidate",
    "Check",
    "Coverage",
    "EscalationDecision",
    "Experiment",
    "Hypothesis",
    "InvestigationReport",
    "Investigator",
    "Mode",
    "Mutation",
    "Outcome",
    "QuestionOutcome",
    "StopReason",
    "Testability",
    "TimelineEntry",
    "Verdict",
    "WhatIfResult",
    "classify_testability",
    "evaluate",
    "expected_information_gain",
    "experiments_for",
    "select_experiment",
    "should_escalate",
]
