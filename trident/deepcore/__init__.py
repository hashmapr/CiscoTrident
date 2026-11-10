"""DeepCore: deterministic network reasoning.

Predicts forwarding behaviour from parsed configuration and topology, with no
LLM involved. Every conclusion cites its evidence, unusable steps are reported as
``UNKNOWN`` rather than guessed, and predictions are kept in a separate evidence
kind from simulator observations so they can never be mistaken for one another.

See :mod:`trident.deepcore.path` for the engine.
"""

from .path import DeepCore, EvidenceKind, PathPrediction, PathStep, Step

__all__ = [
    "DeepCore",
    "EvidenceKind",
    "PathPrediction",
    "PathStep",
    "Step",
]
