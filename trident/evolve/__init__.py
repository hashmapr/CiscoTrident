"""TRIDENT EVOLVE: evidence-backed failure and regression registry.

A place to record what TRIDENT got wrong, why, and the smallest input that
demonstrates it, so future planning can consult real mistakes instead of
rediscovering them.

See :mod:`trident.evolve.registry` for the trust rules. The short version: a
lesson is only usable when its corrected outcome was established by live
simulation or by consensus across extraction families, and when a reproducible
counterexample is attached. Nothing in this package changes production behaviour
on its own.
"""

from .registry import (
    DEFAULT_REGISTRY,
    EvidenceStrength,
    Lesson,
    RecordState,
    Registry,
    RootCause,
    identity_of,
)

__all__ = [
    "DEFAULT_REGISTRY",
    "EvidenceStrength",
    "Lesson",
    "RecordState",
    "Registry",
    "RootCause",
    "identity_of",
]
