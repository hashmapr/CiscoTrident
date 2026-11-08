"""Offline Cisco IOS knowledge layer for TRIDENT.

Reference material only: nothing in this package inspects a network snapshot.
"""

from .index import KnowledgeEntry, KnowledgeIndex, KnowledgeKind, default_index

__all__ = ["KnowledgeEntry", "KnowledgeIndex", "KnowledgeKind", "default_index"]
