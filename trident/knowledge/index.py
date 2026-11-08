"""Offline Cisco IOS knowledge index.

This module is reference documentation: it answers "what does this command
print", "what does this protocol do" and "how is this fault diagnosed". It
never inspects a network snapshot and never states that a particular device is
configured correctly or incorrectly.

Separation rule
---------------
``KnowledgeIndex`` consumes only :class:`KnowledgeEntry` objects and ``str``
arguments. This package imports nothing from ``trident.models``, has no method
that accepts a ``NetworkModel`` and exposes no verification surface, so no
lookup here can be used to assert a fact about a specific device or snapshot.
Every result is a pure function of the shipped corpus and the query text.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

_TOKEN_RE = re.compile(r"[a-z0-9]+")

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "by",
        "do",
        "does",
        "for",
        "from",
        "how",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "the",
        "to",
        "vs",
        "was",
        "what",
        "when",
        "where",
        "which",
        "why",
        "with",
    }
)


class KnowledgeKind(StrEnum):
    """What kind of reference material an entry holds."""

    COMMAND = "command"
    PROTOCOL = "protocol"
    TROUBLESHOOTING = "troubleshooting"
    CONCEPT = "concept"


@dataclass(frozen=True)
class KnowledgeEntry:
    """One curated piece of Cisco IOS reference material.

    ``related`` holds ids of other entries in the same corpus; the constructor
    of :class:`KnowledgeIndex` rejects a corpus with dangling references.
    ``ios_commands`` lists commands that demonstrate or verify the entry and is
    never a claim about a device's configuration.
    """

    id: str
    kind: KnowledgeKind
    title: str
    summary: str
    detail: str
    related: tuple[str, ...] = ()
    ios_commands: tuple[str, ...] = ()
    source: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("knowledge entry id must be a non-empty string")
        if not isinstance(self.kind, KnowledgeKind):
            object.__setattr__(self, "kind", KnowledgeKind(self.kind))
        for name in ("title", "summary", "detail"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"knowledge entry {self.id!r} has an empty {name}")
        object.__setattr__(self, "related", tuple(self.related))
        object.__setattr__(self, "ios_commands", tuple(self.ios_commands))
        if not isinstance(self.source, str):
            raise TypeError(f"knowledge entry {self.id!r} has a non-string source")


@dataclass(frozen=True)
class _Doc:
    """Pre-tokenised view of one entry, built once per index."""

    entry: KnowledgeEntry
    title_phrase: str
    title_tokens: frozenset[str]
    command_phrases: tuple[str, ...]
    command_tokens: frozenset[str]
    summary_phrase: str
    summary_tokens: frozenset[str]
    detail_phrase: str
    detail_tokens: frozenset[str]
    id_tokens: frozenset[str]


_KIND_ORDER = {
    KnowledgeKind.COMMAND: 0,
    KnowledgeKind.TROUBLESHOOTING: 1,
    KnowledgeKind.PROTOCOL: 2,
    KnowledgeKind.CONCEPT: 3,
}


def _phrase(text: str) -> str:
    """Lowercase word sequence used for exact and substring comparisons."""
    return " ".join(_TOKEN_RE.findall(text.lower()))


def _tokens(text: str) -> list[str]:
    """Content tokens: lowercase alphanumerics, stopwords and lone digits removed."""
    out: list[str] = []
    for token in _TOKEN_RE.findall(text.lower()):
        if token in _STOPWORDS:
            continue
        if token.isdigit() and len(token) < 2:
            continue
        out.append(token)
    return out


def _build_doc(entry: KnowledgeEntry) -> _Doc:
    return _Doc(
        entry=entry,
        title_phrase=_phrase(entry.title),
        title_tokens=frozenset(_tokens(entry.title)),
        command_phrases=tuple(_phrase(cmd) for cmd in entry.ios_commands),
        command_tokens=frozenset(_tokens(" ".join(entry.ios_commands))),
        summary_phrase=_phrase(entry.summary),
        summary_tokens=frozenset(_tokens(entry.summary)),
        detail_phrase=_phrase(entry.detail),
        detail_tokens=frozenset(_tokens(entry.detail)),
        id_tokens=frozenset(_tokens(entry.id)),
    )


def _prefix_hit(token: str, tokens: frozenset[str], min_length: int) -> bool:
    return len(token) >= min_length and any(other.startswith(token) for other in tokens)


def _score_doc(doc: _Doc, phrase: str, tokens: list[str], entry_id_phrase: str) -> int | None:
    """Relevance score for one entry, or ``None`` when it must not be returned.

    ``phrase`` is the content-token sequence of the query (stopwords removed),
    so a natural-language question such as "what is a native vlan" is compared
    as ``"native vlan"``.
    """
    entry = doc.entry
    score = 0
    exact = False

    if any(phrase == cmd for cmd in doc.command_phrases):
        score += 120
        exact = True
    elif any(cmd.startswith(phrase) for cmd in doc.command_phrases):
        score += 90
    elif any(phrase in cmd for cmd in doc.command_phrases):
        score += 65

    if phrase == doc.title_phrase:
        score += 110
        exact = True
    elif doc.title_phrase.startswith(phrase):
        score += 70
    elif phrase in doc.title_phrase:
        score += 55

    if entry_id_phrase == entry.id:
        score += 80
        exact = True
    elif len(entry_id_phrase) >= 3 and entry_id_phrase in entry.id:
        score += 20

    if len(phrase) >= 4 and phrase in doc.summary_phrase:
        score += 25
    if len(phrase) >= 4 and phrase in doc.detail_phrase:
        score += 10

    matched = 0
    for token in tokens:
        hit = 0
        if token in doc.title_tokens:
            hit = 12
        elif _prefix_hit(token, doc.title_tokens, 4):
            hit = 8
        if token in doc.id_tokens:
            hit = max(hit, 7)
        if token in doc.command_tokens:
            hit = max(hit, 10)
        if not hit:
            if token in doc.summary_tokens:
                hit = 5
            elif _prefix_hit(token, doc.summary_tokens, 4):
                hit = 4
        if not hit:
            if token in doc.detail_tokens:
                hit = 3
            elif _prefix_hit(token, doc.detail_tokens, 5):
                hit = 2
        if hit:
            matched += 1
            score += hit

    if matched == 0 and not exact:
        return None
    if len(tokens) > 1 and matched < 2 and not exact:
        return None
    if matched == len(tokens):
        score += 15
    return score


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string; the knowledge index is offline documentation "
            f"and never accepts a network model (got {type(value).__name__})"
        )


class KnowledgeIndex:
    """Read-only search index over a fixed corpus of knowledge entries.

    The index is a plain in-memory structure: no file, socket, subprocess or
    model is touched after construction. Construction validates the corpus, so
    an index that exists is internally consistent.
    """

    def __init__(self, entries: Iterable[KnowledgeEntry]) -> None:
        by_id: dict[str, KnowledgeEntry] = {}
        for entry in entries:
            if not isinstance(entry, KnowledgeEntry):
                raise TypeError(
                    "KnowledgeIndex accepts KnowledgeEntry objects only, "
                    f"got {type(entry).__name__}"
                )
            if entry.id in by_id:
                raise ValueError(f"duplicate knowledge entry id {entry.id!r}")
            by_id[entry.id] = entry

        dangling = sorted(
            (entry.id, related)
            for entry in by_id.values()
            for related in entry.related
            if related not in by_id
        )
        if dangling:
            pairs = ", ".join(f"{src}->{dst}" for src, dst in dangling)
            raise ValueError(f"unresolved related ids in knowledge corpus: {pairs}")

        self._by_id: dict[str, KnowledgeEntry] = dict(sorted(by_id.items()))
        self._docs: tuple[_Doc, ...] = tuple(
            _build_doc(entry) for entry in self._by_id.values()
        )

    @property
    def entries(self) -> tuple[KnowledgeEntry, ...]:
        """Every entry in the corpus, ordered by id."""
        return tuple(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)

    def search(self, query: str, limit: int = 5) -> list[KnowledgeEntry]:
        """Rank entries against free-text ``query``.

        Scoring is deterministic: exact command, title and id matches dominate,
        then per-token matches weighted by field (title > command > id >
        summary > detail). A multi-token query must match at least two tokens
        (or hit an exact command/title/id) to be returned, which keeps a query
        like ``"show zzzq"`` from matching every ``show`` command. An empty or
        punctuation-only query returns ``[]``.
        """
        _require_text("query", query)
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError(f"limit must be an int, got {type(limit).__name__}")
        if limit <= 0:
            return []

        raw_phrase = _phrase(query)
        tokens = _tokens(raw_phrase)
        if not raw_phrase or not tokens:
            return []

        # Compare against entries using content tokens only, so a natural-language
        # question ("what is a native vlan") is matched as "native vlan".
        phrase = " ".join(tokens)

        scored: list[tuple[int, int, str, KnowledgeEntry]] = []
        for doc in self._docs:
            score = _score_doc(doc, phrase, tokens, raw_phrase)
            if score is not None:
                scored.append((-score, _KIND_ORDER[doc.entry.kind], doc.entry.id, doc.entry))
        scored.sort(key=lambda row: (row[0], row[1], row[2]))
        return [row[3] for row in scored[:limit]]

    def by_command(self, command_prefix: str) -> list[KnowledgeEntry]:
        """Entries whose ``ios_commands`` start with ``command_prefix``.

        The prefix is normalised to lowercase words, so ``"show ip"`` matches
        every ``show ip ...`` command and ``"SHOW  vlan"`` matches ``show vlan
        brief``. No IOS abbreviation expansion is applied. An unknown prefix
        returns ``[]``.
        """
        _require_text("command_prefix", command_prefix)
        prefix = _phrase(command_prefix)
        if not prefix:
            return []

        hits: list[tuple[str, str, KnowledgeEntry]] = []
        for doc in self._docs:
            for command in doc.command_phrases:
                if command.startswith(prefix):
                    hits.append((command, doc.entry.id, doc.entry))
                    break
        hits.sort(key=lambda row: (row[0], row[1]))
        return [row[2] for row in hits]

    def explain(self, entry_id: str) -> str:
        """Render one entry as plain text for a terminal or a chat reply.

        Raises ``KeyError`` for an unknown id. The rendered text always ends
        with a reminder that the entry is documentation only.
        """
        _require_text("entry_id", entry_id)
        entry = self._by_id.get(entry_id)
        if entry is None:
            entry = self._by_id.get(entry_id.strip().lower())
        if entry is None:
            raise KeyError(f"unknown knowledge entry id {entry_id!r}")

        lines = [
            f"{entry.title} [{entry.kind.value}]",
            f"id: {entry.id}",
            "",
            entry.summary,
            "",
            entry.detail,
            "",
            "IOS commands:",
        ]
        if entry.ios_commands:
            lines.extend(f"  {command}" for command in entry.ios_commands)
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append("Related:")
        if entry.related:
            lines.extend(f"  {related} - {self._by_id[related].title}" for related in entry.related)
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append(f"Source: {entry.source}")
        lines.append("")
        lines.append(
            "Documentation only: this entry describes Cisco IOS behaviour and says "
            "nothing about any particular device."
        )
        return "\n".join(lines)


def default_index() -> KnowledgeIndex:
    """Build an index over the shipped corpus.

    A fresh index is constructed on each call: the corpus is small and building
    it is cheap, and no shared mutable state can leak between callers.
    """
    from .corpus import ENTRIES

    return KnowledgeIndex(ENTRIES)
