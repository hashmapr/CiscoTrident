"""Canonical entity resolution for device names and interfaces.

The previous resolver used "longest device name that appears as a substring",
which silently resolves ``Router`` and ``Router-1`` to whichever is longer and
maps ``Router-1`` text onto ``Router-10``. This module replaces it with
deterministic, boundary-aware matching and explicit ambiguity reporting.

Resolution order (first level that matches decides):

1. Exact case-sensitive name.
2. Exact case-insensitive name.
3. Exact hostname (case-insensitive).
4. Boundary-delimited mention in free text, preferring the longest name; distinct
   names tying at the same length are reported as ambiguous.

Anything that matches more than one entity at the same precedence level is
reported as ambiguous instead of being resolved arbitrarily.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Characters that may continue a device name token. A match is only accepted
#: when the characters immediately outside the match are not in this set, so
#: ``Router-1`` cannot match inside ``Router-10`` and ``SW1`` cannot match inside
#: ``SW10``.
_NAME_CHARS = r"A-Za-z0-9_\-."


@dataclass(frozen=True)
class EntityResolution:
    """Outcome of resolving a device mention."""

    name: str | None
    #: Which rule matched: exact | exact-ci | hostname | mention | none
    rule: str = "none"
    #: All candidates that matched at the winning precedence level (sorted).
    candidates: list[str] = field(default_factory=list)

    @property
    def ambiguous(self) -> bool:
        return len(self.candidates) > 1

    @property
    def resolved(self) -> bool:
        return self.name is not None and not self.ambiguous


def _bounded(name: str, text: str) -> bool:
    """True when ``name`` appears in ``text`` delimited by non-name characters."""
    rx = re.compile(rf"(?<![{_NAME_CHARS}]){re.escape(name)}(?![{_NAME_CHARS}])", re.IGNORECASE)
    return rx.search(text) is not None


def resolve_device_name(
    names: list[str], text: str, hostnames: dict[str, str] | None = None
) -> EntityResolution:
    """Resolve a device mention in free text against known device names.

    ``hostnames`` maps hostname -> device name.
    """
    if not text or not text.strip():
        return EntityResolution(None, "none")
    query = text.strip()

    # 1. exact name
    for name in names:
        if name == query:
            return EntityResolution(name, "exact", [name])

    # 2. case-insensitive exact name
    ci = sorted({n for n in names if n.lower() == query.lower()})
    if len(ci) == 1:
        return EntityResolution(ci[0], "exact-ci", ci)
    if len(ci) > 1:
        return EntityResolution(None, "exact-ci", ci)

    # 3. exact hostname
    if hostnames:
        hits = sorted({dev for host, dev in hostnames.items() if host and host.lower() == query.lower()})
        if len(hits) == 1:
            return EntityResolution(hits[0], "hostname", hits)
        if len(hits) > 1:
            return EntityResolution(None, "hostname", hits)

    # 4. boundary-delimited mention anywhere in the text. Longest name wins;
    #    a tie at the same length is ambiguous.
    best_len = -1
    best: list[str] = []
    for name in names:
        if not name:
            continue
        if not _bounded(name, text):
            continue
        length = len(name)
        if length > best_len:
            best_len, best = length, [name]
        elif length == best_len:
            best.append(name)
    if best:
        best = sorted(set(best))
        if len(best) == 1:
            return EntityResolution(best[0], "mention", best)
        return EntityResolution(None, "mention", best)

    # 5. hostname mention
    if hostnames:
        hits: list[tuple[int, str]] = []
        for host, dev in hostnames.items():
            if host and _bounded(host, text):
                hits.append((len(host), dev))
        if hits:
            top = max(length for length, _ in hits)
            best_hosts = sorted({dev for length, dev in hits if length == top})
            if len(best_hosts) == 1:
                return EntityResolution(best_hosts[0], "hostname", best_hosts)
            return EntityResolution(None, "hostname", best_hosts)

    return EntityResolution(None, "none")
