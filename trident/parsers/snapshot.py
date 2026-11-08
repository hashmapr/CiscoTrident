"""Snapshot selection shared by all three parser adapters.

A Packet Tracer activity file (``.pka``) may contain several ``<PACKETTRACER5>``
snapshot blocks: typically the starting network plus reference/answer networks
embedded in ``<COMPARISONS>``, ``<INITIALSETUP>`` or ``<CLEAN_ACTIVITY>``
wrappers. TRIDENT must analyse exactly one snapshot, or abstain.

Policy (identical for every adapter, so all engines inspect the same block):

1. Reference/answer wrappers are never read. A block nested inside
   ``<COMPARISONS>``, ``<INITIALSETUP>``, ``<CLEAN_ACTIVITY>`` or ``<ACTIVITY>``
   is excluded from selection regardless of its device count.
2. No snapshot block at all -> the whole document is the network (plain
   single-network ``.pkt``).
3. No candidate block contains devices -> abstain.
4. Exactly one populated candidate -> that block is the network.
5. Several populated candidates -> **evidence-based** selection, not device
   count:

   a. A block containing unresolved template placeholders
      (``[[pr3-rt_Display_name]]``) is a reference/simulation state produced by
      Packet Tracer's assessment engine, not the shipped network. Such blocks
      are demoted.
   b. If exactly one populated block is free of template placeholders, it is
      the shipped network and is selected.
   c. Otherwise, if all populated blocks are byte-identical they are duplicates
      of one snapshot and the first is used.
   d. Otherwise TRIDENT abstains. It never picks "the biggest" snapshot.

Rationale for (a): a real assessment file was observed where the shipped
network had fully resolved device names while the two later states carried
``[[..._Display_name]]`` placeholders and the graded (completed) configuration.
Device count alone is not evidence that a snapshot is the intended network.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

#: Wrappers that hold reference/answer networks. Content inside them is never
#: read by any extraction path.
REFERENCE_WRAPPERS = ("COMPARISONS", "INITIALSETUP", "CLEAN_ACTIVITY", "ACTIVITY")

_SNAPSHOT_BLOCK_RE = re.compile(r"<PACKETTRACER5>(.*?)</PACKETTRACER5>", re.DOTALL)
_DEVICE_BLOCK_RE = re.compile(r"<DEVICE>(.*?)</DEVICE>", re.DOTALL)
_DEVICE_OPEN_RE = re.compile(r"<DEVICE[ />]")
_LINE_RE = re.compile(r"<LINE>(.*?)</LINE>", re.DOTALL)
_NAME_RE = re.compile(r"<NAME[^>]*>(.*?)</NAME>", re.DOTALL)
_SAVE_REF_RE = re.compile(r"<SAVE_REF_ID>(.*?)</SAVE_REF_ID>", re.DOTALL)
#: Placeholder reference such as ``[[pr3-rt_Display_name]]``.
_PLACEHOLDER_RE = re.compile(r"\[\[([^\]]+)\]\]")
_STRING_VAR_RE = re.compile(r"<STRING_VAR>(.*?)</STRING_VAR>", re.DOTALL)
_STRING_POOL_RE = re.compile(r"<STRING_POOL>(.*?)</STRING_POOL>", re.DOTALL)

def _inner(tag: str, body: str) -> str | None:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", body, re.DOTALL)
    return m.group(1).strip() if m else None


def build_placeholder_map(xml_text: str) -> dict[str, str]:
    """Resolve Packet Tracer assessment placeholders to real display names.

    An activity ``.pka`` stores human names in ``<STRING_VAR>`` entries
    (``NAME`` -> ``VALUE``); the network blocks then reference them as
    ``[[pr3-rt_Display_name]]``. Without this map every device in such a file is
    named by a raw placeholder, which then leaks into answers.

    Falls back to ``<STRING_POOL>`` values when a variable's VALUE is empty.
    """
    pools: dict[str, list[str]] = {}
    for m in _STRING_POOL_RE.finditer(xml_text):
        body = m.group(1)
        name = _inner("NAME", body)
        if not name:
            continue
        values = [v.strip() for v in re.findall(r"<VALUES>(.*?)</VALUES>", body, re.DOTALL)]
        if values:
            pools[name] = values

    mapping: dict[str, str] = {}
    for m in _STRING_VAR_RE.finditer(xml_text):
        body = m.group(1)
        name = _inner("NAME", body)
        if not name:
            continue
        value = _inner("VALUE", body) or ""
        if not value:
            pool = _inner("POOL_NAME", body)
            if pool and pools.get(pool):
                value = pools[pool][0]
        if value:
            mapping[name] = value
    return mapping


def resolve_display_name(name: str, mapping: dict[str, str]) -> str:
    """Resolve one name, following nested placeholder references (bounded)."""
    current = name
    for _ in range(4):
        m = _PLACEHOLDER_RE.fullmatch(current.strip())
        if not m:
            break
        nxt = mapping.get(m.group(1).strip())
        if not nxt or nxt == current:
            break
        current = nxt
    return current


def resolve_placeholders(text: str, mapping: dict[str, str]) -> str:
    """Replace every resolvable ``[[...]]`` placeholder in a string."""
    if not text or "[[" not in text:
        return text

    def repl(m: re.Match[str]) -> str:
        return mapping.get(m.group(1).strip(), m.group(0))

    return _PLACEHOLDER_RE.sub(repl, text)
#: Packet Tracer assessment placeholders such as ``[[pr3-rt_Display_name]]``.
_TEMPLATE_TOKEN_RE = re.compile(r"\[\[[^\]]*\]\]")

_WRAPPER_RANGE_RES = tuple(
    (name, re.compile(rf"<{name}>(.*?)</{name}>", re.DOTALL)) for name in REFERENCE_WRAPPERS
)


@dataclass(frozen=True)
class SnapshotSelection:
    """The outcome of snapshot selection for one decoded document."""

    #: ``root`` (single-network file), ``blockN`` or ``abstain``.
    snapshot_id: str
    #: The text the adapter must parse, or ``None`` when abstaining.
    xml_text: str | None
    ambiguous: bool
    notes: list[str] = field(default_factory=list)
    #: True when selection could not be made safely.
    abstained: bool = False
    #: Rule that decided the outcome (root|single|identical|template-demoted|abstain).
    reason: str = ""
    #: Number of display-name placeholders found in the document's STRING_VAR table.
    placeholder_count: int = 0
    #: True when every placeholder inside the selected block could be resolved.
    placeholders_resolved: bool = True


def _template_tokens(body: str) -> int:
    return len(_TEMPLATE_TOKEN_RE.findall(body))


_RUNNING_RE = re.compile(r"<RUNNINGCONFIG>(.*?)</RUNNINGCONFIG>", re.DOTALL)
_LINK_TUPLE_RE = re.compile(r"<LINK>(.*?)</LINK>", re.DOTALL)
_PORT_RE = re.compile(r"<PORT>(.*?)</PORT>", re.DOTALL)
_FROM_RE = re.compile(r"<FROM>(.*?)</FROM>", re.DOTALL)
_TO_RE = re.compile(r"<TO>(.*?)</TO>", re.DOTALL)


def _semantic_fingerprint(body: str) -> str:
    """Fingerprint a snapshot's *extracted meaning*, ignoring volatile noise.

    Two snapshots that describe the same network differ only in things like
    ``MEM_ADDR`` / ``DEV_ADDR`` / save timestamps. Comparing raw bytes would call
    them different; comparing what TRIDENT would actually extract tells the truth.
    The fingerprint covers device names, each device's running-config lines, and
    the physical link tuples.
    """
    parts: list[str] = []
    ref_to_name: dict[str, str] = {}
    for block in _DEVICE_BLOCK_RE.findall(body):
        m = _NAME_RE.search(block)
        if not m:
            continue
        name = m.group(1).strip()
        ref_m = _SAVE_REF_RE.search(block)
        if ref_m and ref_m.group(1).strip():
            ref_to_name[ref_m.group(1).strip()] = name
        run = _RUNNING_RE.search(block)
        lines = _LINE_RE.findall(run.group(1)) if run else _LINE_RE.findall(block)
        parts.append(
            name
            + "\u0001"
            + "\u0002".join(" ".join(line.split()) for line in lines if line.strip())
        )
    # Only links whose endpoints resolve to known devices contribute, matching
    # what the walker actually emits. Unresolved <LINK> stanzas differ in
    # volatile addressing between otherwise identical snapshots.
    for link in _LINK_TUPLE_RE.findall(body):
        frm_m = _FROM_RE.search(link)
        to_m = _TO_RE.search(link)
        frm = ref_to_name.get(frm_m.group(1).strip()) if frm_m else None
        to = ref_to_name.get(to_m.group(1).strip()) if to_m else None
        ports = [p.strip() for p in _PORT_RE.findall(link)]
        if not frm or not to or len(ports) < 2:
            continue
        parts.append(f"link\u0001{frm}\u0001{ports[0]}\u0001{to}\u0001{ports[1]}")
    return hashlib.sha256("\u0000".join(sorted(parts)).encode()).hexdigest()


def select_snapshot(xml_text: str) -> SnapshotSelection:
    """Choose one snapshot block or abstain. Never merges snapshots.

    Display-name placeholders (``[[pr3-rt_Display_name]]``) are resolved from the
    document's ``<STRING_VAR>`` table before the block is returned, so adapters
    never see a raw placeholder as a device name.
    """
    mapping = build_placeholder_map(xml_text)

    def finish(
        snapshot_id: str,
        body: str | None,
        ambiguous: bool,
        notes: list[str],
        reason: str,
        abstained: bool = False,
    ) -> SnapshotSelection:
        text = body
        unresolved = 0
        if text is not None:
            unresolved = len(
                [p for p in _PLACEHOLDER_RE.findall(text) if p.strip() not in mapping]
            )
            text = resolve_placeholders(text, mapping)
            if unresolved:
                notes = [
                    *notes,
                    (
                        f"{unresolved} display-name placeholder(s) could not be "
                        "resolved; they remain visible as internal identifiers"
                    ),
                ]
        return SnapshotSelection(
            snapshot_id=snapshot_id,
            xml_text=text,
            ambiguous=ambiguous,
            notes=notes,
            abstained=abstained,
            reason=reason,
            placeholder_count=len(mapping),
            placeholders_resolved=unresolved == 0,
        )

    excluded: list[tuple[int, int, str]] = []
    for name, rx in _WRAPPER_RANGE_RES:
        for m in rx.finditer(xml_text):
            excluded.append((m.start(), m.end(), name))

    def _inside_reference(span: tuple[int, int]) -> str | None:
        for start, end, name in excluded:
            if span[0] >= start and span[1] <= end:
                return name
        return None

    blocks: list[tuple[int, str, str | None]] = []
    for m in _SNAPSHOT_BLOCK_RE.finditer(xml_text):
        wrapper = _inside_reference((m.start(), m.end()))
        blocks.append((m.start(), m.group(1), wrapper))

    if not blocks:
        return finish(
            "root",
            xml_text,
            False,
            ["no <PACKETTRACER5> block; treating the whole document as the network"],
            "root",
        )

    candidates: list[tuple[int, str]] = []
    notes: list[str] = []
    for index, (_, body, wrapper) in enumerate(blocks):
        if wrapper is not None:
            notes.append(f"block{index} skipped: nested inside <{wrapper}> (never read)")
            continue
        candidates.append((index, body))

    counts = {index: len(_DEVICE_OPEN_RE.findall(body)) for index, body in candidates}
    non_empty = [(index, body) for index, body in candidates if counts[index] > 0]

    if not non_empty:
        return finish(
            "abstain",
            None,
            False,
            ["all snapshot blocks are empty; no network snapshot to analyse"],
            "abstain",
            abstained=True,
        )

    if len(non_empty) == 1:
        index, body = non_empty[0]
        return finish(f"block{index}", body, False, notes, "single")

    bodies = {body for _, body in non_empty}
    if len(bodies) == 1:
        index = non_empty[0][0]
        return finish(
            f"block{index}",
            body,
            False,
            notes + ["multiple identical snapshot blocks; using the first"],
            "identical",
        )

    # Evidence-based discrimination. Two independent signals, strongest first:
    # (a) majority agreement: several snapshots that extract to the same network
    #     are one network captured more than once; a dissenting snapshot is a
    #     later reference/answer state.
    # (b) unresolvable placeholders: a name that cannot be resolved from
    #     <STRING_VAR> marks an unresolved assessment state.
    fingerprints = {index: _semantic_fingerprint(body) for index, body in non_empty}
    groups: dict[str, list[int]] = {}
    for index, fp in fingerprints.items():
        groups.setdefault(fp, []).append(index)
    majority = [members for members in groups.values() if len(members) >= 2]
    if len(majority) == 1 and len(groups) > 1:
        members = majority[0]
        chosen = min(members)
        body = dict(non_empty)[chosen]
        dissent = sorted(i for i, _ in non_empty if fingerprints[i] != fingerprints[chosen])
        notes.append(
            f"selected block{chosen}: block(s) {sorted(members)} extract to an identical "
            f"network (majority agreement); block(s) {dissent} describe a different state "
            "and were not merged"
        )
        return finish(f"block{chosen}", body, False, notes, "majority-agreement")

    # (b) A block whose placeholders cannot be resolved is an assessment state.
    #     This applies whether or not the document carries a STRING_VAR table: a
    #     placeholder with no resolution is unresolved either way.
    resolvable = [
        (index, body)
        for index, body in non_empty
        if all(p.strip() in mapping for p in _PLACEHOLDER_RE.findall(body))
    ]
    if len(resolvable) == 1 and len(resolvable) < len(non_empty):
        index, body = resolvable[0]
        demoted = [i for i, _ in non_empty if i != index]
        notes.append(
            f"selected block{index}: its display-name placeholders all resolve; "
            f"block(s) {demoted} contain unresolvable placeholders and are treated as "
            "unresolved assessment states"
        )
        return finish(f"block{index}", body, False, notes, "template-demoted")

    # (c) A block with no placeholders at all is the shipped network when every
    #     other populated block depends on unresolvable placeholders.
    plain = [
        (index, body) for index, body in non_empty if not _PLACEHOLDER_RE.findall(body)
    ]
    if len(plain) == 1 and len(plain) < len(non_empty):
        index, body = plain[0]
        notes.append(
            f"selected block{index}: it has resolved device names while the other "
            "snapshot block(s) carry placeholders that cannot be resolved"
        )
        return finish(f"block{index}", body, False, notes, "resolved-names")

    counts_summary = [counts[i] for i, _ in candidates]
    return finish(
        "abstain",
        None,
        True,
        [
            *notes,
            (
                "cannot safely identify the intended snapshot "
                f"(device counts {counts_summary}, "
                f"{len(resolvable)} block(s) with fully resolvable names); "
                "abstaining instead of selecting by size or merging reference networks"
            ),
        ],
        "abstain",
        abstained=True,
    )


def device_names_in(xml_text: str) -> list[str]:
    """Device names declared inside a snapshot text, in document order."""
    names: list[str] = []
    for block in _DEVICE_BLOCK_RE.findall(xml_text):
        m = _NAME_RE.search(block)
        if not m:
            continue
        name = m.group(1).strip()
        if name and name not in names:
            names.append(name)
    return names
