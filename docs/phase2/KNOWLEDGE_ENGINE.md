# Knowledge and Training Engine (Phase 2)

An offline, deterministic reference layer for Cisco IOS commands, protocols, concepts
and troubleshooting procedures. It answers "what does this mean" — never "what is
this network".

## Non-goals

The knowledge layer is **documentation only**. It is architecturally incapable of
stating that a device, interface, VLAN, route or ACL in a snapshot is correct.

* No import of `trident.models`, no `NetworkModel` anywhere in the package.
* No method with a `model`, `snapshot`, `device` or `config` parameter.
* No method named or shaped like `assert`, `verify`, `check`, `validate` or `diagnose`.
* No file, socket, subprocess or LLM call. Every result is a pure function of the
  shipped corpus plus the query string.

The `test_knowledge.py` separation tests enforce all four points structurally, so a
future change that tries to point the index at a snapshot fails CI.

## Public API

```python
from trident.knowledge import (
    KnowledgeEntry, KnowledgeIndex, KnowledgeKind, default_index,
)

class KnowledgeKind(StrEnum):
    COMMAND = "command"
    PROTOCOL = "protocol"
    TROUBLESHOOTING = "troubleshooting"
    CONCEPT = "concept"

@dataclass(frozen=True)
class KnowledgeEntry:
    id: str
    kind: KnowledgeKind
    title: str
    summary: str
    detail: str
    related: tuple[str, ...] = ()
    ios_commands: tuple[str, ...] = ()
    source: str = ""

class KnowledgeIndex:
    def __init__(self, entries: Iterable[KnowledgeEntry]) -> None: ...
    @property
    def entries(self) -> tuple[KnowledgeEntry, ...]: ...
    def __len__(self) -> int: ...
    def search(self, query: str, limit: int = 5) -> list[KnowledgeEntry]: ...
    def by_command(self, command_prefix: str) -> list[KnowledgeEntry]: ...
    def explain(self, entry_id: str) -> str: ...

def default_index() -> KnowledgeIndex
```

There is deliberately no `lookup_device`, no `check_topology`, no
`validate_config` and no `answer_question`.

## Files

| File | Purpose |
| --- | --- |
| `trident/knowledge/__init__.py` | Public exports only |
| `trident/knowledge/index.py` | `KnowledgeKind`, `KnowledgeEntry`, `KnowledgeIndex`, `default_index` |
| `trident/knowledge/corpus.py` | 46 hand-curated entries |
| `tests/test_phase2/test_knowledge.py` | 51 tests including the separation proof |
| `docs/phase2/KNOWLEDGE_ENGINE.md` | This document |

## Corpus

46 entries: 12 command references, 12 concepts, 12 troubleshooting procedures and
10 protocol notes. Coverage includes every item required by the brief:

**Commands** — `show ip interface brief`, `show running-config`, `show vlan brief`,
`show interfaces trunk`, `show ip route`, `show spanning-tree`,
`show etherchannel summary`, `show access-lists`, `show ip ospf neighbor`,
`show ip protocols`, plus `show interfaces status` and `show mac address-table`.

**Concepts** — VLAN vs access port vs trunk port, native VLAN, SVI,
`ip default-gateway` vs a default route, OSPF neighbours vs network statements,
ACL direction, NAT overload, DHCP relay, administrative distance, static vs dynamic
routing, broadcast domains, ARP.

**Troubleshooting** — interface down, VLAN mismatch, trunk not forming, native VLAN
mismatch, missing route, ACL blocking traffic, DHCP not assigned, OSPF adjacency
not forming, duplex/speed mismatch, EtherChannel not bundling, NAT not translating,
unexpected STP root.

**Protocols** — OSPF, STP, VTP, 802.1Q, DHCP, NAT, ARP, LACP, ACLs, static routing.

Wording convention throughout: entries describe what IOS *does* or *prints*
("a trunk stays up when …"), never what a particular device *is* configured as.

### Invariants enforced at construction

`KnowledgeIndex(entries)` fails fast, so an index that exists is internally
consistent:

| Check | Exception |
| --- | --- |
| every `related` id exists in the corpus | `ValueError: unresolved related ids …` |
| ids are unique | `ValueError: duplicate knowledge entry id …` |
| each element is a `KnowledgeEntry` | `TypeError` |
| `title` / `summary` / `detail` are non-empty | `ValueError` |

## Search

Scoring is deterministic and tiered. A single query pass computes an integer score
per entry, then sorts by `(-score, kind_rank, id)`. Kind rank only breaks exact ties,
so equal scores resolve as command → troubleshooting → protocol → concept, which is
usually the order a reader wants.

| Signal | Weight |
| --- | --- |
| exact `ios_commands` match | +120 |
| command prefix / substring | +90 / +65 |
| exact / prefix / substring title match | +110 / +70 / +55 |
| exact id / id substring | +80 / +20 |
| exact summary / detail substring (≥4 chars) | +25 / +10 |
| token in title / id / command / summary / detail | +12 / +7 / +10 / +5 / +3 |
| all query tokens matched | +15 |

Token matching uses prefix comparison for tokens ≥4 characters, so `neighbour`
matches `neighbor` and `spanning` matches `spanning-tree`. Tokens are lowercased
alphanumeric runs with English stopwords removed, and a query must match at least
two tokens (or hit an exact command, title or id) to be returned. That second rule
stops `show zzzq` from matching every `show` command.

```python
ix = default_index()
ix.search("native vlan")          # concept-native-vlan, ts-native-vlan-mismatch, …
ix.search("what is a native vlan")# same ranking: stopwords are dropped
ix.search("show ip", limit=3)     # command entries first
ix.search("")                     # []
ix.search("!!!")                  # []
```

Guarantees: empty/whitespace/punctuation query → `[]`; `limit <= 0` → `[]`; unknown
content → `[]`; repeat calls return identical lists.

## Command lookup

`by_command(prefix)` normalises the prefix to lowercase words and returns every entry
with at least one `ios_commands` value starting with it, sorted by command then id.
No IOS abbreviation expansion is applied — `sh ip ro` does not resolve.

```python
ix.by_command("show ip")      # show ip interface brief, show ip route, show ip ospf neighbor, …
ix.by_command("show vlan")    # cmd-show-vlan-brief
ix.by_command("show nonexistent")  # []
```

## Rendering

`explain(entry_id)` returns plain text with title, kind, id, summary, detail, IOS
commands, related entries with their titles, source and a closing
"Documentation only" line. Unknown ids raise `KeyError`.

## Wiring it in

The layer is standalone and safe to expose to an interface. A CLI or HTTP handler may
call `search`, `by_command` and `explain` freely; the answers are reference text that
describes IOS behaviour and contain no snapshot-derived facts. When a user asks
"is VLAN 10 correct on SW1", the knowledge layer can explain what a VLAN is and what
`show vlan brief` prints, but the verdict must come from the reasoning/verification
pipeline operating on the actual model — never from here.

## Verification

```bash
.venv/bin/python -m pytest tests/test_phase2/test_knowledge.py -q
.venv/bin/python -m ruff check trident/knowledge tests/test_phase2
```
