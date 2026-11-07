# TRIDENT Architecture

## Pipeline

```
PKA FILE
  │  ingestion.ingest()      extension + size + SHA-256, in-memory copy
  ▼
Read-Only File Loader  ──────  private temp workspace (auto-deleted)
  │
  ├── EngineAAdapter   cisco-pka-to-xml  (in-process, MIT)
  ├── EngineBAdapter   PKT-CORE          (subprocess CLI + public API, GPL-3.0)
  └── EngineCAdapter   pt-convert        (Node subprocess, All Rights Reserved)
  ▼
AdapterResult[]  (devices, configs, links, end-host facts, raw, report)
  ▼
Normalizer.build()  ──►  NetworkModel + Observation[]
  ▼
ConsensusEngine  ──►  FieldConsensus per (entity, field)
  ▼
AIClient.plan_questions()  (optional)  ──►  QueryPlan[]
  ▼
AnswerBuilder.build()  ──►  Deterministic execution + option matching
  ▼
AnalysisResponse  ──►  Web UI / JSON / text
```

## Why the layering is strict

**Parsers never decide truth.** They return observations with provenance. A parser that
is unavailable returns `UNAVAILABLE` and contributes nothing.

**Normalisation is canonicalisation, not judgement.** It merges observations and makes
MACs and interface aliases comparable. It does not pick winners.

**Consensus decides.** Only `verification/consensus.py` assigns `VERIFIED`. It counts
*distinct engines* per canonical value, so a duplicated observation from one engine cannot
inflate the vote.

**Validation is the authority for answers.** `verification/validators.py` executes queries
and caps every option match at the status of the fact supporting it. An option match can
never be `VERIFIED` if the underlying fact is `INCOMPLETE`.

**AI only plans.** The model returns `QueryPlan` objects (`op`, `device`, `interface`, …).
Unknown operations are filtered out. A plan referencing a nonexistent device yields no
fact. The model's own recollection (`comparison`) is never used as a value.

## Consensus policy

`strict` (default): `VERIFIED` requires 3 agreeing engines.

```
agreeing_engines(value) >= required  ->  VERIFIED
len(distinct_values) > 1             ->  CONFLICT
otherwise                            ->  INCOMPLETE
no observations                      ->  NOT_AVAILABLE
```

`required` is 3 under strict even if only 2 engines are available — so two-engine output
is honestly `INCOMPLETE`. `two_engine` lowers it to 2; `deterministic` additionally allows
single-source derivations to be `VERIFIED_DERIVED`.

## Derived answers

Subnet arithmetic, topology traversal and VLAN member expansion are computed from the
merged model, not asked of each parser. They are `VERIFIED_DERIVED` with an explicit trace
(`network_address(ip, mask) = value`), and the trace is attached as evidence.

## Provenance model

Every `Observation` records:

| Field | Meaning |
|---|---|
| `engine` | `engine_a` \| `engine_b` \| `engine_c` |
| `extraction_path` | `ios-config`, `raw-xml-walk`, `endhost-xml`, `links`, … |
| `source_path` | XML path or engine output location |
| `snapshot` | snapshot identifier |
| `warnings` | extraction warnings |
| `crypto_shared` | always true: container decode is the shared public algorithm |

`crypto_shared` exists so no consumer can mistake 3/3 for three independent decodes.

## Snapshot isolation

A `.pka` can contain several `<PACKETTRACER5>` blocks (initial/current/reference).
`pka_xml._select_snapshot`:

1. counts `<DEVICE>` occurrences per block;
2. if more than one block is non-empty, sets `snapshot_ambiguous=True` and analyses only
   the richest block, recording the index;
3. never merges blocks;
4. never reads `<ACTIVITY>`, `<COMPARISONS>` or `<CLEAN_ACTIVITY>`.

## Failure handling

| Failure | Behaviour |
|---|---|
| Adapter raises | `ERROR` report, empty contribution, other engines continue |
| Adapter times out | `TIMEOUT` report, other engines continue |
| Engine not installed | `UNAVAILABLE` with actionable message |
| File undecodable | all adapters `ERROR`; response says so; no invented devices |
| Question unparseable | per-question `NOT_AVAILABLE` / `ERROR`, batch continues |
| AI provider error | warning added, deterministic path continues |

## Threat model notes

- The uploaded bytes are treated as untrusted. XML is never parsed by a live external
  entity-capable parser in Engine A's path (regex walk over decoded text).
- `defusedxml` is a declared dependency for any future XML parsing.
- Subprocess calls use argument lists, never `shell=True`.
- Filenames are discarded before any disk write.
- The AI prompt receives a redacted digest: no credentials, no `enable secret`, no full
  configs, no file bytes.
