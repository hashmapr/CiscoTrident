# Engine C and strict consensus — status

**Status:** Engine C is **UNAVAILABLE** in this environment.
**Consensus impact:** none beyond the honest one — strict results that need a third
extraction family stay `INCOMPLETE`. Nothing was relaxed, stubbed, or faked.

- Branch: `cyberpatriot/readiness`
- Scope of this note: `trident/parsers/pt_convert.py`, `trident/parsers/engine_c_bridge.mjs`,
  `trident/verification/consensus.py`, `tests/test_consensus_three_engine.py`
- Date: 2026-11-14

## What Engine C is

Engine C is TRIDENT's adapter around **pt-convert**, a third-party TypeScript tool
that decodes Packet Tracer containers and simplifies the decoded XML into device,
link, and config JSON. TRIDENT does **not** reimplement pt-convert and does **not**
vendor or copy its source:

- `trident/parsers/pt_convert.py` is the Python adapter. It probes availability,
  runs the bridge as a subprocess, applies the shared snapshot-selection policy to
  the decoded XML, and emits observations with `extraction_family="pt-convert"`.
- `trident/parsers/engine_c_bridge.mjs` is TRIDENT's own glue. It imports
  `decryptPacket()` from `<checkout>/src/lib/packet-crypto.ts` and
  `simplifyXmlToJson()` from `<checkout>/src/lib/xml-simplifier.ts`.

Engine C is the third **extraction** family. It is not a third independent
container decoder: all three engines use the same public Twofish-EAX format, and
consensus records `crypto_shared=True`. Independence is claimed only at the
extraction step.

## Why it is unavailable

Three independent reasons, all verified in this environment:

1. **The checkout has no `src/lib` implementation files.** The directory named by
   `TRIDENT_PT_CONVERT_DIR` contains `src/`, `public/`, `docs/`, and `node_modules/`,
   but `src/lib/` is empty. `src/lib/packet-crypto.ts` and
   `src/lib/xml-simplifier.ts` do not exist, so the bridge cannot import them and
   the adapter refuses to run.
2. **It is not a git repository.** `git -C "$TRIDENT_PT_CONVERT_DIR" rev-parse
   --is-inside-work-tree` fails with *"not a git repository"*. There is no history to
   restore the missing modules from.
3. **pt-convert is All-Rights-Reserved — a policy constraint, not an artifact
   observed here.** An independent audit noted there is no LICENSE/COPYING file
   and no `license` field in the checkout's `package.json`, so this reason cannot
   be *verified from the files present*. It is TRIDENT's operating policy (and
   the upstream project's stated terms) that the source must never be vendored,
   copied, reimplemented or downloaded. Recording it as a policy rather than as
   an observed fact is the accurate framing.

   Only reasons 1 and 2 are verified from artifacts. Either one alone is
   sufficient to make Engine C unavailable here.

The dependencies *are* present (`node_modules/` contains `pako`, `twofish`,
`fast-xml-parser`), which is why the probe fails on the missing source files rather
than on dependencies. Node.js is installed (v25.8.2 at the time of writing).

## Exact evidence

Probe against the configured checkout:

```text
(False, 'pt-convert checkout missing src/lib/packet-crypto.ts')
```

Running the adapter through the normal template method (probe first, then execute):

```text
UNAVAILABLE | pt-convert checkout missing src/lib/packet-crypto.ts | obs: 0
```

That is `AdapterResult.report.state == ParserState.UNAVAILABLE` with **zero
observations**. An unavailable engine contributes no votes; it cannot be counted as
agreement.

## What strict consensus does with two families

The strict policy requires **three distinct extraction families**:

```python
# trident/verification/consensus.py
if self.policy == "strict":
    threshold = 3
...
if len(agreeing_engines) < threshold:
    return AnswerStatus.INCOMPLETE
...
families = {_extraction_family(o) for o in agreeing}
if len(families) < threshold:
    return AnswerStatus.INCOMPLETE
```

With Engine C absent, the audited benchmark questions have `engine_a`
(`raw-xml-walk`) and `engine_b` (`pkt-core`) only. The result is the shape already
visible in `tests/test_okcup_regressions.py`, e.g. Q54:

```text
answer='OpenSeas' status=INCOMPLETE consensus.agree=2 available=2 required=3 policy='strict'
```

The value is correct; the status is honestly `INCOMPLETE` because a third distinct
family is missing. It is **not** `VERIFIED`.

### Properties verified by `tests/test_consensus_three_engine.py`

| Property | Test | Result |
| --- | --- | --- |
| Verification counts distinct extraction families, not engine IDs | `test_three_engines_two_families_are_incomplete` | pass |
| Three distinct families verify | `test_three_distinct_families_are_verified` | pass |
| A single engine repeating the same value counts once | `test_same_engine_same_value_twice_counts_once` | pass |
| A duplicate from one family cannot inflate agreement | `test_duplicate_does_not_inflate_a_two_family_agreement`, `test_duplicate_from_a_third_engine_does_not_create_a_new_family` | pass |
| `strict` keeps `required=3` with only two families | `test_strict_required_stays_three_with_only_two_families` | pass |
| `VERIFIED` only at or above `required` | `test_verified_only_at_or_above_required` (1/2/3 families) | pass |
| Two families that disagree are a conflict | `test_two_families_that_disagree_are_a_conflict` | pass |
| A missing family in provenance blocks verification | `test_missing_family_in_provenance_blocks_verification` | pass |
| An absent engine is `UNAVAILABLE` with no observations | `test_absent_engine_is_unavailable_and_contributes_nothing` | pass |
| An absent engine never promotes `INCOMPLETE` to `VERIFIED` | `test_absent_engine_never_promotes_incomplete_to_verified` | pass |

### Note on engines vs. families

`ConsensusSummary.agree` and `.available` count **engine IDs** (the validators phrase
them as "engines agree"). Verification additionally requires **distinct extraction
families**, so three engines that share two families do not verify. The engine gate
is a conservative anti-padding guard: one engine cannot claim two family labels and
satisfy strict with only two engines (`test_two_engines_cannot_pad_the_family_count`).
No false `VERIFIED` was found: every shortfall returns `INCOMPLETE`.

## What would restore Engine C

All of the following, none of which TRIDENT may manufacture itself:

1. A **legitimate checkout** of pt-convert at a revision that contains
   `src/lib/packet-crypto.ts` and `src/lib/xml-simplifier.ts`.
2. That checkout's dependencies installed (`npm install` there), providing `pako`,
   `twofish`, and `fast-xml-parser` under `node_modules/`.
3. Node.js 18+ on `PATH` (or `TRIDENT_NODE`).
4. `TRIDENT_PT_CONVERT_DIR` pointing at that checkout.

When those hold, `EngineCAdapter.probe()` returns `(True, "ready (node at ...)")`
and Engine C contributes a third family (`pt-convert`), allowing strict
`VERIFIED` where three families genuinely agree.

## Reproduction commands

From the repository root:

```bash
source .venv/bin/activate

# 1. Probe Engine C (reads TRIDENT_PT_CONVERT_DIR from .env or the environment).
python - <<'PY'
from pathlib import Path
from trident.config import Settings
from trident.parsers.pt_convert import EngineCAdapter

adapter = EngineCAdapter(Settings())
print(adapter.probe())

result = adapter.run(Path("input.pkt"), Path("."))
print(result.report.state.value, "|", result.report.message, "| observations:", len(result.observations))
PY

# 2. Show why it is unavailable.
echo "$TRIDENT_PT_CONVERT_DIR"
ls "$TRIDENT_PT_CONVERT_DIR/src/lib"          # expected: empty / missing the two modules
ls "$TRIDENT_PT_CONVERT_DIR/node_modules" | grep -E '^(pako|twofish|fast-xml-parser)$'
git -C "$TRIDENT_PT_CONVERT_DIR" rev-parse --is-inside-work-tree   # expected: fatal: not a git repository

# 3. Consensus invariants (this file's tests plus the existing consensus/parser tests).
python -m pytest tests/test_consensus_three_engine.py tests/test_consensus.py tests/test_parsers.py -q

# 4. Lint the changed Python files.
ruff check tests/test_consensus_three_engine.py trident/verification/consensus.py trident/parsers/pt_convert.py
```

Expected probe output in this environment:

```text
(False, 'pt-convert checkout missing src/lib/packet-crypto.ts')
```

Expected test output:

```text
44 passed, 1 skipped
```

(The skip is the existing real-file Engine C test, gated on `engine_available("engine_c")`.)

## Confirmation: strict consensus is preserved, not relaxed

- The policy default remains `strict`; `required` is still **3**.
- No fake decrypt or stub module was added, and no package was installed.
- Engine C contributes zero observations while unavailable, so it cannot be counted
  as a third vote.
- All shortfalls (one family, two families, duplicate observations, missing family,
  absent engine) return `INCOMPLETE`; conflicts remain `CONFLICT`.
- The only production change from this investigation is test and documentation
  coverage. `trident/verification/consensus.py` required no fix.

## Blocker statement

> Engine C is UNAVAILABLE: `TRIDENT_PT_CONVERT_DIR` points at a pt-convert checkout
> whose `src/lib/` directory does not contain `packet-crypto.ts` or
> `xml-simplifier.ts`; the checkout is not a git repository, and pt-convert is
> All-Rights-Reserved, so TRIDENT cannot vendor or reconstruct those modules. The
> probe returns `(False, 'pt-convert checkout missing src/lib/packet-crypto.ts')`
> and `run()` returns `UNAVAILABLE` with zero observations. Strict consensus
> therefore remains `required=3` with only `engine_a` and `engine_b`
> (two distinct families), so affected answers stay `INCOMPLETE` instead of being
> promoted to `VERIFIED`.
