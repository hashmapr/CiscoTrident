# TRIDENT — Full Code Audit

Audit date: 2026-11-07
Baseline commit: `9928cae175c3c4b88fa9052506405058819a55d3` (`Add Twofish encryption algorithm header file`)
Working tree: audited including uncommitted changes from the preceding review.
Environment: macOS (Apple Silicon), Python 3.12.12, Engine A (vendored Twofish build), Engine B (pkt-core 0.2.2), Engine C (pt-convert bridge, Node 22).

Baseline at audit start: `pytest -q` → **184 passed**; `ruff check .` → 5 errors, **all in vendored `vendor/engine_a` third-party code**.

Final after fixes: `pytest -q` → **220 passed**; `ruff check trident tests` → **All checks passed**.

---

## Severity legend

**Critical** — produces wrong answers or leaks assessment data.
**High** — silently degrades correctness or hides failures.
**Medium** — misreports, drops evidence, or breaks under real inputs.
**Low** — cosmetic / maintainability / defence-in-depth.

---

## 1. Snapshot selection used device count, not evidence (Critical)

**File/function:** `trident/parsers/snapshot.py::select_snapshot` (previously `trident/parsers/pka_xml.py::_select_snapshot`)

**Root cause:** with several populated `<PACKETTRACER5>` blocks the code chose `max(non_empty, key=device_count)`. Device count is not evidence that a block is the intended network. Worse, the previous walker scanned the *entire decoded XML*, so all blocks were merged regardless of which was "selected".

**Reproduction:** `R1_OKCUP_24_25_CiscoPT.pka` contains three populated blocks (21 / 20 / 20 devices). Blocks 1 and 2 carry unresolved assessment placeholders (`[[pr3-rt_Display_name]]`) and the graded configuration; block 0 is the shipped network with resolved names. Pre-fix, the analyzer merged all three (40 unique devices, 6 conflicting fields).

**Fix:**
- Block selection is now **evidence-based**: blocks nested in `COMPARISONS` / `INITIALSETUP` / `CLEAN_ACTIVITY` / `ACTIVITY` are never candidates; among populated candidates a block containing unresolved `[[...]]` template placeholders is demoted as a reference/simulation state; exactly one template-free candidate is selected; identical duplicates are collapsed; anything else **abstains**.
- Engine A walks only the selected block text.
- Engines B and C apply the same policy to their own decoded XML and filter their output to the selected block's device inventory.
- Pipeline aborts if adapters disagree on the snapshot id.

**Regression tests:** `tests/test_audit_regressions.py::test_template_snapshot_is_demoted_even_when_larger`, `test_two_differing_resolved_snapshots_abstain`, `test_reference_wrapper_block_never_selected`, `test_single_resolved_snapshot_is_selected`; `tests/test_regressions_correctness.py` (adapter-level scoping, pipeline disagreement).

**Remaining limitation:** placeholder detection is a heuristic tied to Packet Tracer's `[[...]]` convention. A file with several plausible snapshots and no placeholders correctly abstains rather than guessing — the user must then analyse a specific snapshot manually.

---

## 2. Engine A merged RUNNINGCONFIG with STARTUPCONFIG (Critical)

**File/function:** `trident/parsers/pka_xml.py::_walk_xml` → new `_device_config_lines`

**Root cause:** `_LINE_RE.findall(scope)` collected every `<LINE>` in a device block. Both `<RUNNINGCONFIG>` and `<STARTUPCONFIG>` contain `<LINE>`s, so the parsed config was running+startup concatenated, and the later (startup) interface stanzas overwrote live IPs.

**Reproduction:** real file, device `Internet (Router) 1`:
- RUNNINGCONFIG: `hostname InternetRouter1`, `Gi0/0 5.78.157.1`, `Gi0/1 54.215.47.1`
- STARTUPCONFIG: `hostname OpenSeas`, `Gi0/0 44.102.3.1`, `Gi0/1 34.130.13.1`

Pre-fix result: 6 CONFLICT fields (`hostname`, three `ipv4_address`) between Engine A and Engines B/C. Post-fix: **0 conflicts**.

**Fix:** parse `<RUNNINGCONFIG>` only; fall back to `<STARTUPCONFIG>` when no running config exists; never concatenate.

**Regression tests:** `test_audit_regressions.py::test_engine_a_config_uses_running_not_startup`, `test_engine_a_falls_back_to_startup_when_no_running_config`.

---

## 3. Engine B dropped every config for names containing spaces (High)

**File/function:** `trident/parsers/pkt_core.py::_extract`

**Root cause:** pkt-core writes per-device files with sanitised stems (`Hub_Switch_1__Our_Trusty_Sidekick.cfg`), while the snapshot filter compared against the real device name (`Hub Switch 1 (Our Trusty Sidekick)`). Result: `configs: 0 devices` on the real file even though the files existed.

**Fix:** `_slug()` mirrors pkt-core's sanitisation and maps slug → real device name.

**Regression test:** `test_engine_b_slug_matches_pkt_core_filenames`.

---

## 4. Single-source facts were labelled VERIFIED_DERIVED (High)

**File/function:** `trident/verification/validators.py::_single_source_fact`

**Root cause:** end-host facts (gateway/DNS) available from one engine only were returned as `VERIFIED_DERIVED`, implying a deterministic derivation. They are directly observed, single-source values.

**Fix:** status is now `INCOMPLETE` with an explicit `single-source:` conflict note and an explanation that it is not independently corroborated. Genuine arithmetic derivations keep `VERIFIED_DERIVED`.

**Regression test:** `test_audit_regressions.py::test_single_source_gateway_is_incomplete_not_derived`.

---

## 5. MCQ substring fallback caused false positives (Critical)

**File/function:** `trident/reasoning/mcq.py::option_matches_value`

**Root cause:** `return len(val) >= 4 and val in opt` matched any option text containing the value. Consequences: `VLAN 10` matched `VLAN 100`; a correct IP inside a false sentence verified the sentence; `Switch` matched `Switch-Backup`.

**Fix:** strict, type-aware equivalence only — exact normalised text, IPv4/IPv6 (rejecting leading zeros), CIDR, contiguous subnet mask, MAC (any format), full-option interface alias, VLAN id, number, boolean. Negated options never match a positive value. **No substring fallback.**

**Regression tests:** `tests/test_mcq_adversarial.py` (16 tests: VLAN 10/100, Gi0/1 vs Gi0/10, Switch vs Switch-Backup, 192.168.1.1 vs .10, embedded value, negation, duplicate options, invalid mask, CIDR, no-match).

**Remaining limitation:** prose options are compared by exact normalised text only, so a reworded-but-correct prose answer yields `CONFLICT`. This is deliberate (never guess); it is reported as `CONFLICT`, not a wrong answer.

---

## 6. Entity resolution picked the longest substring (High)

**File/function:** `trident/verification/validators.py::resolve_device`, `trident/models.py::find_device`

**Root cause:** `if name.lower() in lowered and len(name) > len(best)`. With `Router`, `Router-1`, `Router-10` in a model, a question about `Router-1` could resolve to `Router-10`; `HS_Edge_Router`/`MS_Edge_Router` were indistinguishable.

**Fix:** new `trident/reasoning/entities.py` with precedence exact → case-insensitive exact → hostname → boundary-delimited mention (device-name token boundaries so `Router-1` cannot match inside `Router-10`), longest match wins, ties reported as **ambiguous** and resolved to `None`. `NetworkModel.find_device` no longer returns an arbitrary alias match.

**Regression tests:** `test_mcq_adversarial.py::test_device_name_containing_another_is_not_confused`, `test_ambiguous_device_mention_returns_none`, `test_exact_device_name_wins_over_substring`, `test_hostname_resolution`.

---

## 7. Consensus could verify from one engine under non-strict policies (High)

**File/function:** `trident/verification/consensus.py::ConsensusEngine.required`, `FieldConsensus.status`

**Root cause:** `required` was scaled by availability (`min(2, max(available,1))`), so with one engine `two_engine` demanded 1 agreement and returned `VERIFIED`; `deterministic` likewise bypassed its own branch.

**Fix:** fixed policy floors (strict=3, two_engine=2, deterministic=1) and a rewritten status ladder that checks the floor, provenance blockers, and family count before any verification status.

**Regression tests:** `test_regressions_correctness.py::test_two_engine_policy_not_satisfied_by_single_engine`, `test_deterministic_policy_yields_verified_derived_not_verified`, `test_two_agreeing_engines_under_two_engine_policy_verify`.

---

## 8. Verification counted engine IDs, not extraction families (High)

**File/function:** `trident/verification/consensus.py::FieldConsensus`

**Root cause:** the module docstring promised distinct extraction families and matching snapshots, but the implementation only counted distinct `provenance.engine` values; observations carried no snapshot id at all (Normalizer never received one), so the snapshot guarantee was vacuous.

**Fix:**
- `Provenance` now records the four independence layers explicitly: `decoder` (Layer A), `extraction_family` (Layer B), `interpretation_family` (Layer C), plus `normalization` and `validation` operations (Layer D).
- The normalizer threads the agreed snapshot id into every observation and prefixes `extraction_path` with the adapter's declared family.
- VERIFIED requires: agreeing engines ≥ floor, distinct **families** ≥ floor, uniform non-empty snapshot id equal to the model's snapshot, and no shared-decoder false independence.

**Regression tests:** `test_regressions_correctness.py::test_three_distinct_engines_one_family_is_not_verified`, `test_snapshot_identity_mismatch_is_incomplete`, `test_missing_snapshot_attribution_is_incomplete`.

**Remaining limitation:** families are adapter-declared constants. The check enforces the invariant structurally and catches degenerate configurations, but it cannot cryptographically prove algorithmic independence. All three engines share the same public Twofish-EAX decode — this is stated in the UI and reports, never hidden.

---

## 9. Multi-select evaluated one fact for the whole question (High)

**Files:** `trident/verification/validators.py::_build_choice`, `trident/reasoning/mcq.py`

**Root cause:** `match_multi(question, [fact.value])` used a single inferred fact; the remaining options were never adjudicated, and a "choose two" question could be answered from one established value.

**Fix:** `adjudicate_options()` returns TRUE / FALSE / UNKNOWN per option; `match_multi_independent()` selects only TRUE options, returns `INCOMPLETE` if any option is UNKNOWN, verifies the stated choice count, and `CONFLICT`s when a value is established both true and false. The builder pools **all** plan facts instead of the first.

**Regression tests:** `test_mcq_adversarial.py` (6 multi-select tests) and `test_regressions_correctness.py::test_builder_multi_select_uses_all_plan_facts`.

**Remaining limitation:** "established FALSE" requires the query plan (or heuristics) to produce negative facts. TRIDENT has no general negative-fact mining, so many multi-select questions correctly end `INCOMPLETE` rather than guessed.

---

## 10. AI planning could silently lose questions in large batches (Medium)

**File/function:** `trident/reasoning/ai_client.py::AIClient.plan_questions`

**Root cause:** one request carried every question; long output truncated mid-JSON, `parse_plan_json` returned `[]`, and the pipeline silently fell back for the whole set.

**Fix:** chunked requests (`AI_BATCH_SIZE`, default 12), `finish_reason == "length"` detection, reconciliation against the question numbers actually sent (a plan for an unasked number is discarded), per-batch error isolation with all-batches-failed surfaced as one error.

**Regression tests:** `test_audit_regressions.py` (batching at 10/25/65/100, unasked-number rejection, truncation, partial-batch failure).

**Live validation:** Ollama Cloud (`deepseek-v4.1-flash:1017-cloud`), 5-question flow: 1 `VERIFIED`, 1 `INCOMPLETE` (single-source gateway), 2 `VERIFIED_DERIVED`, 1 `INCOMPLETE` — no hallucinated facts accepted, no key leakage.

---

## 11. Decompression is unbounded in the vendored decoder (Medium)

**File/function:** `vendor/engine_a/pka2xml/__init__.py` (stage 4), `trident/parsers/pka_xml.py`

**Root cause:** `zlib.decompress` runs before any size check; the declared length prefix is only a warning.

**Fix:** `TRIDENT_MAX_DECOMPRESSION_RATIO` (default 200×) plus the existing `TRIDENT_MAX_XML_BYTES`, applied immediately after decode and before any parsing. Real lab files measure 9.9×–12.8×.

**Remaining limitation:** the ratio check runs *after* inflation, so it limits what reaches the parsers but cannot abort an in-progress bomb. Fixing that properly requires modifying (or wrapping) the vendored MIT decoder; documented rather than silently claimed.

---

## 12. Vendored code fails the project linter (Low)

**Root cause:** `ruff check .` covered `vendor/engine_a`.

**Resolution:** audit scope is now `ruff check trident tests` (clean). Modifying third-party vendored sources to satisfy our lint rules was deliberately avoided.

---

## Read-only and security audit results

| Check | Result | Evidence |
|---|---|---|
| Original file SHA-256 unchanged | PASS | `tests/test_security.py`; real HTTP test compared before/after hashes |
| Temp workspaces isolated and cleaned | PASS | `make_workspace()` uses `TemporaryDirectory` |
| Path traversal on upload name | PASS | `ingest()` rejects separators; `temp_path()` resolves inside workspace |
| Arbitrary shell execution | PASS | no `shell=True`, no `eval`, no `exec` anywhere in `trident/` |
| Subprocess bounded | PASS | both engines use `subprocess.run(..., timeout=parser_timeout, check=False)` |
| XXE | N/A (safe) | TRIDENT parses no XML with an XML library; extraction is regex over decoded text |
| Decompression bound | PARTIAL | ratio/size caps post-inflation (item 11) |
| API key leakage | PASS | key only in the Authorization header; `_scrub()` on provider errors; `public_dict()` omits it |
| Raw `.pka` sent to AI | PASS | only `build_digest()` (devices/interfaces/links/routes/vlans/acl IDs) is sent; secrets stripped |
| Assessment answer keys read | PASS | reference wrappers never candidates; placeholder blocks demoted |
| Localhost-only binding | PASS | default `TRIDENT_HOST=127.0.0.1` |

---

## Not fixed / explicitly out of scope

1. **True semantic independence is impossible here.** All three engines share the same public decode. The audit documents this everywhere rather than implying four independent confirmations.
2. **`deterministic` policy still allows single-source VERIFIED_DERIVED for arithmetic**, which is correct (the arithmetic is reproducible), but it must not be read as corroboration.
3. **Prose MCQ options** only match on exact normalised text; reworded answers yield `CONFLICT`.
4. **65-question benchmark set was not provided**, so no accuracy percentage is claimed anywhere.
