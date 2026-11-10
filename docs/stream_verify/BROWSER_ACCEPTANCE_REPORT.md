# BROWSER ACCEPTANCE REPORT

Real-browser validation of STREAM + VERIFY. Captured 2026-11-10 against a
running TRIDENT instance at `http://127.0.0.1:8000`.

Baseline commit at start: `c5ee19e`, working tree clean.

---

## 1. Verdict

**Two real defects were found and fixed.** The reported baseline was accurate
about the backend, but "streaming implemented" was not true of the running
product: the endpoint computed the whole analysis and then replayed finished
events. A user would have seen nothing until everything was done.

| Claim | Verified? |
|---|---|
| Frontend renders in a real browser | **yes** |
| `/api/analyze/stream` exists | yes |
| Streaming is genuinely incremental | **was NO — now yes** |
| `/api/analyze/verify` exists | yes |
| Buffered fallback works | yes |
| Three questions on three lines | **was NO — now yes** |

---

## 2. Defect 1 — questions on separate lines merged into one

### Symptom
Pasting three questions, one per line, produced **one** answer that addressed
all three.

### Cause
`parse_questions` splits blocks only on *numbered* lines (`1.`, `2)`). Input
without numbering became a single block:

```
What is the hostname of R1?
What IP address does R1 GigabitEthernet0/0 have?
Which device is directly connected to R1 GigabitEthernet0/0?
```
→ 1 question, stem = all three lines concatenated.

### Fix
An explicit unnumbered-list rule, deliberately narrow: apply it only when there
is **no** numbering anywhere and **every** non-empty line ends with `?`. A
multi-line question with options is untouched.

### Evidence
```
bare lines         -> 3 question(s)
numbered           -> 2 question(s)
multiline+options  -> 1 question(s)   (3 options preserved)
mixed              -> 1 question(s)
```

---

## 3. Defect 2 — streaming was a replay, not a stream

### Symptom
The UI showed no answers until everything finished. In the browser, the results
list jumped from 0 to 3 cards in a single frame.

### Cause
The endpoint awaited the complete analysis, then emitted events for the finished
result:

```python
outcome = await analyze(...)          # everything happens here
async def frames():
    for result in outcome.response.results:
        yield streamer.answer(result).to_sse()   # then this replays it
```

Every test passed because the *events* were correct. They were simply not
streamed.

### Fix
The pipeline now takes optional `on_stage` / `on_answer` hooks and calls them as
the work happens. The endpoint runs the analysis as a task, pushes events into a
queue, and yields from it as they arrive.

### Evidence — wall-clock timestamps from `curl -N`

```
18:11:01.032  STAGE  parsing
18:11:01.752  STAGE  consensus
18:11:01.774  STAGE  resolving
18:11:01.792  ANSWER Q1  R1
18:11:01.808  ANSWER Q2  192.168.1.1
18:11:01.824  ANSWER Q3  SW1
18:11:01.842  COMPLETE
```

Parsing is emitted 720 ms before consensus, and each answer is a separate frame.

### Evidence — browser read boundaries

Instrumented `fetch().body.getReader()` inside the page:

```json
{
  "readCount": 3,
  "arrivals": [
    {"ms": 10,   "bytes": 45},
    {"ms": 1263, "bytes": 625},
    {"ms": 1263, "bytes": 528}
  ],
  "kinds": ["STAGE","STAGE","STAGE","ANSWER","ANSWER","ANSWER","COMPLETE"]
}
```

Three separate network reads. The first (45 bytes) is the `parsing` stage,
delivered **10 ms** after the request while the analysis was still running.

---

## 4. What the browser actually did

Real Chrome against a real server, real file upload, real button click.

### Page loaded

All three engines reported available:

```
cisco-pka-to-xml (engine_a)   AVAILABLE   ready (libtwofish: libtwofish.dylib)
PKT-CORE (engine_b)           AVAILABLE   pkt-core 0.2.2
pt-convert (engine_c)         AVAILABLE   ready (node at .../node)
```

The simulator panel correctly reported:

> Operational simulation unavailable: live simulator is disabled. Set
> `TRIDENT_ALLOW_LIVE_SIMULATOR=1` to allow Packet Tracer to be started.
> Static analysis works normally.

### Analysis run

Three questions, one per line, `sample_lab.pkt`:

| # | Question | Badge | Answer |
|---|---|---|---|
| Q1 | What is the hostname of R1? | VERIFIED | **R1** |
| Q2 | What IP address does R1 Gi0/0 have? | VERIFIED | **192.168.1.1** |
| Q3 | Which device is connected to R1 Gi0/0? | VERIFIED_DERIVED | **SW1** |

Status line: `Done in 5.2s — 3 question(s): 2 verified, 1 verified_derived.`

Progress was observed advancing in the browser: `Analyzing… parsing` at 52 ms,
`Analyzing… consensus` at 932 ms, then completion.

---

## 5. Why the DOM still jumps 0 → 3

After the fix, events arrive separately (proven above) but the three cards
appear in one frame. This is arithmetic, not a defect: local static analysis
resolves all three questions in ~16 ms once parsing completes, which is faster
than one browser frame. The answers *are* appended individually; the browser
paints once.

The practical benefit is on slow files, where parsing dominates: the user now
sees `parsing` immediately instead of a frozen screen for the whole decode.
On the 30 MB fixture that is a difference of roughly two minutes.

---

## 6. Verification endpoint

`/api/analyze/verify` returns the analysis plus an independent re-derivation:

```json
{"CONFIRMED": 1, "DISAGREES": 0, "NOT_INDEPENDENTLY_CHECKABLE": 0,
 "UNRESOLVED": 0, "total": 1}
```

No answer that reached VERIFIED was contradicted by the independent read.

---

## 7. Tests added

`tests/test_streaming_progressive.py` — 11 tests:

- bare lines, numbered lists, multi-line-with-options, trailing prose
- hooks fire in pipeline order, and answers are emitted one at a time
- analysis without hooks is byte-identical to the hooked path
- the live endpoint emits a STAGE frame before the analysis finishes
- exactly one ANSWER per question, numbered 1..3, COMPLETE last
- an empty question set is a 400, before streaming begins

---

## 8. Limitations

1. **No automated browser test in CI.** Validation used a live Chrome session
   driven manually. `tests/test_web_ui.py` checks the served HTML and that
   `app.js` references the streaming path, but does not execute JavaScript.
2. **Streaming benefit is latency-shaped, not throughput-shaped.** On small
   files all answers arrive within one frame. The gain is on large files and on
   the stage feedback during a long decode.
3. **The ghost runtime was not exercised in this sprint.** Simulator status was
   correctly reported as unavailable, since `TRIDENT_ALLOW_LIVE_SIMULATOR` was
   not set for the application process. That is the intended degraded behaviour.

---

## 9. Commands to reproduce

```bash
# start the application
.venv/bin/python -m trident            # http://127.0.0.1:8000

# backend streaming, with wall-clock timestamps
curl -s -N -X POST http://127.0.0.1:8000/api/analyze/stream \
  -F "file=@tests/fixtures/sample_lab.pkt" \
  -F "questions=What is the hostname of R1?
What IP address does R1 GigabitEthernet0/0 have?" \
  -F "use_ai=false"

# targeted tests
.venv/bin/python -m pytest tests/test_streaming_progressive.py \
  tests/test_stream_verify.py -q
```
