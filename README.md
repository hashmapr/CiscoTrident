# TRIDENT

**Local, read-only Cisco Packet Tracer analysis with three-engine consensus and AI question interpretation.**

TRIDENT accepts a `.pka`/`.pkt` file and a block of questions, extracts the network
configuration using three independent parsing engines, reconciles their findings with a
strict consensus policy, and answers the questions **only** from verified facts.

The guiding rule is **factual correctness over answer coverage**. When TRIDENT cannot
establish an answer from evidence, it says so (`INCOMPLETE`, `CONFLICT`,
`NOT_AVAILABLE`) and tells you what to check manually. It never guesses.

---

## What it actually does

```
.pka/.pkt ──► read-only loader ──► 3 parser adapters ──► normaliser ──► unified model
                                                                          │
                                                     consensus verifier ◄─┘
                                                            │
   questions ──► question parser ──► AI query plan (optional) ──► deterministic validator
                                                            │
                                                        results page
```

- Parses the file **once** per analysis and reuses the model for every question.
- Extracts devices, interfaces, IPs/masks, gateways, DNS, VLANs, trunks, routes, ACLs,
  IOS versions and physical links — each with provenance.
- Applies a strict consensus policy by default: `VERIFIED` needs **3 agreeing engines**.
- Subnet arithmetic is computed deterministically and labelled `VERIFIED_DERIVED`.

---

## Quick start (macOS, including Apple Silicon)

Requires **Python 3.11+** and a C compiler (`cc`/`clang`, already present with Xcode CLT).

```bash
git clone <this repo> trident
cd trident

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
pip install -r requirements-dev.txt     # optional: test tooling

# Build Engine A's native Twofish library (one-time)
sh vendor/engine_a/build.sh

cp .env.example .env
# edit .env if you want AI interpretation (optional)

python -m trident
```

Open **http://127.0.0.1:8000**.

Without the C compiler, Engine A reports `UNAVAILABLE` and TRIDENT continues with the
other engines — it will not pretend 3/3 agreement happened.

---

## Configuration

All settings are environment variables, normally set in `.env`:

| Variable | Default | Purpose |
|---|---|---|
| `TRIDENT_HOST` | `127.0.0.1` | Bind address (keep on localhost) |
| `TRIDENT_PORT` | `8000` | Bind port |
| `AI_API_KEY` | *(empty)* | OpenAI-compatible key. Empty = deterministic mode only |
| `AI_BASE_URL` | `https://api.openai.com/v1` | Provider endpoint |
| `AI_MODEL` | *(empty)* | Model name |
| `AI_TEMPERATURE` | `0` | Sampling temperature |
| `TRIDENT_MAX_FILE_BYTES` | `67108864` | Upload size cap |
| `TRIDENT_MAX_QUESTIONS` | `500` | Batch size cap |
| `TRIDENT_PARSER_TIMEOUT` | `90` | Per-adapter timeout (seconds) |
| `TRIDENT_CONSENSUS_POLICY` | `strict` | `strict` \| `two_engine` \| `deterministic` |
| `TRIDENT_PT_CONVERT_DIR` | *(empty)* | Path to a pt-convert checkout (Engine C) |

### Enabling Engine C (pt-convert)

pt-convert is **All Rights Reserved**. TRIDENT never copies its source; it runs your
checkout as an external Node process. To enable it:

```bash
git clone https://github.com/semicolonmystery/pt-convert ~/pt-convert
cd ~/pt-convert
npm install pako twofish fast-xml-parser     # only the runtime libs are needed
export TRIDENT_PT_CONVERT_DIR=~/pt-convert
```

Only do this if you have permission to run that code.

---

## Question formats

Paste questions separated by blank lines. Numbering and option letters are preserved.

```text
1. What is the IP address of R1 GigabitEthernet0/0?
A. 192.168.1.1
B. 192.168.2.1

2. Which two statements are true? (Choose two.)
A. ...
B. ...

3. True or false: PC-A has a default gateway.
True
False

4. What is the network address of 192.168.1.10 255.255.255.0?

5. Explain how OSPF elects a DR.
```

---

## Result statuses

| Status | Meaning |
|---|---|
| `VERIFIED` | 3 independent engines extracted the same normalised value; validation passed |
| `VERIFIED_DERIVED` | Deterministic arithmetic/traversal from verified inputs, with a trace |
| `INCOMPLETE` | Fewer than the required engines agreed, or a field was missing |
| `CONFLICT` | Engines disagree, or no offered MCQ option matches the data |
| `NOT_AVAILABLE` | No trustworthy source establishes the fact |
| `ERROR` | A parser or the pipeline failed for this item |

**`VERIFIED` does not mean "three fully independent confirmations."** All three engines
decrypt with the same public container algorithm. Independence is claimed only for the
extraction/parsing layer, and the UI always shows `shared container decode` alongside the
agreement count.

---

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Web interface |
| `GET` | `/api/health` | Health + adapter availability |
| `GET` | `/api/parsers` | Parser capability matrix |
| `POST` | `/api/analyze` | `multipart/form-data`: `file`, `questions`, `use_ai` |
| `GET` | `/api/docs` | OpenAPI UI (FastAPI) |

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -F "file=@lab.pka" \
  -F "questions=1. What is the IP of R1 Gi0/0?" \
  -F "use_ai=false"
```

---

## Security posture

- Binds to `127.0.0.1` by default; no telemetry, no analytics, no accounts.
- The **raw file is never sent to the AI provider** — only a compact, redacted digest.
- The API key stays server-side in memory and is scrubbed from error messages.
- Uploads are validated by extension and size, hashed with SHA-256, and held in memory.
- Parser subprocesses run with timeouts in a private temp workspace that is auto-deleted.
- The uploaded original is never written to, and a test asserts its hash is unchanged.
- `ACTIVITY`, `COMPARISONS` and `CLEAN_ACTIVITY` (grading/answer-key data) are never read.
- No `shell=True`, no `eval`, no execution of config or AI output.

---

## Testing

```bash
pytest -q                 # full suite
pytest -q -m "not slow"   # fast subset (if you add the marker)
```

Real-file tests run against the bundled fixtures in `tests/fixtures/` and skip cleanly
when an engine is unavailable. Synthetic fixtures cover consensus/security logic so the
suite is meaningful even with zero engines installed.

See **[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)** for the last recorded run.

---

## Parser compatibility

See **[docs/parser_coverage.md](docs/parser_coverage.md)** for the full matrix, licensing
analysis, verified execution evidence and the independence caveat.

Summary: Engine A (MIT), Engine B (GPL-3.0, external), Engine C (All Rights Reserved,
external). All three were executed against a real 7-device lab file and produced
byte-identical container decodes.

---

## Known limitations

1. **Container decryption is shared.** All three engines implement the same public
   Twofish-EAX scheme. A decode bug would be identical across engines.
2. **Engine A is a decoder, not a parser.** Its device/interface facts come from
   TRIDENT's own XML walk (`A:raw-xml-walk`), recorded as such.
3. **End-host facts are single-source.** Gateways and DNS come only from Engine A's XML,
   so they are `VERIFIED_DERIVED` (1/3), never `VERIFIED`.
4. **Engine B synthesises interface names** (`iface0`…) in its topology export; real names
   are reconciled from IOS config and Engine C.
5. **No simulation.** TRIDENT analyses static configuration only. It never claims a ping
   would succeed.
6. **Snapshot ambiguity.** Multi-snapshot `.pka` files are reported, and only the block
   with the most devices is analysed — blocks are never merged.
7. **Empty activity skeletons.** A `.pka` whose snapshot blocks contain no devices yields
   zero devices and no verified answers, by design.
8. **AI is optional.** Without a key, deterministic heuristics interpret common question
   shapes. Unusual phrasings will be `NOT_AVAILABLE` rather than guessed.
9. **The 65-question benchmark was not available** in the workspace, so no benchmark
   accuracy is claimed. A 65-question batch test verifies scale and ordering only.

---

## License and third-party code

- TRIDENT itself: MIT.
- `vendor/engine_a/`: MIT (cisco-pka-to-xml), with the MIT-licensed Twofish C reference
  implementation by Niels Ferguson. See the LICENSE files in that directory.
- **PKT-CORE**: GPL-3.0-or-later, installed as a separate distribution and invoked through
  its public API/CLI. It is not vendored.
- **pt-convert**: All Rights Reserved. Not vendored; executed only from the operator's own
  checkout when explicitly configured.

---

## Layout

```
trident/
├── config.py              settings + secret handling
├── ingestion.py           read-only validation and hashing
├── models.py              Pydantic contracts
├── pipeline.py            orchestration
├── server.py              FastAPI app
├── parsers/               engine_a / engine_b / engine_c adapters
├── normalization/         IOS config parser + value normalisation + merge
├── verification/          consensus, validators
├── reasoning/             questions, queries, MCQ, AI client
└── web/                   index.html, app.js, style.css
```
