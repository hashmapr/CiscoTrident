# TRIDENT — Parser Compatibility Matrix & Integration Research

All findings below were produced by **actually cloning, installing, and executing** each
engine against the real sample files shipped in `PKT-CORE/corpus/samples/`:

| File | Bytes | SHA-256 (first 16) | Format |
|---|---|---|---|
| `sample_activity.pka` | 34,226 | `2f1c2b7f...` | PKA (activity) |
| `sample_lab.pkt` | 81,474 | `9b3b0a0d...` | PKT (network lab) |

## 1. Executive summary

| | **Engine A** — cisco-pka-to-xml | **Engine B** — PKT-CORE | **Engine C** — pt-convert |
|---|---|---|---|
| License | **MIT** | **GPL-3.0-or-later** | **All Rights Reserved** (proprietary) |
| Language | Python + C (vendored Twofish) | Python (+ optional Rust) | TypeScript / Next.js (browser) |
| Local headless | Yes (`decrypt_pka` / `encrypt_pka`) | Yes (`pkt` CLI, `open_lab`, `decode`) | Yes (Node, after extracting 2 lib modules) |
| Supports `.pka` | Yes | Yes | Yes |
| Supports `.pkt` | Yes | Yes | Yes |
| Container decode | Yes | Yes | Yes |
| IOS config extraction | **No** (decode only) | Yes (`pkt unpack` → `configs/*.cfg`) | Yes (`config[:]` per device) |
| Device inventory | No (needs caller XML walk) | Yes (`topology.json`) | Yes (`devices{}`) |
| Physical topology | No | Yes (`topology.json`) | Yes (`links[]`) |
| Programmatic entry point | `pka2xml.decrypt_pka()` | `pkt_core.open_lab()` / CLI | `decryptPacket()` + `simplifyXmlToJson()` |
| Vendoring permissable | Yes (MIT) | Copyleft — process-isolated | **No** — process-isolated only |

### Verified execution evidence

Container decryption was executed through all three engines on both sample files and
compared byte-for-byte:

```
sample_activity.pka  A=321434 sha=58083b3ca17ed9d6  B=321434 sha=58083b3ca17ed9d6  C=321434 sha=58083b3ca17ed9d6
sample_lab.pkt       A=1045755 sha=ae176dc9ad51b4b9 B=1045755 sha=ae176dc9ad51b4b9 C=1045755 sha=ae176dc9ad51b4b9
```

**Result: all three produce byte-identical XML.**

## 2. The independence problem (critical finding)

All three engines implement the **same published container format**:

- Twofish-EAX with the *constant* key `0x89 × 16` and IV `0x10 × 16`
- position-keyed XOR obfuscation (two layers)
- zlib with a 4-byte big-endian length prefix

There is no per-file secret. Therefore **container decryption is not three independent
observations** — it is one shared algorithm reproduced three times. A bug in the algorithm
would produce identical wrong output in all three.

TRIDENT therefore treats the engines as independent **at the extraction layer only**:

- **Engine A** genuinely contributes: decrypted XML bytes + raw XML evidence. It extracts
  nothing beyond the container, so its device/interface observations are derived by
  TRIDENT's own XML walker over *Engine A's own decoded bytes* and are recorded with a
  distinct `extraction_path` (`A:raw-xml-walk`) rather than being counted as a third
  opinion on vendor semantics.
- **Engine B** contributes its own typed model (`pkt_core.open_lab`) and its own CLI
  unpacker output (`topology.json`, `configs/*.cfg`).
- **Engine C** contributes its own JS parser (`fast-xml-parser`) and simplifier.

The consensus engine enforces this: it counts **distinct extraction families**, and
`crypto_shared=true` is recorded on every observation so a `VERIFIED` result can never be
produced from three copies of the same decode. See `trident/verification/consensus.py`.

## 3. Engine A — cisco-pka-to-xml

- **Repo:** https://github.com/jeamxn/cisco-pka-to-xml
- **License:** MIT (vendored Twofish reference implementation is also MIT)
- **Install:** `python build_libtwofish.py` (needs a C compiler; succeeded on Apple Silicon
  via `/usr/bin/cc` producing `libtwofish.dylib`)
- **API:** `pka2xml.decrypt_pka(bytes) -> bytes` (XML), `encrypt_pka(bytes) -> bytes`
- **Own tests:** `tests/test_roundtrip.py` — encode/decode roundtrip + Twofish KAT.
- **Extraction capability:** **container only.** The README states it decodes to XML; the
  bundled `examples/inspect_devices.py` is a regex demo, not a parser.
- **Integration:** imported in-process. TRIDENT copies the package into
  `vendor/engine_a/pka2xml` plus the built `libtwofish.dylib`, respecting MIT attribution.
- **Caveat:** requires native library present; TRIDENT reports `UNAVAILABLE` with the exact
  build error if the `.dylib`/`.so` is missing. It never fabricates output.

## 4. Engine B — PKT-CORE

- **Repo:** https://github.com/Shamveel-Khan/PKT-CORE
- **PyPI:** `pkt-core==0.2.2` (installed and executed successfully)
- **License:** **GPL-3.0-or-later**. TRIDENT does **not** vendor or import its source into
  the shipped tree as a linked derivative; it invokes the installed distribution through
  the documented public API and its own CLI as an external dependency, and documents the
  obligation.
- **API:** `pkt_core.open_lab(path) -> LabView`; `pkt_core.decode(path) -> Container`;
  CLI `pkt unpack <file> -o <dir>` producing `topology.json`, `configs/*.cfg`,
  `topology.dot`, `*.container.json`.
- **Extraction capability:** typed `Lab` model (`devices`, `links`, `clusters`), NetBox-shaped
  `topology.json` (device name/role/model/position/interfaces with MAC + media type),
  Graphviz DOT, and **per-device IOS running config** text.
- **Known limitation:** its `topology.json` synthesises interface names as `iface0`,
  `iface1`, … because real port names are not present on the `<PORT>` element — the true
  names live in `<LINKS>` and in the IOS config. TRIDENT reconciles this: real names come
  from Engine C / config text, and `iface*` names are treated as opaque port handles.

## 5. Engine C — pt-convert

- **Repo:** https://github.com/semicolonmystery/pt-convert
- **License:** **"All Rights Reserved"** — explicit prohibition on copying, building,
  modifying, using or distributing. The live site is `pt-convert.podik.cz`.
- **Notable:** no Python API, no server API. Everything is client-side TS in a Web Worker.
- **Usable modules:** `src/lib/packet-crypto.ts` (`decryptPacket`, `encryptXml`) and
  `src/lib/xml-simplifier.ts` (`simplifyXmlToJson`). Runtime deps needed: `pako`,
  `twofish`, `fast-xml-parser` only — the Next.js/React/shadcn tree is irrelevant.
- **Integration approach chosen:** **external subprocess only.** TRIDENT runs a small
  Node.js bridge (`trident/parsers/engine_c_bridge.mjs`) that imports the operator's own
  clone of pt-convert from a configurable path (`TRIDENT_PT_CONVERT_DIR`). The bridge script
  is TRIDENT's own glue code; pt-convert's code is never copied into this repository.
  Licensing is surfaced in the UI/README and the adapter reports `UNAVAILABLE` when
  `TRIDENT_PT_CONVERT_DIR` is not configured. The operator is responsible for having
  permission to run that code.
- **Extraction capability (verified):** full `devices{}` map with `type`, `config[]`
  (complete IOS running config lines), `notes`; `links[]` with real `FromDevice`,
  `FromPort`, `ToDevice`, `ToPort`; `metadata` with counts.

## 6. Shared dependencies and their consequences

| Shared concern | Engines | Consequence |
|---|---|---|
| Twofish-EAX + XOR + zlib container | A, B, C | Decryption is **one** algorithm, not three votes |
| Same constant key/IV | A, B, C | No per-file entropy; a wrong decode is wrong identically everywhere |
| XML semantics | B, C (and A via TRIDENT walker) | Interface-name reconstruction is genuinely re-derived per engine |
| IOS text | B (`configs/*.cfg`), C (`config[]`) | Strongest real cross-check available |

## 7. PKA snapshot isolation

Verified by inspecting a real activity file. A `.pka` root contains:

```
<VERSION>, <PACKETTRACER5> ×3, <COMPARISONS>, <INITIALSETUP>, <LOCKINGTREE>,
<OPTIONS>, <ACTIVITY>, ... <CLEAN_ACTIVITY>, <SCRIPT_MODULE>, <AUTHOR>
```

- The **three** `<PACKETTRACER5>` siblings are the initial / current / reference state blocks.
  The shipped `sample_activity.pka` is an empty skeleton (all three blocks have zero devices),
  so ordering cannot be inferred from that file alone.
- `<ACTIVITY>` holds `INSTRUCTIONS` and `INSTRUCTION_DIALOG`; `<COMPARISONS>` holds grading
  `NODE`s. **These are answer-key bearing and are never extracted or exposed.**
- TRIDENT policy: analyse a **single** snapshot; if the file has >1 non-empty `<PACKETTRACER5>`
  block, TRIDENT reports `snapshot_ambiguous=true` and analyses **only the block with the
  highest device count**, recording which index was used. It never merges blocks and never
  reads `ACTIVITY`/`COMPARISONS`/`CLEAN_ACTIVITY`.

## 8. Capability matrix (what each adapter yields into the unified model)

| Field | A (`A:raw-xml-walk`) | B (`B:pkt-core`) | C (`C:pt-convert`) |
|---|---|---|---|
| Device name | yes | yes | yes |
| Device kind / model | yes | yes | yes |
| IOS version | yes (config/`<VERSION>`) | yes (config) | yes (config) |
| Running config lines | yes | yes | yes |
| IPv4 / mask (L3) | yes (config) | yes (config) | yes (config) |
| IPv4 / mask (end host `<IP>`) | yes | partial | partial |
| Default gateway | yes | — | — |
| DNS server | yes | — | — |
| VLANs | yes | yes (config) | yes (config) |
| ACLs | yes (config) | yes (config) | yes (config) |
| Routes | yes (config) | yes (config) | yes (config) |
| Links (device+port) | yes (`<LINKS>`) | yes (typed) | yes (real port names) |
| MAC address | yes (`<PORT>`) | yes | — |
| Answer-key data | **never read** | **never read** | **never read** |

Legend: `yes` = observed during this research; `—` = not produced by that engine's own parser.
