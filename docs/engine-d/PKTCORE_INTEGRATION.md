# Engine B — pkt_core integration (authoring path)

Status: deepening of the existing Engine B integration. Engine B remains a
separate, external distribution; Trident consumes it through adapters only.
Nothing in this work adds a new parser or a new container codec.

## 1. Installed distribution and licence

| Item | Value |
| --- | --- |
| Distribution | `pkt-core` |
| Version | **0.2.2** |
| Import package | `pkt_core` |
| Location | `.venv/lib/python3.12/site-packages/pkg_core` (module `pkt_core`) |
| Declared licence | **GPL-3.0-or-later** (`License-Expression: GPL-3.0-or-later`) |
| Runtime dependency | `pydantic` |
| Required by | `trident-pt` |

Licensing rules applied here:

* pkt_core is **GPL-3.0-or-later**. Trident does not vendor, copy, submodule,
  fork, or re-implement its source.
* The adapter imports the *installed* package through its documented public API.
  Trident ships `trident/labgen/pktcore_adapter.py` and
  `trident/parsers/pkt_core.py`; it does not ship pkt_core.
* Any redistribution of a Trident build that bundles pkt_core must satisfy
  GPL-3.0-or-later. Trident's own source is not relicensed by this dependency
  because it is used as a separate program at runtime, not linked into it.
* No source file from the package is copied into tests or docs. Tests exercise
  the installed package and skip when it is absent.

## 2. Public API surface

`pkt_core.__all__` exposes three groups.

### Authoring (the path hardened here)

| Symbol | Purpose |
| --- | --- |
| `Lab` | Author a fresh lab: bundled device models and seed. `add_device`, `link`/`connect`, `install_module`, `set_os`, `set_config_register`, `set_wireless`, `auto_layout`, `drop_initial`, `drop_seed_devices`, `prune_seed_devices`, `to_xml`, `save`/`export`, `as_view`, `device_names`, `initial_id`. |
| `LabBuilder` | Lower-level builder used by `Lab`. |
| `Activity`, `ActivityBuilder` | Author `.pka` activity files. See §7 — inspected, deliberately not used. |
| `Layout` | Canvas placement helper. |

`Lab.add_device(model, name, x, y, power=True, ios_config=None, pc_ip=None,
install=None, bay=0, slot=None, on_name_conflict="raise")` accepts
`pc_ip=(ip, mask, gateway)` for end hosts and `ios_config=[...]` for IOS devices.
`Lab.save(path, fmt="pkt")` writes the real container.

### Reading / codec

| Symbol | Purpose |
| --- | --- |
| `open_lab(path)` | Decode a container and return a typed `LabView` (devices, links, clusters, running config, summary). |
| `decode(path)` / `decode_bytes(raw)` | Container -> `Container(xml, format_name, root_tag)`. |
| `encode(path, ...)` / `encode_bytes(xml, fmt)` | XML -> container bytes. |
| `detect_format`, `root_tag`, `DEFAULT_FORMAT`, `Container` | Format inspection. |
| `diff_labs(a, b)` | Semantic diff of two `LabView`s: devices, links, config lines, meta. |
| `export(lab, fmt)` | Topology export (`graphviz`, `netbox`, `containerlab`, ...). |

### Crypto / framing primitives

`FORMATS`, `FormatSpec`, `get_format`, `eax_seal`, `eax_open`, `eax_verify`,
`qcompress`, `quncompress`, `BLOCK_SIZE`, `TAG_SIZE`. Supported container
flavours measured on this build: `pkt`, `log`, `pkc`, `pta`, `sm`, `userapp`,
`legacy`.

### What it can do

* Build a new `.pkt` from bundled models: PCs, servers, switches, routers,
  access points, IoT-style devices; install modules; add IOS config lines; place
  and cable devices.
* Write and read the container format faithfully (see §3).
* Inspect typed device/port/link state and running configuration.
* Author `.pka` activities, including an answer network and scoring XML.

### What it cannot do (measured limits)

* `add_device(..., pc_ip=...)` does **not** set the value Packet Tracer reads as
  an end host's default gateway. It writes `<PORT_GATEWAY>` only and leaves
  `<ENGINE><GATEWAY>` at the donor template's value. See §4.
* No public setter for `<ENGINE><GATEWAY>` (or for L3 state in general) is
  exposed by `Lab`, `LabBuilder`, or the typed models; `Port` does not expose
  IP/mask/gateway at all.
* The typed model exposes only claimed fields; unrecognised port data stays in
  `extra_fields`. `diff_labs` compares device identity, media/port attributes,
  links and config lines — not ENGINE gateway, not port L3 addressing.
* `export` synthesises interface names as `iface0..N` in its topology JSON; that
  is an existing Engine B limitation and is unchanged by this work.
* Building `Lab()` embeds bundled models and a seed device set; `to_xml()` was
  measured at ~798 KB while the saved container was ~57 KB. Seed devices must be
  dropped explicitly (`drop_seed_devices`/`prune_seed_devices`).

## 3. Fidelity: lossless vs lossy

Measured on this build:

* **Container round-trip is lossless.** `decode(path)` followed by
  `encode_bytes(container.xml, container.format_name)` reproduced the original
  file **byte-for-byte** for a generated lab (`pkt`/`PACKETTRACER5`, 56 821
  bytes). `roundtrip_ok()` reports this as the strongest available statement.
* **XML is preserved as text by the container**, so byte-preserving edits to
  the decoded XML survive re-encoding.
* **The typed model is lossy by design.** It normalises and exposes a subset of
  fields; unknown data is kept in `extra_fields` and is not part of equality or
  diffing. Do not use the model as a lossless representation.
* **Running config is compared as bytes.** pkt_core deliberately exposes config
  lines as `bytes` because IOS banner delimiters contain control characters.
  Any text rendering is lossy and must not be used to rewrite config.
* `diff_labs` matches devices by name and links by endpoint identity, so
  document reordering is not a change. It does not compare canvas-unrelated
  metadata outside its model.

## 4. The end-host gateway defect (pkt_core 0.2.2)

Two independent observations are reproduced by `gateway_support()`:

| Model requested | Requested gateway | Written `<PORT_GATEWAY>` | Written `<ENGINE><GATEWAY>` |
| --- | --- | --- | --- |
| `PC-PT` | `10.0.0.1` | `10.0.0.1` (correct) | **`1.1.1.2`** (donor default) |
| `Server-PT` | `10.0.0.1` | `10.0.0.1` (correct) | **`192.168.10.1`** (donor default) |

Packet Tracer reads the ENGINE-level element for an end host's default gateway.
Because pkt_core writes only the port-level element, every generated PC/server
keeps the donor template's gateway and cannot route off-subnet. A probe with a
distinctive requested gateway (`10.255.255.254`) is used so the test cannot pass
by coincidence.

Element path (confirmed on the generated document):

```
PACKETTRACER5/NETWORK/DEVICES/DEVICE/ENGINE/GATEWAY
```

### The fixup

`trident.labgen.pktcore_adapter.postprocess_endhost_gateways(xml_bytes, hosts)`

* Takes decoded XML bytes and a `{device_name: gateway}` mapping.
* Locates each named device's `ENGINE/GATEWAY` with `xml.parsers.expat` byte
  offsets, replaces **only that element's text** (or the whole element if it
  was written empty), and splices the bytes back in.
* Applies edits right-to-left so offsets remain valid.
* Preserves everything else byte-for-byte: indentation, element order, the XML
  declaration, module/PORT data, and running config.
* Raises `KeyError` if a named device is absent (a typo is not a silent no-op)
  and `ValueError` for an unsafe gateway string.
* Idempotent: a second call with the same mapping returns identical bytes.
* Self-checks the result: every requested value landed, the device inventory is
  unchanged, and the document is still well-formed.

Evidence in `tests/test_pktcore_adapter.py`:

* Masking every `ENGINE/GATEWAY` element in the original and fixed documents to a
  constant produces **byte-identical** documents. Any difference outside those
  elements would survive masking and fail the assertion.
* Exactly two gateway spans change for a two-PC lab.
* Device inventory and running config are unchanged.
* After re-encoding to a container and decoding again, the ENGINE gateways are
  the requested values.

### Is the fixup needed?

Yes on 0.2.2. `gateway_support()` reports:

```
False, "pkt_core 0.2.2: <ENGINE><GATEWAY>='1.1.1.2' != requested '10.255.255.254'
 for probe GWPROBE; port-level <PORT_GATEWAY>='10.255.255.254'. Packet Tracer
 reads the ENGINE element, so the end-host gateway fixup is required."
```

If a future release writes the ENGINE element, `gateway_support()` flips to
`True` and the fixup becomes a no-op for already-correct values.

## 5. Diagnostics helpers

`roundtrip_ok(path) -> (bool, str)`
: Decode -> re-encode and compare to the raw file. Returns True only for
  byte-identical output, with format/root tag and size in the reason. Errors are
  reported as `(False, "ErrorType: message")`, never raised.

`semantic_compare(a_path, b_path) -> dict`
: Returns buckets `identical`, `devices`, `links`, `interfaces`, `configs`,
  `meta`, `summary`, `error`.
  * `devices`, `links`, `configs`, `meta` come from `pkt_core.diff_labs`.
  * `interfaces` compares every port's media and L3 state plus a reserved
    **port index 0** row holding the ENGINE-level gateway (the value pkt_core's
    model does not expose).
  * `configs` lines are rendered with `backslashreplace`; the underlying bytes
    are the source of truth.
  * On any error all buckets stay empty, `identical` is False, and `error`
    explains why — an error can never be mistaken for "no difference".
  * Used by fault-injection work to prove a fault changes at least one bucket.

## 6. Newer pkt_core copies on this machine

Searched: `/tmp`, `~/Downloads`, `/Volumes` (depth 4–5), the home directory to
depth 5, `~/Library/Caches/pip`, and all `site-packages` directories to depth 6.

Result: **no other copy exists**. The only installed distribution is
`pkt-core 0.2.2` in `/Users/tanayshah/CiscoTrident/.venv`. There is no wheel,
sdist, source checkout, or alternate version to compare against, so it is not
possible to state whether any newer release fixes `<ENGINE><GATEWAY>`.
Nothing was installed or upgraded; that requires the lead's approval.

## 7. Scored activities — inspected, not used

pkt_core's `Activity` / `ActivityBuilder` can author `.pka` files:

* The container root is `<PACKETTRACER5_ACTIVITY>` and embeds three
  `<PACKETTRACER5>` documents: working, initial, and **answer** networks.
* Methods include `set_instructions`, `set_feedback`, `set_scoring`,
  `set_scoring_xml`, `set_timer`, `set_unlock_percent`, `set_password`,
  `set_permissions`, `set_networks`, `set_clean_activity`, `save`.

Assessment: the capability is real and sufficient to generate scored activities.
**It is not used to produce competition material.** Scoring/answer-network
authoring is inspected only. Producing graded competition content from a third-
party generator would undermine assessment integrity and is out of scope for
this integration. Trident may read or diagnose `.pka` files; it does not author
scored answer networks.

## 8. Adapter usage

```python
from pathlib import Path

import pkt_core
from trident.labgen.pktcore_adapter import (
    gateway_support,
    postprocess_endhost_gateways,
    roundtrip_ok,
    semantic_compare,
)

ok, reason = gateway_support()          # measured, not assumed

lab = pkt_core.Lab()
lab.add_device("PC-PT", "PC1", 100, 100,
               pc_ip=["10.20.30.10", "255.255.255.0", "10.20.30.1"])
lab.add_device("2960-24TT", "SW1", 300, 100)
lab.link("PC1", "FastEthernet0", "SW1", "FastEthernet0/1")
lab.save("lab.pkt")

container = pkt_core.decode("lab.pkt")
fixed_xml = postprocess_endhost_gateways(container.xml, {"PC1": "10.20.30.1"})
Path("lab-fixed.pkt").write_bytes(
    pkt_core.encode_bytes(fixed_xml, container.format_name)
)

roundtrip_ok("lab-fixed.pkt")           # (True, "lossless: pkt/PACKETTRACER5 ...")
semantic_compare("lab.pkt", "lab-fixed.pkt")   # interface GATEWAY delta
```

## 9. Test coverage

`tests/test_pktcore_adapter.py` (offline; entire module skips when pkt_core is
not installed):

1. `gateway_support()` returns a measured bool and a reason naming the version.
2. `postprocess_endhost_gateways` changes only ENGINE gateway elements
   (masking equality), leaves inventory and config intact, and is idempotent.
3. An unknown device name is rejected.
4. The fixup survives a container save/decode round trip and the gateway reads
   back correctly.
5. `semantic_compare` detects an added running-config line.
6. `semantic_compare` reports no differences for two identical builds.
7. `semantic_compare` detects an ENGINE gateway change as an interface delta.
8. `roundtrip_ok` is byte-lossless on a generated lab.
9. `roundtrip_ok` reports a non-container honestly instead of raising.

## 10. Not verified / open items

* No newer pkt_core exists locally, so the upstream fix status is unknown.
* Packet Tracer itself was not launched (per task rules). The claim that Packet
  Tracer reads `<ENGINE><GATEWAY>` is established context from two independent
  agents, not re-measured here.
* `.pka` activity authoring was inspected at the API level only; its runtime
  behaviour in Packet Tracer's grading engine was not exercised.
* Fault-injection callers are out of scope for this file set; the adapter only
  provides the comparison primitive they can use.
