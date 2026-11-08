# Operational CLI Evidence Ingestion

Phase 2 · `trident/evidence/`

Turns pasted Cisco IOS terminal output into structured, attributed evidence that
the diagnostics engine can reason over. It is the **root prerequisite** for
diagnostics: nothing downstream should ever re-parse raw `show` text.

The module is pure: no device connection, no shell, no socket, no clock, no AI.
It only reads the text it is given.

---

## 1. The two questions this module answers honestly

Every pasted artefact is classified on two independent axes.

### What is it? — `EvidenceKind`

| Value | Command it comes from |
| --- | --- |
| `RUNNING_CONFIG` | `show running-config` |
| `IP_INTERFACE_BRIEF` | `show ip interface brief` |
| `VLAN_BRIEF` | `show vlan brief` |
| `INTERFACES_TRUNK` | `show interfaces trunk` |
| `IP_ROUTE` | `show ip route` |
| `SPANNING_TREE` | `show spanning-tree` |
| `ETHERCHANNEL_SUMMARY` | `show etherchannel summary` |
| `ACCESS_LISTS` | `show access-lists` |
| `OSPF_NEIGHBOR` | `show ip ospf neighbor` |
| `UNKNOWN` | anything else |

### Where does it come from? — `ObservationSource`

| Value | Meaning | Kinds |
| --- | --- | --- |
| `STATIC_CONFIG` | the **intended** configuration | `RUNNING_CONFIG` only |
| `RUNTIME_STATE` | the **observed** live state | every other kind |

This distinction is the point of the module. A value in `show running-config` is
what the operator meant to configure; a value in `show ip interface brief` is
what the device is actually doing. They can disagree, and that disagreement is
itself a diagnostic finding.

The mapping lives in one place, `SOURCE_BY_KIND`, and `CliRecord.__post_init__`
**rejects** a record whose `source` contradicts its `kind`. A runtime `show`
command can never be labelled `STATIC_CONFIG`.

---

## 2. Public surface

```python
from trident.evidence import (
    CliRecord, EvidenceBundle, EvidenceKind, ObservationSource, ParseStatus,
    detect_kind, parse_cli_output, strip_prompts,
)

record = parse_cli_output(text)                                  # may be unattributed
record = parse_cli_output(text, device="SW1")                   # caller asserts device
record = parse_cli_output(text, device="SW1", captured_at=ts)   # caller asserts time

kind, confidence = detect_kind(text)        # (EvidenceKind, 0.0 .. 1.0)
```

### `CliRecord`

```python
@dataclass(frozen=True)
class CliRecord:
    device: str | None
    kind: EvidenceKind
    source: ObservationSource
    captured_at: str | None
    raw_text: str
    parsed: dict | list      # list for IP_ROUTE / OSPF_NEIGHBOR / ETHERCHANNEL_SUMMARY
    status: ParseStatus
    notes: tuple[str, ...]
    line_count: int
```

Enum fields accept their string spellings (`"IP_ROUTE"`, `"RUNTIME_STATE"`,
`"PARSED"`) and are normalised on construction, so a record rebuilt from
serialised JSON is validated exactly like a freshly parsed one — and the
source/kind guard still fires.

### `ParseStatus`

| Value | Meaning |
| --- | --- |
| `PARSED` | a device is attributed, rows were parsed, nothing was skipped |
| `PARTIAL` | something was skipped, unattributed, or multi-device; `notes` says what |
| `UNRECOGNISED` | the paste is not a supported command; `parsed == {}` |

### `EvidenceBundle`

```python
bundle = EvidenceBundle()
bundle.add(record)

bundle.for_device("SW1")            # tuple[CliRecord, ...]
bundle.by_kind(EvidenceKind.IP_ROUTE)
bundle.devices()                    # sorted device names actually present
bundle.unattributed()               # records with device=None, kept apart

bundle.runtime_interfaces("SW1")    # {interface: {ip, ok, method, status, protocol}}
bundle.runtime_routes("SW1")        # [{code, network, mask_or_prefix, next_hop, interface, metric}]
bundle.static_config("SW1")         # the running-config lines, verbatim
```

Per-device views read only the **most recent** record of that kind for that
device; unattributed records never leak into a device view.

---

## 3. The hard rules, and where they are enforced

| Rule | Enforcement |
| --- | --- |
| Runtime vs static is never confused | `SOURCE_BY_KIND` + `CliRecord.__post_init__` |
| A device name is never invented | `resolve_device` returns `None` unless supplied or unambiguous in prompts |
| A timestamp is never invented | `captured_at` is only ever the caller's value; no clock is read |
| Unknown command stays unknown | `detect_kind` → `UNKNOWN`; `parse_cli_output` returns `UNRECOGNISED` with `parsed == {}` |
| A malformed row is skipped, not guessed | every parser appends a note and continues |
| Prompts are stripped, and used only if unambiguous | `strip_prompts` + `resolve_device` |
| Two devices are never merged | `parse_cli_output` refuses the whole paste; bundle keys strictly by device |
| A record without a device cannot claim `PARSED` | `CliRecord.__post_init__` |
| A `PARTIAL` record must explain itself | `CliRecord.__post_init__` |
| An `UNKNOWN` record cannot carry data | `CliRecord.__post_init__` |

### Device attribution order

1. the `device=` argument, if given;
2. otherwise exactly one distinct prompt device in the paste (`SW1#`, `R1(config)#`);
3. otherwise `None` — and the record is `PARTIAL` with a note.

If the caller's `device=` disagrees with the prompt, the caller's value wins and
a note records the conflict; the record is `PARTIAL`.

### Multi-device and multi-session pastes

A paste is rejected (one record, `device=None`, `parsed={}`, `PARTIAL`) when:

* prompts name more than one device, or
* the artefact's session marker appears more than once
  (`Current configuration :` for configs, the `IP-Address … Protocol` header,
  the `VLAN Name Status Ports` header, `Gateway of last resort`, the OSPF
  `Neighbor ID Pri` header, the EtherChannel `Group Port-channel Protocol`
  header), or
* a running-config contains more than one `hostname` declaration.

Rejection is deliberate: silently merging two devices into one structured result
is the failure mode this module exists to prevent.

---

## 4. Parsed shapes

All values are plain `dict` / `list` / `str` / `int` / `None`. No prose, no
nested dataclasses, so any consumer can serialise them directly.

| Kind | `parsed` |
| --- | --- |
| `IP_INTERFACE_BRIEF` | `{iface: {ip, ok, method, status, protocol}}` |
| `VLAN_BRIEF` | `{vlan_id: {name, status, ports: [str]}}` |
| `INTERFACES_TRUNK` | `{iface: {mode, encapsulation, native_vlan, allowed_vlans, active_vlans}}` |
| `IP_ROUTE` | `[{code, network, mask_or_prefix, next_hop, interface, metric}]` |
| `ACCESS_LISTS` | `{acl_name: [{seq, action, protocol, src, dst, raw}]}` |
| `OSPF_NEIGHBOR` | `[{neighbor_id, priority, state, dead_time, address, interface}]` |
| `ETHERCHANNEL_SUMMARY` | `[{group, protocol, flags, ports: [str]}]` |
| `SPANNING_TREE` | `{vlan: {root_id, bridge_id, interfaces: [{interface, role, status, cost, priority}]}}` |
| `RUNNING_CONFIG` | `{lines, hostname, ios_version, default_gateway, interfaces, vlans, routes, acls}` |

Notes on shapes:

* `status` in `IP_INTERFACE_BRIEF` keeps the two-word
  `administratively down` intact rather than splitting it.
* Standard ACL entries have `protocol = None`: a standard ACL has no protocol
  token, so inventing `ip` there would be a fabrication.
* `mask_or_prefix` is the prefix length as a string when the output used CIDR,
  or the dotted mask when the output used a mask.
* `SPANNING_TREE` keys are decimal VLAN strings (`"1"`, `"10"`), not `VLAN0001`.
* `native_vlan` is an `int` when present.
* `VLAN_BRIEF` merges wrapped port columns into the row above them.

---

## 5. Detection

`detect_kind(text) -> (EvidenceKind, confidence)` uses, in order:

1. **command echoes** — the text after a prompt (`SW1#show ip int brief`). This is
   the strongest signal and yields `0.99`. Two *different* recognised echoes in
   one paste is `UNKNOWN` at `0.1` confidence.
2. **structural signatures** — `Current configuration :`, the header row of each
   `show` output, `Gateway of last resort`, etc. These yield `0.85`–`0.95`.
3. otherwise `UNKNOWN` at `0.0`.

Two equally strong structural signals for different kinds is `UNKNOWN` at `0.3`
— ambiguity is reported, never broken by preference order.

Confidence is a property of the paste, not of the parse: a `PARSED` record from a
purely structural match is still fully parsed. It exists so callers can decide
whether to ask the operator to confirm.

---

## 6. Worked examples

```python
>>> from trident.evidence import parse_cli_output
>>> r = parse_cli_output(
...     "SW1#show ip interface brief\n"
...     "Interface    IP-Address   OK? Method Status Protocol\n"
...     "Gi0/1        10.0.0.1     YES manual up     up\n"
... )
>>> r.device, r.kind.value, r.source.value, r.status.value
('SW1', 'IP_INTERFACE_BRIEF', 'RUNTIME_STATE', 'PARSED')
>>> r.parsed["Gi0/1"]
{'ip': '10.0.0.1', 'ok': 'YES', 'method': 'manual', 'status': 'up', 'protocol': 'up'}
```

Two devices in one paste — rejected, never merged:

```python
>>> r = parse_cli_output(
...     "R1#show ip int brief\nGi0/0 10.0.0.1 YES manual up up\n"
...     "R2#show ip int brief\nGi0/0 10.0.0.2 YES manual up up\n"
... )
>>> r.device is None, r.status.value, r.parsed
(True, 'PARTIAL', {})
>>> r.notes
('paste contains prompts for several devices (R1, R2); no single device is attributed',)
```

Garbage:

```python
>>> r = parse_cli_output("%% Invalid input detected at '^' marker.", device="R1")
>>> r.kind.value, r.status.value, r.parsed
('UNKNOWN', 'UNRECOGNISED', {})
```

A truncated row is skipped, the rest survive:

```python
>>> text = (
...     "SW1#show ip int brief\n"
...     "Gi0/1 10.0.0.1 YES manual up up\n"
...     "Gi0/2 10.0.0.2 YES\n"
...     "Gi0/3 10.0.0.3 YES manual up up\n"
... )
>>> r = parse_cli_output(text)
>>> sorted(r.parsed), r.status.value
(['Gi0/1', 'Gi0/3'], 'PARTIAL')
```

---

## 7. For the diagnostics engine

Diagnostics should consume the bundle, not the text:

```python
from trident.evidence import EvidenceBundle, EvidenceKind

bundle = EvidenceBundle()
for paste in operator_pastes:
    bundle.add(parse_cli_output(paste, captured_at=capture_time))

runtime = bundle.runtime_interfaces("SW1")   # what the device is doing
intended = bundle.static_config("SW1")       # what it was told to do
```

Then compare. The `ObservationSource` on each record tells you which side of the
comparison you are on, and `record.notes` is the reason a field is missing —
never infer "the value is absent" from an absent key without checking `status`.

Do not re-derive a device name from `raw_text`; use `record.device`. It is
`None` precisely when attribution was impossible.

---

## 8. Testing

`tests/test_phase2/test_evidence.py` (77 tests) covers, for every kind, both the
happy path and the honesty contract:

* each of the nine kinds parses real-looking output into the documented shape
* runtime vs static classification for every kind, plus a constructor-level test
  that a lying `source` is rejected
* no device supplied → `device is None`, `PARTIAL`, rows still parsed
* garbage → `UNKNOWN` / `UNRECOGNISED`, empty `parsed`
* truncated `show ip int brief` → `PARTIAL`, good rows survive
* two devices pasted together → rejected, and the bundle keeps devices separate
* `captured_at` is `None` unless supplied, and is carried verbatim
* prompt-derived device detection (`Router#`, `SW1(config)#`, `R1>`, dotted names)
* a malformed route line is skipped while the others parse
* bundle typed views, latest-record-wins, and empty results for unknown devices
* serialisation round-trip (`CliRecord` rebuilt from raw enum spellings)
* a spanning-tree paste with no VLAN header is keyed `"unknown"` and `PARTIAL`,
  never assigned a guessed VLAN

Run:

```bash
.venv/bin/python -m pytest tests/test_phase2/test_evidence.py -q
.venv/bin/python -m ruff check trident/evidence tests/test_phase2/test_evidence.py
```

---

## 9. Known limits

Stated plainly, because a diagnostics engine must not over-trust this layer:

* **`show access-lists` requires sequence numbers.** They are always present in
  real IOS output; a line without one is treated as malformed rather than being
  assigned an invented sequence.
* **`show interfaces trunk` requires the five-column header row.** Some IOS
  generations print an extra `Vlans in spanning tree forwarding state` block,
  which is deliberately ignored (not modelled); a truncated header row is
  reported as malformed.
* **`show ip route` handles the classic IOS layout.** It understands `C`, `L`,
  `S`, `S*`, `O`, `R`, `D`, `B`, `i`, `*` and multi-letter codes, CIDR and dotted
  masks, `via <hop>` and `is directly connected, <iface>`. It does not model
  recursive-route resolution, VRF-specific tables, or multi-line route detail
  blocks.
* **`show spanning-tree` requires `VLANnnnn` section headers** and the
  `Interface Role Sts Cost Prio.Nbr` table header. Output with no VLAN header at
  all is keyed under `"unknown"` and reported `PARTIAL` — a VLAN is never
  guessed for it. Multi-instance MST output keyed only by `MST0` is not
  separated per instance.
* **`show etherchannel summary` requires the `Group Port-channel Protocol`
  header.** The per-port bundle detail below the summary is not merged into the
  group rows.
* **`show ip ospf neighbor` requires one neighbour per line** with exactly the
  six documented columns. Detail views (`show ip ospf neighbor detail`) parse as
  nothing and are reported `PARTIAL`.
* **`show vlan brief` merges continuation lines** into the preceding VLAN's port
  list. VLANs printed without a `Ports` column are still parsed, with `ports: []`.
* **Running-config parsing is delegated** to the existing deterministic
  `trident.normalization.configs.parse_running_config`; anything that parser does
  not model is preserved verbatim in `parsed["lines"]` but not structured.
* Only the nine listed commands are recognised. Anything else, including other
  perfectly valid `show` commands, is `UNKNOWN` by design — a best-effort guess
  is worse than an honest gap.

---

## 10. Packaging note

`trident/evidence` is a new package. It imports only from
`trident.normalization.configs`, so it has no new third-party dependency. The
`[tool.setuptools] packages` list in `pyproject.toml` should gain
`"trident.evidence"` when the next packaging change is made; this change was
kept inside the requested directories and did not edit `pyproject.toml`.
