# Before/After Network Comparison Engine

Phase 2 · `trident/diff/`

The diff engine answers one question:

> Given two trusted `NetworkModel` snapshots of the same network, what actually
> changed, and what evidence supports each claim?

It is a **pure function of two models**. No AI, no network I/O, no mutation of
either input. Two `NetworkModel` instances go in; one immutable `DiffResult`
comes out.

```python
from trident.diff import compare

result = compare(before_model, after_model)

for change in result.changes:
    print(change.device, change.field, change.before, "->", change.after, change.severity)
```

---

## 1. Public surface

Everything below is exported from `trident.diff`:

```python
from trident.diff import (
    ChangeKind, Severity, FieldChange, DiffResult,
    compare, DEVICE_FIELDS, INTERFACE_FIELDS,
)
```

### `ChangeKind`

| Value | Meaning |
| --- | --- |
| `ADDED` | The field exists only in the after snapshot (including a newly added device or interface). |
| `REMOVED` | The field exists only in the before snapshot. |
| `MODIFIED` | The field exists in both snapshots with different values. |
| `UNCHANGED` | Reserved for reporting layers. `compare()` never emits it — equal fields are counted in `unchanged_count` instead. |

### `Severity`

| Value | Meaning |
| --- | --- |
| `INFO` | Cosmetic or metadata change. Nothing about reachability moved. |
| `WARNING` | Reachability, interface identity, or routing changed. |
| `CRITICAL` | A device present before is no longer in the snapshot. |

### `FieldChange`

Frozen dataclass. All attributes are read-only.

| Field | Meaning |
| --- | --- |
| `device` | Device name. When the two sides are keyed differently it is rendered `before->after`. |
| `interface` | `None` for device-level fields and for device presence changes. Otherwise the canonical interface name. |
| `field` | `hostname`, `model`, `ios_version`, one of the interface fields, `device`, `interface`, or `route:<destination>`. |
| `before` / `after` | The values, or `None` where the value is absent on that side. |
| `kind` | `ADDED`, `REMOVED`, or `MODIFIED`. |
| `severity` | Per the table above. |
| `evidence_before` / `evidence_after` | Always populated. Name the model attribute and the snapshot side; absence is spelled out. |

### `DiffResult`

| Field | Meaning |
| --- | --- |
| `before_snapshot` / `after_snapshot` | The two `NetworkModel.snapshot_id` values. |
| `changes` | Tuple of `FieldChange`, sorted by device, then by discovery order. |
| `added_devices` | Device names present only in the after snapshot. |
| `removed_devices` | Device names present only in the before snapshot. |
| `ambiguous_devices` | Names that could not be matched safely. Never diffed. |
| `unchanged_count` | Number of compared field slots that were equal, plus route keys present in both snapshots. |

---

## 2. Device matching

Matching runs in three tiers. A device that matches in an earlier tier is never
considered again.

1. **Exact name** — the device key or `DeviceInfo.name` on each side, compared
   case-insensitively. Substring matching is never used.
2. **Hostname** — `DeviceInfo.hostname` on the after side against the key,
   name, or hostname on the before side.
3. **Display-name alias** — the snapshot `placeholder_map` that Packet Tracer
   uses to turn `[[pr3-rt_Display_name]]` into `Node One Router`. Both directions
   are honoured: a device keyed by the raw placeholder matches a device keyed by
   the display name. Resolution delegates to
   `trident.reasoning.entities.resolve_device_name`, which is boundary-aware and
   returns ambiguity instead of a guess.

### Ambiguity rules

A device is **ambiguous** — reported in `ambiguous_devices` and not diffed at
all — when either:

* its name resolves to more than one device at the same tier, or
* two after-side devices both claim the same before-side device.

Ambiguous devices are never reported as added or removed, because neither claim
can be supported.

### `Router-1` vs `Router-10`

Matching is equality-based, and alias resolution uses boundary-delimited regexes,
so `Router-1` can only ever match `Router-1`. A pair like `Router-1` (before) and
`Router-10` (after) yields exactly one removed device and one added device. The
two are never merged, and no change pairs them.

---

## 3. What is compared

### Per device (matched pairs)

`hostname`, `model`, `ios_version`.

### Per interface (matched pairs, keyed by canonical name)

`ipv4_address`, `subnet_mask`, `prefix_length`, `admin_state`,
`operational_state`, `description`, `vlan_assignments`.

`vlan_assignments` is a list on the model; it is rendered as a sorted,
comma-separated string so the comparison is order-insensitive.

Interfaces present on only one side produce one `interface` change
(`ADDED` / `REMOVED`, `WARNING`) rather than a field-by-field expansion, because
the missing interface has no comparable fields.

### Routes

Keyed by `(device, destination, next_hop)` — case-insensitive, with a missing
next hop treated as `"connected"`. A route key present on only one side is one
`route:<destination>` change. A route present on both sides is counted as
unchanged; non-key attributes such as `route_type` are deliberately not
compared, to keep the key definition honest.

`RouteInfo.device` is canonicalised onto the owning device key when that mapping
is unambiguous, so a route whose device is recorded as a hostname on one side
and a key on the other is still compared.

### Added / removed devices

Produce exactly one `device` presence change. Their interfaces and routes are
**not** enumerated, because a device that exists on only one side has nothing to
be compared against. Removed devices are `CRITICAL`.

---

## 4. Severity assignment

| Field | Severity |
| --- | --- |
| `hostname` | `INFO` |
| `description` | `INFO` |
| `model` | `INFO` |
| `ios_version` | `INFO` |
| `ipv4_address` | `WARNING` |
| `subnet_mask` | `WARNING` |
| `prefix_length` | `WARNING` |
| `admin_state` | `WARNING` |
| `operational_state` | `WARNING` |
| `vlan_assignments` | `WARNING` |
| `interface` (added / removed) | `WARNING` |
| `route:<destination>` | `WARNING` |
| `device` (added) | `WARNING` |
| `device` (removed) | `CRITICAL` |

---

## 5. The honesty contract

1. **A change always cites both sides.** `evidence_before` and
   `evidence_after` are never empty. Where a value is absent, the string says so
   (`"R1: InterfaceInfo.ipv4_address absent in before snapshot"`) instead of
   leaving a blank that could be mistaken for an observed value.

2. **Silence is not agreement.** A field that is `None` on both sides is
   neither a change nor an unchanged slot. Two snapshots that both fail to
   observe a value have not agreed on anything.

3. **Ambiguity is reported, never resolved.** Names that match more than one
   device go to `ambiguous_devices` and are excluded from every other list and
   from `changes`. This is the same stance as the compliance engine's
   `INDETERMINATE` and the entity resolver's ambiguity output.

4. **`UNCHANGED` is never emitted as a change.** Identical snapshots give
   `changes == ()` with a positive `unchanged_count`. Callers that need
   per-field confirmation read the count, not a list of no-ops.

5. **Boundary-aware identity.** Device names are compared for equality; alias
   resolution uses the boundary-aware matcher. `Router-1` and `Router-10` cannot
   be conflated by a prefix.

---

## 6. Tests

`tests/test_phase2/test_diff.py` covers the contract directly:

| Test | What it pins |
| --- | --- |
| `test_device_added` | Added device appears in `added_devices` with both evidence strings. |
| `test_device_removed_is_critical` | Removed device is `CRITICAL` and is not expanded into field changes. |
| `test_interface_address_change_has_before_after_and_evidence` | IP change carries both values and both evidence strings. |
| `test_subnet_mask_change_is_warning_and_description_is_info` | Severity split between mask (`WARNING`) and description (`INFO`). |
| `test_route_added` | Route present only after is `ADDED` with evidence from both sides. |
| `test_route_removed` | Route present only before is `REMOVED`. |
| `test_identical_networks_produce_no_changes` | Empty `changes`, positive `unchanged_count`. |
| `test_router_1_never_merged_with_router_10` | Boundary matching; one added, one removed, no pairing. |
| `test_ambiguous_device_name_is_reported_and_not_diffed` | Ambiguous name in `ambiguous_devices`, absent from every other list. |
| `test_duplicate_claims_are_reported_not_silently_resolved` | Two after-side claimants on one before-side device are both ambiguous. |
| `test_display_name_alias_matches_placeholder_keyed_device` | `[[pr3-rt_Display_name]]` ↔ `Node One Router` pairs correctly. |
| `test_removed_device_is_not_expanded_into_interface_or_route_changes` | Removal stays a single presence change. |

Run them with:

```bash
cd ~/CiscoTrident && .venv/bin/python -m pytest tests/test_phase2/test_diff.py -q
cd ~/CiscoTrident && .venv/bin/python -m ruff check trident/diff tests/test_phase2
```

---

## 7. Non-goals

* **No remediation advice.** The diff says what changed, not what to do about
  it. Remediation lives in `trident/remediation`.
* **No AI.** No model call is made, so every result is reproducible byte for
  byte from the two inputs.
* **No cross-snapshot inference.** A device that exists on one side only is
  reported as added or removed, not reconstructed.
* **No modification of inputs.** Both `NetworkModel` objects are read only.
