"""Before/after network comparison for TRIDENT.

The engine compares two ``NetworkModel`` snapshots and reports *field-level*
differences, each carrying the evidence string from both sides. Design rules:

* Device matching is deterministic and conservative. Exact name wins, then
  hostname, then display-name alias. A name that matches more than one device is
  reported as ambiguous and is **not** diffed.
* Matching is never substring-based, so ``Router-1`` can never be paired with
  ``Router-10``. Alias resolution delegates to
  :func:`trident.reasoning.entities.resolve_device_name`, which is
  boundary-aware and reports ambiguity instead of guessing.
* A field that is unobservable in *both* snapshots is neither reported as a
  change nor counted as unchanged — silence is not agreement.
* An emitted change always has both evidence strings populated. Absence is
  spelled out (``"... absent in before snapshot"``) rather than left blank.
* Devices that are added or removed produce exactly one presence change. Their
  interfaces and routes are not enumerated separately, because they are not
  comparable across the two snapshots.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import DeviceInfo, InterfaceInfo, NetworkModel, RouteInfo
from ..reasoning.entities import resolve_device_name
from .types import ChangeKind, DiffResult, FieldChange, Severity

__all__ = ["DEVICE_FIELDS", "INTERFACE_FIELDS", "compare"]

#: Device-level fields compared for every matched device pair.
DEVICE_FIELDS: tuple[str, ...] = ("hostname", "model", "ios_version")

#: Interface-level fields compared for every matched interface pair.
INTERFACE_FIELDS: tuple[str, ...] = (
    "ipv4_address",
    "subnet_mask",
    "prefix_length",
    "admin_state",
    "operational_state",
    "description",
    "vlan_assignments",
)

#: Severity per field. Documented in ``docs/phase2/NETWORK_DIFF.md``.
#:
#: ``hostname`` and ``description`` are cosmetic, so they are ``INFO``. Address
#: and mask fields change reachability, so they are ``WARNING``. Device removal
#: is handled separately and is ``CRITICAL``.
_FIELD_SEVERITY: dict[str, Severity] = {
    "hostname": Severity.INFO,
    "model": Severity.INFO,
    "ios_version": Severity.INFO,
    "description": Severity.INFO,
    "ipv4_address": Severity.WARNING,
    "subnet_mask": Severity.WARNING,
    "prefix_length": Severity.WARNING,
    "vlan_assignments": Severity.WARNING,
    "admin_state": Severity.WARNING,
    "operational_state": Severity.WARNING,
    "interface": Severity.WARNING,
    "route": Severity.WARNING,
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(value: str | None) -> str:
    return _SLUG_RE.sub("_", (value or "").strip().lower()).strip("_")


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def _label(key: str, dev: DeviceInfo) -> str:
    return (dev.name or key).strip() or key


# ---------------------------------------------------------------------------
# Device matching
# ---------------------------------------------------------------------------


def _device_names(model: NetworkModel) -> list[str]:
    """Every name a device can be referred to by: key and ``DeviceInfo.name``."""
    names: set[str] = set()
    for key, dev in model.devices.items():
        if key:
            names.add(key)
        if dev.name:
            names.add(dev.name)
    return sorted(names)


def _hostname_map(model: NetworkModel) -> dict[str, str]:
    """hostname -> device key (first writer wins; collisions surface as ambiguity)."""
    out: dict[str, str] = {}
    for key, dev in model.devices.items():
        if dev.hostname and _norm(dev.hostname):
            out.setdefault(_norm(dev.hostname), key)
    return out


def _raw_stem(raw: str) -> str:
    """``pr3-rt_Display_name`` -> ``pr3-rt`` (the device-facing placeholder stem)."""
    text = (raw or "").strip()
    lowered = text.lower()
    for suffix in ("_display_name", "_displayname"):
        if lowered.endswith(suffix):
            return text[: -len(suffix)].strip()
    return text


def _display_aliases(model: NetworkModel, key: str) -> set[str]:
    """Display names that the snapshot placeholder table attaches to a device.

    A placeholder such as ``pr3-rt_Display_name`` maps to a human name
    (``Node One Router``). Devices may appear keyed by either side of that
    mapping, so both directions are honoured, including the stem form
    (``pr3-rt``) used as a device key.
    """
    dev = model.devices.get(key)
    own = {_slug(v) for v in (key, dev.name if dev else None, dev.hostname if dev else None) if v}
    own.discard("")
    aliases: set[str] = set()
    for raw, resolved in (model.placeholder_map or {}).items():
        stem = _raw_stem(raw)
        raw_slugs = {_slug(raw), _slug(stem)} - {""}
        resolved_slug = _slug(resolved)
        if not resolved_slug and not raw_slugs:
            continue
        if resolved_slug and resolved_slug in own:
            # Device is named by the display name: expose the raw forms.
            aliases.add(resolved or "")
            aliases.add(raw or "")
            aliases.add(stem or "")
            continue
        if raw_slugs & own:
            # Device is keyed by the placeholder (raw or stem): expose the name.
            aliases.add(resolved or "")
    aliases.discard("")
    return aliases


def _name_candidates(before: NetworkModel, after_key: str, after_dev: DeviceInfo) -> list[str]:
    """Tier 1: exact name equality (case-insensitive, no substring logic)."""
    wanted = {_norm(after_key), _norm(after_dev.name)} - {""}
    hits: list[str] = []
    for key, dev in before.devices.items():
        names = {_norm(key), _norm(dev.name)} - {""}
        if names & wanted:
            hits.append(key)
    return sorted(set(hits))


def _hostname_candidates(
    before: NetworkModel, after_dev: DeviceInfo, taken: set[str]
) -> list[str]:
    """Tier 2: hostname equality against hostname or name on the before side."""
    wanted = {_norm(after_dev.hostname)} - {""}
    if not wanted:
        return []
    hits: list[str] = []
    for key, dev in before.devices.items():
        if key in taken:
            continue
        names = {_norm(key), _norm(dev.name), _norm(dev.hostname)} - {""}
        if names & wanted:
            hits.append(key)
    return sorted(set(hits))


def _alias_candidates(
    before: NetworkModel,
    after: NetworkModel,
    after_key: str,
    taken: set[str],
    before_names: list[str],
    before_hosts: dict[str, str],
) -> list[str]:
    """Tier 3: display-name alias, resolved boundary-aware against before names."""
    after_dev = after.devices[after_key]
    aliases = _display_aliases(after, after_key) | _display_aliases(after, after_dev.name)
    hits: set[str] = set()
    for alias in sorted(aliases):
        if alias in before.devices:
            hits.add(alias)
            continue
        res = resolve_device_name(before_names, alias, before_hosts)
        if res.resolved and res.name is not None:
            key = res.name if res.name in before.devices else before_hosts.get(_norm(res.name), res.name)
            if key in before.devices:
                hits.add(key)
        elif res.ambiguous:
            # Boundary-aware resolution found several equally good names.
            for cand in res.candidates:
                key = cand if cand in before.devices else before_hosts.get(_norm(cand), cand)
                if key in before.devices:
                    hits.add(key)
    # Last resort: compare alias slugs with the before device's own aliases.
    if not hits:
        after_slugs = {_slug(a) for a in aliases} - {""}
        if after_slugs:
            for key in before.devices:
                if key in taken:
                    continue
                own = {_slug(key), _slug(before.devices[key].name)} - {""}
                own |= {_slug(a) for a in _display_aliases(before, key)} - {""}
                if after_slugs & own:
                    hits.add(key)
    return sorted(k for k in hits if k not in taken)


def _match_devices(
    before: NetworkModel, after: NetworkModel
) -> tuple[dict[str, str], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Return ``(after_key -> before_key, added, removed, ambiguous)``.

    ``ambiguous`` holds the names that could not be matched safely. Those
    devices are neither diffed nor reported as added.
    """
    pairs: dict[str, str] = {}
    ambiguous_keys: set[str] = set()
    contested: set[str] = set()
    claimed: dict[str, str] = {}
    before_names = _device_names(before)
    before_hosts = _hostname_map(before)

    def mark_ambiguous(after_keys: list[str]) -> None:
        for key in after_keys:
            ambiguous_keys.add(key)
            pairs.pop(key, None)

    def claim(after_key: str, candidates: list[str]) -> bool:
        """Pair an after device with exactly one before device, or mark ambiguity."""
        candidates = sorted(set(candidates))
        if len(candidates) > 1:
            # Ambiguity is decided before any contested-target pruning, so a
            # later device cannot be silently paired with one of these.
            mark_ambiguous([after_key])
            contested.update(candidates)
            return False
        if not candidates:
            return False
        target = candidates[0]
        if target in contested:
            # The only candidate is already contested by another device.
            mark_ambiguous([after_key])
            return False
        prior = claimed.get(target)
        if prior is None:
            claimed[target] = after_key
            pairs[after_key] = target
            return True
        if prior != after_key:
            # Two after-side devices claim the same before-side device.
            del claimed[target]
            contested.add(target)
            mark_ambiguous([prior, after_key])
        return False

    def unpaired() -> list[str]:
        return [k for k in after.devices if k not in pairs and k not in ambiguous_keys]

    # Tier 1 - exact name.
    for after_key in unpaired():
        claim(after_key, _name_candidates(before, after_key, after.devices[after_key]))

    # Tier 2 - hostname.
    taken = set(claimed) | contested
    for after_key in unpaired():
        if claim(after_key, _hostname_candidates(before, after.devices[after_key], taken)):
            taken.add(pairs[after_key])

    # Tier 3 - display-name alias.
    for after_key in unpaired():
        taken = set(claimed) | contested
        claim(after_key, _alias_candidates(before, after, after_key, taken, before_names, before_hosts))

    matched_before = set(claimed)
    added = tuple(sorted(k for k in after.devices if k not in pairs and k not in ambiguous_keys))
    removed = tuple(sorted(k for k in before.devices if k not in matched_before and k not in contested))
    ambiguous = tuple(sorted({_label(k, after.devices[k]) for k in ambiguous_keys}))
    return pairs, added, removed, ambiguous


# ---------------------------------------------------------------------------
# Interface enumeration
# ---------------------------------------------------------------------------


def _device_interfaces(model: NetworkModel, device_key: str) -> dict[str, InterfaceInfo]:
    """Interfaces belonging to one device, keyed by normalised canonical name.

    A duplicated canonical name (two records claiming the same port) is dropped
    rather than resolved arbitrarily.
    """
    dev = model.devices[device_key]
    collected: list[InterfaceInfo] = []
    seen: set[int] = set()

    def add(info: InterfaceInfo | None) -> None:
        if info is None or id(info) in seen:
            return
        seen.add(id(info))
        collected.append(info)

    for canon in dev.interfaces:
        add(model.interfaces.get(f"{dev.name}:{canon}"))
        add(model.interfaces.get(f"{device_key}:{canon}"))
        add(model.interfaces.get(canon))

    for key, info in model.interfaces.items():
        if info.device in (dev.name, device_key) or key.startswith(f"{dev.name}:"):
            add(info)

    out: dict[str, InterfaceInfo] = {}
    duplicates: set[str] = set()
    for info in collected:
        canon = _norm(info.canonical_name or info.name)
        if not canon:
            continue
        if canon in out:
            duplicates.add(canon)
        else:
            out[canon] = info
    for dup in duplicates:
        out.pop(dup, None)
    return out


# ---------------------------------------------------------------------------
# Value + evidence helpers
# ---------------------------------------------------------------------------


def _field_value(obj: Any, field: str) -> str | None:
    """Render one field as a comparable string, or ``None`` when unobservable."""
    value = getattr(obj, field, None)
    if field == "vlan_assignments":
        items = sorted({str(v).strip() for v in (value or []) if str(v).strip()})
        return ", ".join(items) if items else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _device_evidence(device: str, field: str, value: str | None, side: str) -> str:
    if value is None:
        return f"{device}: DeviceInfo.{field} absent in {side} snapshot"
    return f"{device}: DeviceInfo.{field} = {value!r} ({side} snapshot)"


def _interface_evidence(device: str, iface: str, field: str, value: str | None, side: str) -> str:
    if value is None:
        return f"{device}:{iface}: InterfaceInfo.{field} absent in {side} snapshot"
    return f"{device}:{iface}: InterfaceInfo.{field} = {value!r} ({side} snapshot)"


def _route_evidence(
    route: RouteInfo | None, device: str, destination: str, next_hop: str, side: str
) -> str:
    if route is None:
        return f"{device}: route {destination} via {next_hop} absent in {side} snapshot"
    detail = f"{device}: route {destination} via {next_hop} type={route.route_type} ({side} snapshot)"
    raw = (route.raw_config or "").strip()
    if raw:
        detail = f"{detail} raw={raw!r}"
    return detail


def _severity(field: str, kind: ChangeKind) -> Severity:
    if field == "device":
        return Severity.CRITICAL if kind is ChangeKind.REMOVED else Severity.WARNING
    base = field.split(":", 1)[0]
    return _FIELD_SEVERITY.get(base, Severity.INFO)


def _compare_fields(
    before_obj: Any,
    after_obj: Any,
    fields: tuple[str, ...],
    device: str,
    interface: str | None,
    evidence_for,
) -> tuple[list[FieldChange], int]:
    changes: list[FieldChange] = []
    unchanged = 0
    for field in fields:
        bval = _field_value(before_obj, field)
        aval = _field_value(after_obj, field)
        if bval is None and aval is None:
            # Unobservable on both sides: not agreement, not a change.
            continue
        if bval == aval:
            unchanged += 1
            continue
        if bval is None:
            kind = ChangeKind.ADDED
        elif aval is None:
            kind = ChangeKind.REMOVED
        else:
            kind = ChangeKind.MODIFIED
        changes.append(
            FieldChange(
                device=device,
                interface=interface,
                field=field,
                before=bval,
                after=aval,
                kind=kind,
                severity=_severity(field, kind),
                evidence_before=evidence_for(field, bval, "before"),
                evidence_after=evidence_for(field, aval, "after"),
            )
        )
    return changes, unchanged


def _device_summary(dev: DeviceInfo) -> str:
    bits = [f"name={dev.name!r}"]
    if dev.hostname:
        bits.append(f"hostname={dev.hostname!r}")
    if dev.device_type:
        bits.append(f"type={dev.device_type}")
    bits.append(f"interfaces={len(dev.interfaces)}")
    return ", ".join(bits)


# ---------------------------------------------------------------------------
# Route comparison
# ---------------------------------------------------------------------------


def _route_device_key(model: NetworkModel, device: str) -> str:
    """Canonicalise ``RouteInfo.device`` onto a device key when that is unambiguous."""
    if not device:
        return ""
    if device in model.devices:
        return device
    target = _norm(device)
    hits = [
        k
        for k, d in model.devices.items()
        if _norm(k) == target or _norm(d.name) == target or _norm(d.hostname) == target
    ]
    if len(hits) == 1:
        return hits[0]
    slug = _slug(device)
    hits = [k for k in model.devices if _slug(k) == slug]
    if len(hits) == 1:
        return hits[0]
    return device


def _routes_by_device(model: NetworkModel) -> dict[str, dict[tuple[str, str], RouteInfo]]:
    """``device -> (destination, next_hop) -> route`` with deterministic dedupe."""
    out: dict[str, dict[tuple[str, str], RouteInfo]] = {}
    for route in model.routes:
        device = _route_device_key(model, route.device)
        key = (_norm(route.destination), _norm(route.next_hop or ""))
        bucket = out.setdefault(device, {})
        prior = bucket.get(key)
        if prior is None:
            bucket[key] = route
        elif prior.route_type != route.route_type:
            merged = "|".join(sorted({prior.route_type or "", route.route_type or ""} - {""}))
            bucket[key] = prior.model_copy(update={"route_type": merged or prior.route_type})
    return out


def _compare_routes(
    before: NetworkModel, after: NetworkModel, pairs: dict[str, str]
) -> tuple[list[FieldChange], int]:
    before_routes = _routes_by_device(before)
    after_routes = _routes_by_device(after)
    changes: list[FieldChange] = []
    unchanged = 0

    for after_key, before_key in sorted(pairs.items()):
        b_bucket = before_routes.get(before_key, {})
        a_bucket = after_routes.get(after_key, {})
        device_label = before_key if before_key == after_key else f"{before_key}->{after_key}"

        for key in sorted(set(b_bucket) | set(a_bucket)):
            destination, next_hop = key
            b_route = b_bucket.get(key)
            a_route = a_bucket.get(key)
            if b_route is not None and a_route is not None:
                unchanged += 1
                continue
            kind = ChangeKind.ADDED if b_route is None else ChangeKind.REMOVED
            present = a_route if a_route is not None else b_route
            if present is None:  # defensive: key came from one of the two buckets
                continue
            display_dest = present.destination
            display_nh = present.next_hop or "connected"
            changes.append(
                FieldChange(
                    device=device_label,
                    interface=present.outgoing_interface,
                    field=f"route:{display_dest}",
                    before=None if b_route is None else (b_route.next_hop or "connected"),
                    after=None if a_route is None else (a_route.next_hop or "connected"),
                    kind=kind,
                    severity=_severity("route", kind),
                    evidence_before=_route_evidence(b_route, before_key, display_dest, display_nh, "before"),
                    evidence_after=_route_evidence(a_route, after_key, display_dest, display_nh, "after"),
                )
            )
    return changes, unchanged


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def compare(before: NetworkModel, after: NetworkModel) -> DiffResult:
    """Compare two snapshots field by field.

    Only real differences appear in ``changes``. Identical networks therefore
    produce an empty tuple and a positive ``unchanged_count``.
    """
    pairs, added, removed, ambiguous = _match_devices(before, after)

    changes: list[FieldChange] = []
    unchanged = 0

    # --- device presence ---------------------------------------------------
    for key in added:
        changes.append(
            FieldChange(
                device=key,
                interface=None,
                field="device",
                before=None,
                after=key,
                kind=ChangeKind.ADDED,
                severity=_severity("device", ChangeKind.ADDED),
                evidence_before=f"{key}: device absent in before snapshot",
                evidence_after=f"{key}: device present in after snapshot ({_device_summary(after.devices[key])})",
            )
        )
    for key in removed:
        changes.append(
            FieldChange(
                device=key,
                interface=None,
                field="device",
                before=key,
                after=None,
                kind=ChangeKind.REMOVED,
                severity=_severity("device", ChangeKind.REMOVED),
                evidence_before=(
                    f"{key}: device present in before snapshot ({_device_summary(before.devices[key])})"
                ),
                evidence_after=f"{key}: device absent in after snapshot",
            )
        )

    # --- matched device fields + interfaces --------------------------------
    for after_key, before_key in sorted(pairs.items()):
        bdev = before.devices[before_key]
        adev = after.devices[after_key]
        device_label = before_key if before_key == after_key else f"{before_key}->{after_key}"

        dev_changes, dev_unchanged = _compare_fields(
            bdev,
            adev,
            DEVICE_FIELDS,
            device_label,
            None,
            lambda field, value, side, _label=device_label: _device_evidence(_label, field, value, side),
        )
        changes.extend(dev_changes)
        unchanged += dev_unchanged

        b_ifaces = _device_interfaces(before, before_key)
        a_ifaces = _device_interfaces(after, after_key)

        for canon in sorted(set(b_ifaces) - set(a_ifaces)):
            info = b_ifaces[canon]
            name = info.canonical_name or info.name or canon
            changes.append(
                FieldChange(
                    device=device_label,
                    interface=name,
                    field="interface",
                    before=name,
                    after=None,
                    kind=ChangeKind.REMOVED,
                    severity=_FIELD_SEVERITY["interface"],
                    evidence_before=f"{device_label}:{name}: interface present in before snapshot",
                    evidence_after=f"{device_label}:{name}: interface absent in after snapshot",
                )
            )
        for canon in sorted(set(a_ifaces) - set(b_ifaces)):
            info = a_ifaces[canon]
            name = info.canonical_name or info.name or canon
            changes.append(
                FieldChange(
                    device=device_label,
                    interface=name,
                    field="interface",
                    before=None,
                    after=name,
                    kind=ChangeKind.ADDED,
                    severity=_FIELD_SEVERITY["interface"],
                    evidence_before=f"{device_label}:{name}: interface absent in before snapshot",
                    evidence_after=f"{device_label}:{name}: interface present in after snapshot",
                )
            )

        for canon in sorted(set(b_ifaces) & set(a_ifaces)):
            b_if = b_ifaces[canon]
            a_if = a_ifaces[canon]
            iface_label = b_if.canonical_name or a_if.canonical_name or canon
            iface_changes, iface_unchanged = _compare_fields(
                b_if,
                a_if,
                INTERFACE_FIELDS,
                device_label,
                iface_label,
                lambda field, value, side, _d=device_label, _i=iface_label: _interface_evidence(
                    _d, _i, field, value, side
                ),
            )
            changes.extend(iface_changes)
            unchanged += iface_unchanged

    # --- routes ------------------------------------------------------------
    route_changes, route_unchanged = _compare_routes(before, after, pairs)
    changes.extend(route_changes)
    unchanged += route_unchanged

    return DiffResult(
        before_snapshot=before.snapshot_id,
        after_snapshot=after.snapshot_id,
        changes=tuple(changes),
        added_devices=added,
        removed_devices=removed,
        ambiguous_devices=ambiguous,
        unchanged_count=unchanged,
    )
