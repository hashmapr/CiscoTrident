"""Safe, reversible remediation for diagnosed faults.

Remediation is the only part of the assessment pipeline that may change
anything, so it is built around three non-negotiable rules:

1. **Read-only is the default.** :func:`read_only_plan` renders what *would* be
   done and touches nothing. Applying requires an explicit call to
   :func:`apply_to_copy`.
2. **The source is never modified.** :func:`apply_to_copy` reads the source into
   memory, edits a deep copy, and writes a distinct destination. It hashes the
   source before and after and refuses a destination that resolves to the source.
3. **Every change is reversible.** The change log records the old value for every
   edit, and :func:`rollback` restores the original payload to the copy.

One change is planned per root cause, not per victim requirement: five hosts
behind one shut port are one ``no shutdown``, not five.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CHANGE_KINDS = ("add_route", "fix_gateway", "no_shutdown", "fix_vlan", "fix_acl")

_KIND_ALIASES = {
    "no_shutdown": "no_shutdown",
    "shutdown": "no_shutdown",
    "admin_shutdown": "no_shutdown",
    "administratively_down": "no_shutdown",
    "interface_down": "no_shutdown",
    "add_route": "add_route",
    "route": "add_route",
    "missing_route": "add_route",
    "missing_forward_route": "add_route",
    "missing_return_route": "add_route",
    "unreachable_next_hop": "add_route",
    "routing_loop": "add_route",
    "fix_gateway": "fix_gateway",
    "gateway": "fix_gateway",
    "wrong_gateway": "fix_gateway",
    "gateway_unowned": "fix_gateway",
    "default_gateway": "fix_gateway",
    "fix_vlan": "fix_vlan",
    "vlan": "fix_vlan",
    "wrong_vlan": "fix_vlan",
    "trunk": "fix_vlan",
    "trunk_vlan_gap": "fix_vlan",
    "vlan_missing": "fix_vlan",
    "vlan_mismatch": "fix_vlan",
    "vlan_membership": "fix_vlan",
    "vlan_subnet_mismatch": "fix_vlan",
    "fix_acl": "fix_acl",
    "acl": "fix_acl",
    "acl_deny": "fix_acl",
    "isolation_violation": "fix_acl",
}

_HEADER_PREFIXES = (
    "interface ",
    "vlan ",
    "router ",
    "line ",
    "ip route ",
    "ip default-gateway ",
    "ip dhcp pool ",
    "ip routing",
    "access-list ",
    "hostname ",
    "spanning-tree ",
    "username ",
    "enable ",
    "service ",
    "banner ",
    "logging ",
    "clock ",
    "ntp ",
    "snmp-server ",
    "crypto ",
    "aaa ",
)


@dataclass(frozen=True)
class Change:
    """One proposed change, derived from a finding -- never invented."""

    device: str
    interface: str | None
    kind: str
    current: object = None
    proposed: object = None
    rationale: str = ""
    requirement_it_fixes: str = ""

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "interface": self.interface,
            "kind": self.kind,
            "current": self.current,
            "proposed": self.proposed,
            "rationale": self.rationale,
            "requirement_it_fixes": self.requirement_it_fixes,
        }


@dataclass
class ChangeRecord:
    """What one applied change replaced, so it can be undone."""

    device: str
    interface: str | None
    kind: str
    old: object
    new: object
    requirement_it_fixes: str = ""

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "interface": self.interface,
            "kind": self.kind,
            "old": self.old,
            "new": self.new,
            "requirement_it_fixes": self.requirement_it_fixes,
        }


@dataclass
class ChangeLog:
    """A reversible record of everything applied to an isolated copy."""

    source: str | None
    dest: str
    source_sha256_before: str
    source_sha256_after: str
    entries: list[ChangeRecord] = field(default_factory=list)
    #: Exact bytes of the original source payload. Used by ``rollback`` to
    #: restore the copy byte-for-byte.
    original_payload: bytes = field(default=b"", repr=False)
    format: str = "json"

    @property
    def source_unchanged(self) -> bool:
        return self.source_sha256_before == self.source_sha256_after

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "dest": self.dest,
            "source_sha256_before": self.source_sha256_before,
            "source_sha256_after": self.source_sha256_after,
            "source_unchanged": self.source_unchanged,
            "format": self.format,
            "entries": [entry.as_dict() for entry in self.entries],
        }


# ---------------------------------------------------------------------------
# Finding normalisation
# ---------------------------------------------------------------------------


def _get(source, *names, default=None):
    if isinstance(source, dict):
        for name in names:
            value = source.get(name)
            if value is not None:
                return value
        return default
    for name in names:
        value = getattr(source, name, None)
        if value is not None:
            return value
    return default


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _nullable(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "n/a", "-"}:
        return None
    return text


def _normalise(finding) -> dict:
    requirement = _get(finding, "requirement", "requirement_id")
    if isinstance(requirement, dict):
        source = (requirement.get("src") or {}).get("device", "")
        destination = (requirement.get("dst") or {}).get("device", "")
        requirement = f"{source} -> {destination}"
    return {
        "device": str(_get(finding, "device", "host", default="") or ""),
        "interface": _nullable(_get(finding, "interface", "port")),
        "kind": str(_get(finding, "kind", "category", "fault_kind", default="") or ""),
        "detail": str(_get(finding, "detail", "description", "message", default="") or ""),
        "affected": [str(item) for item in _as_list(_get(finding, "affected", "requirements"))],
        "requirement": _nullable(requirement),
        "current": _get(finding, "current", "old", "observed"),
        "correction": _get(finding, "proposed_correction", "correction", "fix"),
    }


def _corr_get(correction, *names, default=None):
    if correction is None:
        return default
    if isinstance(correction, dict):
        for name in names:
            if correction.get(name) is not None:
                return correction[name]
        return default
    for name in names:
        value = getattr(correction, name, None)
        if value is not None:
            return value
    return default


def _kind_family(kind: str) -> str:
    text = (kind or "").lower()
    if "shutdown" in text or "interface_down" in text:
        return "shutdown"
    if "acl" in text or "isolation" in text:
        return "acl"
    if "gateway" in text:
        return "gateway"
    if "vlan" in text or "trunk" in text:
        return "vlan"
    if "route" in text or "next_hop" in text or "loop" in text or text == "unreachable":
        return "route"
    return "other"


def _norm_kind(kind) -> str | None:
    if not kind:
        return None
    text = re.sub(r"[\s\-]+", "_", str(kind).strip().lower())
    if text in _KIND_ALIASES:
        return _KIND_ALIASES[text]
    family = _kind_family(text)
    return {
        "shutdown": "no_shutdown",
        "route": "add_route",
        "gateway": "fix_gateway",
        "vlan": "fix_vlan",
        "acl": "fix_acl",
    }.get(family)


# ---------------------------------------------------------------------------
# Correction parsing
# ---------------------------------------------------------------------------


def _route_line(prefix: str, next_hop: str | None = None) -> str | None:
    try:
        network = ipaddress.IPv4Network(prefix, strict=False)
    except ValueError:
        return None
    line = f"ip route {network.network_address} {network.netmask}"
    return f"{line} {next_hop}" if next_hop else line


def _parse_correction(text: str) -> tuple[str | None, object]:
    """Derive (kind, proposed value) from a human-readable correction string."""
    low = text.lower()
    if "no shutdown" in low:
        return "no_shutdown", "no shutdown"
    if "default gateway" in low:
        match = re.search(r"\bto\s+(\d+\.\d+\.\d+\.\d+)", text, re.IGNORECASE)
        return "fix_gateway", match.group(1) if match else None
    if "add a route" in low or "static route" in low:
        prefix = re.search(r"for\s+(\d+\.\d+\.\d+\.\d+/\d+)", text, re.IGNORECASE)
        next_hop = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", text, re.IGNORECASE)
        if prefix:
            return "add_route", _route_line(prefix.group(1), next_hop.group(1) if next_hop else None)
        return "add_route", None
    if "vlan" in low and ("assign" in low or "membership" in low):
        match = re.search(r"vlan\s+(\d+)", text, re.IGNORECASE)
        return "fix_vlan", match.group(1) if match else None
    if "acl" in low or "access-list" in low or "permit" in low or "deny" in low:
        return "fix_acl", None
    return None, None


def _default_proposal(kind: str):
    if kind == "no_shutdown":
        return "no shutdown"
    return None


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def _freeze(value) -> str:
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    return repr(value)


def plan(findings) -> list[Change]:
    """One :class:`Change` per root cause, derived from each finding's correction.

    Victims are collapsed: two findings that name the same device, interface and
    kind produce one change. No change is emitted for a finding with no device,
    and no correction value is invented when the finding does not supply one.
    """
    changes: list[Change] = []
    seen: set[tuple] = set()

    for raw in findings or []:
        finding = _normalise(raw)
        if not finding["device"]:
            continue
        correction = finding["correction"]

        kind = _norm_kind(_corr_get(correction, "kind", "action", "type", "change")) if not isinstance(
            correction, str
        ) else None
        proposed = _corr_get(
            correction, "proposed", "proposed_value", "actual", "expected", "new", "value", "command"
        )

        if isinstance(correction, str):
            parsed_kind, parsed_value = _parse_correction(correction)
            if kind is None:
                kind = parsed_kind
            if proposed is None:
                proposed = parsed_value

        if kind is None:
            kind = _norm_kind(finding["kind"])
        if kind is None:
            continue
        if proposed is None:
            proposed = _default_proposal(kind)

        device = _corr_get(correction, "device", "host") or finding["device"]
        interface = _corr_get(correction, "interface", "port")
        if interface is None:
            interface = finding["interface"]
        current = _corr_get(correction, "current", "old", "observed")
        if current is None:
            current = finding["current"]
        rationale = _corr_get(correction, "rationale", "reason")
        if not rationale:
            rationale = finding["detail"] or (correction if isinstance(correction, str) else "")
        requirement = (
            _corr_get(correction, "requirement", "requirement_it_fixes", "fixes")
            or finding["requirement"]
            or (finding["affected"][0] if finding["affected"] else "")
        )

        key = (str(device), _nullable(interface), kind, _freeze(proposed))
        if key in seen:
            continue
        seen.add(key)
        changes.append(
            Change(
                device=str(device),
                interface=_nullable(interface),
                kind=kind,
                current=current,
                proposed=proposed,
                rationale=str(rationale or ""),
                requirement_it_fixes=str(requirement or ""),
            )
        )
    return changes


# ---------------------------------------------------------------------------
# Config text editing
# ---------------------------------------------------------------------------


def _is_header(line: str) -> bool:
    stripped = line.strip().lower()
    if not stripped:
        return False
    if stripped == "end":
        return True
    return stripped.startswith(_HEADER_PREFIXES)


def _block_bounds(lines: list[str], interface: str, device: str) -> tuple[int, int]:
    target = f"interface {interface}".lower()
    for index, line in enumerate(lines):
        if line.strip().lower() != target:
            continue
        end = index + 1
        while end < len(lines) and not _is_header(lines[end]):
            end += 1
        return index + 1, end
    raise ValueError(f"no interface {interface} on {device}")


def _insert_global(lines: list[str], new_line: str) -> None:
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip().lower() == "end":
            lines.insert(index, new_line)
            return
    lines.append(new_line)


def _interface_edit(
    lines: list[str],
    change: Change,
    matches,
    new_line: str,
) -> tuple[list[str], object, str]:
    if not change.interface:
        return lines, change.current if change.current is not None else "(not present)", new_line
    start, end = _block_bounds(lines, change.interface, change.device)
    for index in range(start, end):
        stripped = lines[index].strip()
        if matches(stripped):
            old = lines[index]
            indent = " " if lines[index][:1].isspace() else ""
            lines[index] = indent + new_line
            return lines, old, new_line
    old = change.current if change.current is not None else "(not present)"
    lines.insert(end, new_line)
    return lines, old, new_line


def _route_identity(line: str) -> tuple[str, ...]:
    tokens = line.strip().split()
    return tuple(token.lower() for token in tokens[:3])


def _proposal_gateway(proposed) -> str | None:
    if isinstance(proposed, dict):
        value = proposed.get("gateway") or proposed.get("address") or proposed.get("value")
        return str(value) if value else None
    return _nullable(proposed)


def _proposal_vlan(proposed) -> str | None:
    if isinstance(proposed, dict):
        value = proposed.get("vlan") or proposed.get("number") or proposed.get("value")
        return str(value) if value is not None else None
    text = _nullable(proposed)
    if text and text.lower().startswith("switchport access vlan"):
        text = text.split()[-1]
    return text


def _apply_change(lines: list[str], change: Change) -> tuple[list[str], object, object]:
    if change.kind == "no_shutdown":
        return _interface_edit(
            lines,
            change,
            lambda stripped: stripped.lower() in {"shutdown", "no shutdown"},
            "no shutdown",
        )

    if change.kind == "add_route":
        new_line = change.proposed
        if isinstance(new_line, dict):
            new_line = _route_line(
                str(new_line.get("destination") or new_line.get("prefix") or ""),
                str(new_line.get("next_hop") or new_line.get("gateway") or "") or None,
            )
        if not isinstance(new_line, str) or not new_line.strip():
            return lines, change.current if change.current is not None else "(not present)", None
        new_line = new_line.strip()
        if not new_line.lower().startswith("ip route "):
            new_line = f"ip route {new_line}"
        identity = _route_identity(new_line)
        for index, line in enumerate(lines):
            if line.strip().lower().startswith("ip route ") and _route_identity(line) == identity:
                old = line
                lines[index] = new_line
                return lines, old, new_line
        old = change.current if change.current is not None else "(not present)"
        _insert_global(lines, new_line)
        return lines, old, new_line

    if change.kind == "fix_gateway":
        gateway = _proposal_gateway(change.proposed)
        if not gateway:
            return lines, change.current if change.current is not None else "(not present)", None
        new_line = f"ip default-gateway {gateway}"
        for index, line in enumerate(lines):
            if line.strip().lower().startswith("ip default-gateway "):
                old = line
                lines[index] = new_line
                return lines, old, new_line
        old = change.current if change.current is not None else "(not present)"
        _insert_global(lines, new_line)
        return lines, old, new_line

    if change.kind == "fix_vlan":
        vlan = _proposal_vlan(change.proposed)
        if not vlan:
            return lines, change.current if change.current is not None else "(not present)", None
        new_line = f"switchport access vlan {vlan}"
        return _interface_edit(
            lines,
            change,
            lambda stripped: stripped.lower().startswith("switchport access vlan"),
            new_line,
        )

    if change.kind == "fix_acl":
        new_line = change.proposed
        if not isinstance(new_line, str) or not new_line.strip():
            return lines, change.current if change.current is not None else "(not present)", None
        new_line = new_line.strip()
        current = str(change.current).strip().lower() if change.current is not None else None
        for index, line in enumerate(lines):
            stripped = line.strip().lower()
            if current and stripped == current:
                old = line
                lines[index] = new_line
                return lines, old, new_line
            if not current and stripped.startswith("access-list ") and " deny " in f" {stripped} ":
                old = line
                lines[index] = new_line
                return lines, old, new_line
        old = change.current if change.current is not None else "(not present)"
        _insert_global(lines, new_line)
        return lines, old, new_line

    return lines, change.current if change.current is not None else "(not present)", None


# ---------------------------------------------------------------------------
# Source loading / writing
# ---------------------------------------------------------------------------


def _normalise_configs(payload) -> dict[str, list[str]]:
    if not isinstance(payload, dict):
        raise TypeError("config payload must be a mapping of device name to lines")
    configs: dict[str, list[str]] = {}
    for device, lines in payload.items():
        if isinstance(lines, str):
            configs[str(device)] = lines.splitlines()
        elif isinstance(lines, (list, tuple)):
            configs[str(device)] = [str(line) for line in lines]
        else:
            raise TypeError(f"config for {device!r} must be a list of lines or a string")
    return configs


def _load_source(spec):
    """Return (configs, original payload bytes, format, source path, source hash)."""
    if spec is None:
        payload = json.dumps({}, sort_keys=True).encode("utf-8")
        return {}, payload, "json", None, hashlib.sha256(payload).hexdigest()

    if isinstance(spec, (str, Path)):
        path = Path(spec)
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        if path.suffix.lower() == ".json":
            configs = _normalise_configs(json.loads(payload.decode("utf-8")))
            return configs, payload, "json", path, digest
        return {"__single__": payload.decode("utf-8").splitlines()}, payload, "text", path, digest

    if hasattr(spec, "devices") and hasattr(spec, "faults"):
        try:
            from ..labgen.faults import intended_configs
        except ImportError as exc:  # pragma: no cover - labgen is a hard dependency here
            raise ValueError("cannot read a TopologySpec: labgen is unavailable") from exc
        configs = _normalise_configs(intended_configs(spec))
        payload = json.dumps(configs, sort_keys=True).encode("utf-8")
        return configs, payload, "json", None, hashlib.sha256(payload).hexdigest()

    if isinstance(spec, dict):
        configs = _normalise_configs(spec)
        payload = json.dumps(configs, sort_keys=True).encode("utf-8")
        return configs, payload, "json", None, hashlib.sha256(payload).hexdigest()

    raise TypeError(f"unsupported spec type: {type(spec).__name__}")


def _write_configs(configs: dict[str, list[str]], path: Path, fmt: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(json.dumps(configs, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    if set(configs) == {"__single__"}:
        path.write_text("\n".join(configs["__single__"]) + "\n", encoding="utf-8")
        return
    parts: list[str] = []
    for device, lines in configs.items():
        parts.append(f"! ==== {device} ====")
        parts.extend(lines)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Applying / rolling back
# ---------------------------------------------------------------------------


def apply_to_copy(spec, changes, dest) -> tuple[Path, ChangeLog]:
    """Apply ``changes`` to a copy of ``spec``, never to the source.

    ``spec`` may be a path to a JSON/text config bundle, a ``TopologySpec``, a
    mapping of device name to config lines, or ``None`` (build a fresh bundle).
    Returns the destination path and a reversible :class:`ChangeLog`.
    """
    configs, original_payload, fmt, source_path, digest_before = _load_source(spec)
    snapshot_before = hashlib.sha256(
        json.dumps(configs, sort_keys=True).encode("utf-8")
    ).hexdigest()

    destination = Path(dest)
    if source_path is not None:
        try:
            if destination.resolve() == source_path.resolve():
                raise ValueError(
                    "refusing to apply remediation to the source file; pass a distinct destination"
                )
        except OSError:
            pass

    working = copy.deepcopy(configs)
    fresh = source_path is None and not configs
    records: list[ChangeRecord] = []
    for change in changes or []:
        if not isinstance(change, Change):
            raise TypeError(f"changes must be Change instances, got {type(change).__name__}")

        key = change.device
        if key not in working:
            if set(working) <= {"__single__"} and "__single__" in working:
                key = "__single__"
            elif fresh:
                working[change.device] = []
            else:
                raise ValueError(
                    f"change targets unknown device {change.device!r}; refusing to invent a device"
                )
        if fresh and change.interface and change.kind in {"no_shutdown", "fix_vlan"}:
            header = f"interface {change.interface}"
            if not any(line.strip().lower() == header.lower() for line in working[key]):
                working[key].append(header)
        lines, old, new = _apply_change(list(working[key]), change)
        working[key] = lines
        records.append(
            ChangeRecord(
                device=change.device,
                interface=change.interface,
                kind=change.kind,
                old=old if old is not None else "(not present)",
                new=new,
                requirement_it_fixes=change.requirement_it_fixes,
            )
        )

    _write_configs(working, destination, fmt)

    snapshot_after = hashlib.sha256(
        json.dumps(configs, sort_keys=True).encode("utf-8")
    ).hexdigest()
    digest_after = (
        hashlib.sha256(source_path.read_bytes()).hexdigest() if source_path is not None else snapshot_after
    )
    if snapshot_before != snapshot_after or (source_path is not None and digest_before != digest_after):
        raise RuntimeError("source was modified during remediation; this is a safety defect")

    log = ChangeLog(
        source=str(source_path) if source_path is not None else None,
        dest=str(destination),
        source_sha256_before=digest_before,
        source_sha256_after=digest_after,
        entries=records,
        original_payload=original_payload,
        format=fmt,
    )
    return destination, log


def rollback(log: ChangeLog) -> dict:
    """Restore the copy's original payload, leaving the source untouched."""
    if log.source:
        source = Path(log.source)
        if source.exists():
            current = hashlib.sha256(source.read_bytes()).hexdigest()
            if current != log.source_sha256_before:
                raise RuntimeError("source file changed after the change log was recorded")

    destination = Path(log.dest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(log.original_payload)
    return {
        "restored": str(destination),
        "entries": len(log.entries),
        "sha256": hashlib.sha256(log.original_payload).hexdigest(),
        "source_unchanged": log.source_unchanged,
    }


# ---------------------------------------------------------------------------
# Outcome comparison
# ---------------------------------------------------------------------------


def _root_key(finding: dict) -> tuple[str, str | None, str]:
    return (finding["device"], _nullable(finding["interface"]), _kind_family(finding["kind"]))


def verify_remediation(original_findings, post_findings) -> dict:
    """Count fixed, still-broken and newly introduced regressions.

    A change that makes a finding disappear but introduces a *new* finding on the
    same device (or the same affected requirement) is reported as a regression,
    and the disappeared finding is **not** counted as fixed.
    """
    original = [_normalise(finding) for finding in (original_findings or [])]
    post = [_normalise(finding) for finding in (post_findings or [])]
    original_by = {_root_key(finding): finding for finding in original}
    post_by = {_root_key(finding): finding for finding in post}

    still = [key for key in original_by if key in post_by]
    gone = [key for key in original_by if key not in post_by]
    new = [key for key in post_by if key not in original_by]

    regression_originals: set[tuple] = set()
    regressions: list[dict] = []
    for key in new:
        finding = post_by[key]
        attributed = None
        for gone_key in gone:
            if gone_key in regression_originals:
                continue
            original_finding = original_by[gone_key]
            if (
                original_finding["device"] == finding["device"]
                or set(original_finding["affected"]) & set(finding["affected"])
            ):
                attributed = gone_key
                break
        if attributed is not None:
            regression_originals.add(attributed)
        regressions.append(
            {
                **finding,
                "attributed_to": original_by[attributed] if attributed is not None else None,
            }
        )

    fixed = [key for key in gone if key not in regression_originals]
    return {
        "fixed": len(fixed),
        "still_broken": len(still),
        "introduced_regressions": len(regressions),
        "fixed_findings": [original_by[key] for key in fixed],
        "still_broken_findings": [original_by[key] for key in still],
        "regressions": regressions,
    }


# ---------------------------------------------------------------------------
# Read-only plan (the default)
# ---------------------------------------------------------------------------


def read_only_plan(findings) -> str:
    """Markdown remediation plan. Changes nothing; writes no file."""
    changes = plan(findings)
    lines = [
        "# Remediation plan (READ-ONLY)",
        "",
        "No changes have been applied. This plan is informational; applying it requires an",
        "explicit call to `apply_to_copy` against an isolated copy.",
        "",
    ]
    if not changes:
        lines.append("No actionable remediation could be derived from the findings.")
        return "\n".join(lines)

    for index, change in enumerate(changes, 1):
        target = change.device
        if change.interface:
            target += f" {change.interface}"
        lines.append(f"## {index}. {target} -- `{change.kind}`")
        lines.append("")
        current = "(not recorded)" if change.current is None else str(change.current)
        proposed = (
            "requires an operator-supplied value (not invented by the planner)"
            if change.proposed is None
            else str(change.proposed)
        )
        lines.append(f"- current: `{current}`")
        lines.append(f"- proposed: `{proposed}`")
        if change.requirement_it_fixes:
            lines.append(f"- fixes: {change.requirement_it_fixes}")
        if change.rationale:
            lines.append(f"- rationale: {change.rationale}")
        lines.append("")

    lines.append(
        f"_{len(changes)} change(s) planned. Read-only mode made no modification._"
    )
    return "\n".join(lines)
