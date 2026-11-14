"""Read-only forensics and reconstruction for autonomous assessment.

This module is the first phase of the assessment workflow: it turns one Packet
Tracer file into a *complete, normalised, provenance-carrying* snapshot. It never
edits the input, never invents a fact, and never promotes a single-engine claim
to "consensus verified".

Design rules enforced here
--------------------------
1. **Byte preservation.** The source file is hashed before and after the run and
   the hash is asserted unchanged. Parsing happens from an in-memory copy, so a
   parser cannot rewrite the upload.
2. **Honest engine states.** Every engine appears in ``NetworkEvidence.engines``
   with its real state, including ``UNAVAILABLE`` when the engine cannot run in
   this environment.
3. **Per-fact provenance.** Every record carries the engine ids that asserted
   it. When two engines disagree about the same field, both values are recorded
   in ``discrepancies`` rather than silently choosing one.
4. **Explicit gaps.** Documented Packet Tracer limitations and capabilities lost
   to an unavailable engine are reported in ``unsupported``; nothing is dropped
   quietly.
5. **No verification claim.** ``NetworkEvidence`` is extraction, not consensus.
   The strict policy needs three distinct engines; consumers must apply
   :mod:`trident.verification.consensus` to a fact before treating it as verified.

The heavy lifting is reused from the existing pipeline (``ingest`` + ``analyze``);
this layer is a projection of the already-normalised model, not a second parser.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ..config import Settings
from ..config import settings as default_settings
from ..engined.observations import (
    PT_901_LIMITATIONS,
    SupportStatus,
    support_status,
    unsupported_reason,
)
from ..engined.reachability import classify_device
from ..ingestion import IngestedFile, ingest
from ..models import (
    AclEntry,
    DeviceInfo,
    InterfaceInfo,
    LinkInfo,
    NetworkModel,
    ParserState,
    RouteInfo,
)
from ..normalization.values import canonical_interface_name, normalize_mac
from ..parsers.base import AdapterResult
from ..pipeline import AnalysisOutcome, analyze

EVIDENCE_FILENAME = "network_evidence.json"

#: The pipeline is question-driven. Forensics reuses it with one inert question
#: and AI planning disabled, so the model is built by the real engines without
#: paying for an interpretation step nobody reads.
_FORENSICS_QUESTION = "1. Report the reconstructed network snapshot."

_MAC_FIELDS = {"mac_address", "endhost_mac"}
_IFACE_FIELDS = {"interface", "link_interface"}


class EvidenceIntegrityError(RuntimeError):
    """The source file changed during reconstruction, or could not be hashed."""


# ---------------------------------------------------------------------------
# Record types
# ---------------------------------------------------------------------------


@dataclass
class InterfaceRecord:
    """One interface as seen in the normalised model."""

    name: str
    ip: str | None = None
    mask: str | None = None
    prefix: int | None = None
    gateway: str | None = None
    admin_state: str | None = None
    vlan_assignments: list[str] = field(default_factory=list)
    access_mode: str | None = None
    native_vlan: int | None = None
    engines: list[str] = field(default_factory=list)


@dataclass
class DeviceRecord:
    """One device. ``role`` comes from ``engined.reachability.classify_device``."""

    name: str
    model: str | None
    device_type: str | None
    role: str
    interfaces: list[InterfaceRecord] = field(default_factory=list)
    config_line_count: int = 0
    engines: list[str] = field(default_factory=list)


@dataclass
class LinkRecord:
    a_device: str
    a_port: str
    b_device: str
    b_port: str
    engines: list[str] = field(default_factory=list)


@dataclass
class VlanRecord:
    """One VLAN on one device.

    ``device`` is empty when no member port, no config block and no provenance
    could attribute the VLAN to a device. That is surfaced, not guessed.
    """

    id: int
    name: str | None
    device: str
    engines: list[str] = field(default_factory=list)


@dataclass
class RouteRecord:
    device: str
    destination: str
    mask: str | None
    next_hop: str | None
    kind: str
    engines: list[str] = field(default_factory=list)


@dataclass
class AclRecord:
    device: str
    acl_id: str
    action: str
    protocol: str | None
    source: str | None
    destination: str | None
    applied_interface: str | None
    direction: str | None
    engines: list[str] = field(default_factory=list)


@dataclass
class Discrepancy:
    """One field where two engines asserted different values.

    Emitted pairwise so a reader can see ``engine_a`` vs ``engine_b`` and both
    values. An engine that asserted several values contributes them all,
    separated by ``" | "`` in its value string.
    """

    entity_type: str
    entity_id: str
    field: str
    engine_a: str
    value_a: str
    engine_b: str
    value_b: str


@dataclass
class UnsupportedItem:
    """A capability this reconstruction could not deliver, and why."""

    capability: str
    reason: str
    status: str
    source: str


@dataclass
class NetworkEvidence:
    """The complete reconstruction snapshot for one source file."""

    devices: list[DeviceRecord]
    links: list[LinkRecord]
    vlans: list[VlanRecord]
    routes: list[RouteRecord]
    acls: list[AclRecord]
    discrepancies: list[Discrepancy]
    unsupported: list[UnsupportedItem]
    engines: dict[str, dict]
    source_sha256: str
    model: NetworkModel
    source_path: str = ""
    snapshot_id: str = ""
    snapshot_ambiguous: bool = False
    consensus_policy: str = "strict"
    consensus_required: int = 3
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """JSON-serialisable form, including the full normalised model."""
        return _plain(self)


# ---------------------------------------------------------------------------
# Projection helpers
# ---------------------------------------------------------------------------


def _plain(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {spec.name: _plain(getattr(value, spec.name)) for spec in fields(value)}
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    return value


def _engines_of(provenance: list) -> list[str]:
    return sorted({p.engine for p in provenance if getattr(p, "engine", "")})


def _mask_prefix(mask: str | None) -> int | None:
    if not mask:
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _is_mask(text: str | None) -> bool:
    if not text:
        return False
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{text}")
    except ValueError:
        return False
    return "." in text


def _route_mask(route: RouteInfo) -> str | None:
    if "/" in route.destination:
        return route.destination.split("/", 1)[1] or None
    match = re.match(r"^ip\s+route\s+\S+\s+(\S+)", (route.raw_config or "").strip(), re.IGNORECASE)
    if match and _is_mask(match.group(1)):
        return match.group(1)
    return None


def _interface_record(iface: InterfaceInfo) -> InterfaceRecord:
    prefix = iface.prefix_length
    if prefix is None:
        prefix = _mask_prefix(iface.subnet_mask)
    return InterfaceRecord(
        name=iface.name,
        ip=iface.ipv4_address,
        mask=iface.subnet_mask,
        prefix=prefix,
        gateway=iface.ipv4_gateway,
        admin_state=iface.admin_state,
        vlan_assignments=list(iface.vlan_assignments),
        access_mode=iface.access_mode,
        native_vlan=iface.native_vlan,
        engines=_engines_of(iface.provenance),
    )


def _device_record(model: NetworkModel, dev: DeviceInfo) -> DeviceRecord:
    interfaces: list[InterfaceRecord] = []
    for canon in dev.interfaces:
        iface = model.interfaces.get(f"{dev.name}:{canon}") or model.interfaces.get(canon)
        if iface is None:
            interfaces.append(InterfaceRecord(name=canon))
        else:
            interfaces.append(_interface_record(iface))
    try:
        role = classify_device(model, dev.name)
    except Exception:  # noqa: BLE001 - classification must never break extraction
        role = "unknown"
    return DeviceRecord(
        name=dev.name,
        model=dev.model,
        device_type=dev.device_type,
        role=role,
        interfaces=interfaces,
        config_line_count=len(dev.configuration),
        engines=_engines_of(dev.provenance),
    )


def _link_record(link: LinkInfo) -> LinkRecord:
    return LinkRecord(
        a_device=link.device_a,
        a_port=link.interface_a,
        b_device=link.device_b,
        b_port=link.interface_b,
        engines=_engines_of(link.provenance),
    )


def _config_declares_vlan(configuration: list[str], vlan_id: int) -> bool:
    pattern = re.compile(rf"^vlan\s+{vlan_id}\s*$", re.IGNORECASE)
    return any(pattern.match(line.strip()) for line in configuration)


def _vlan_records(model: NetworkModel, warnings: list[str]) -> list[VlanRecord]:
    records: dict[tuple[int, str], VlanRecord] = {}
    for vlan in model.vlans:
        devices: set[str] = set()
        for member in vlan.member_ports:
            device, _, _ = member.partition(":")
            if device:
                devices.add(device)
        if not devices:
            for name, dev in model.devices.items():
                if _config_declares_vlan(dev.configuration, vlan.vlan_id):
                    devices.add(name)
        if not devices:
            devices.add("")
            warnings.append(
                f"VLAN {vlan.vlan_id} could not be attributed to a device"
            )
        for device in sorted(devices):
            records[(vlan.vlan_id, device)] = VlanRecord(
                id=vlan.vlan_id,
                name=vlan.name,
                device=device,
                engines=_engines_of(vlan.provenance),
            )

    for iface in model.interfaces.values():
        for raw in iface.vlan_assignments:
            try:
                vlan_id = int(str(raw).strip())
            except (TypeError, ValueError):
                continue
            key = (vlan_id, iface.device)
            if key not in records:
                records[key] = VlanRecord(
                    id=vlan_id,
                    name=None,
                    device=iface.device,
                    engines=_engines_of(iface.provenance),
                )
    return [records[key] for key in sorted(records)]


def _route_records(model: NetworkModel) -> list[RouteRecord]:
    out = [
        RouteRecord(
            device=route.device,
            destination=route.destination,
            mask=_route_mask(route),
            next_hop=route.next_hop,
            kind=route.route_type,
            engines=_engines_of(route.provenance),
        )
        for route in model.routes
    ]
    return sorted(out, key=lambda r: (r.device, r.destination, r.next_hop or ""))


def _acl_device(
    acl: AclEntry,
    interface_devices: dict[str, set[str]],
    config_index: dict[str, set[str]],
) -> str:
    if acl.applied_interface:
        canon = canonical_interface_name(acl.applied_interface)
        devices = interface_devices.get(canon, set())
        if len(devices) == 1:
            return next(iter(devices))
    raw = (acl.raw or "").strip()
    if raw:
        hits = {name for name, lines in config_index.items() if raw in lines}
        if len(hits) == 1:
            return next(iter(hits))
    return ""


def _acl_records(model: NetworkModel, warnings: list[str]) -> list[AclRecord]:
    interface_devices: dict[str, set[str]] = defaultdict(set)
    for iface in model.interfaces.values():
        interface_devices[iface.canonical_name].add(iface.device)
        interface_devices[canonical_interface_name(iface.name)].add(iface.device)

    config_index = {
        name: {line.strip() for line in dev.configuration}
        for name, dev in model.devices.items()
    }

    out: list[AclRecord] = []
    unattributed: set[str] = set()
    for acl in model.acls:
        device = _acl_device(acl, interface_devices, config_index)
        if not device:
            unattributed.add(acl.acl_id)
        out.append(
            AclRecord(
                device=device,
                acl_id=acl.acl_id,
                action=acl.action,
                protocol=acl.protocol,
                source=acl.source,
                destination=acl.destination,
                applied_interface=acl.applied_interface,
                direction=acl.direction,
                engines=_engines_of(acl.provenance),
            )
        )
    for acl_id in sorted(unattributed):
        warnings.append(f"ACL {acl_id} could not be attributed to a device")
    return sorted(
        out,
        key=lambda a: (a.device, a.acl_id, a.action, a.source or "", a.destination or ""),
    )


def _canonical(field_name: str, value: str) -> str:
    if field_name in _MAC_FIELDS:
        return normalize_mac(value) or value.strip().lower()
    if field_name in _IFACE_FIELDS:
        return canonical_interface_name(value)
    return value.strip().lower()


def _discrepancies(model: NetworkModel) -> list[Discrepancy]:
    groups: dict[tuple[str, str, str], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for observation in model.observations:
        groups[(observation.entity_type, observation.entity_id, observation.field)][
            observation.provenance.engine
        ].add(_canonical(observation.field, observation.value))

    out: list[Discrepancy] = []
    for (entity_type, entity_id, field_name), by_engine in sorted(groups.items()):
        engines = sorted(by_engine)
        for index, engine_a in enumerate(engines):
            for engine_b in engines[index + 1 :]:
                value_a = by_engine[engine_a]
                value_b = by_engine[engine_b]
                if value_a == value_b:
                    continue
                out.append(
                    Discrepancy(
                        entity_type=entity_type,
                        entity_id=entity_id,
                        field=field_name,
                        engine_a=engine_a,
                        value_a=" | ".join(sorted(value_a)),
                        engine_b=engine_b,
                        value_b=" | ".join(sorted(value_b)),
                    )
                )
    return out


def _engine_states(
    model: NetworkModel, adapter_results: list[AdapterResult]
) -> dict[str, dict]:
    observation_counts = Counter(
        observation.provenance.engine for observation in model.observations
    )
    states: dict[str, dict] = {}
    for result in adapter_results:
        report = result.report
        states[result.engine_id] = {
            "state": report.state.value,
            "device_count": report.device_count or len(result.devices),
            "link_count": report.link_count,
            "observation_count": observation_counts.get(result.engine_id, 0),
            "message": report.message,
            "duration_ms": report.duration_ms,
            "capabilities": list(report.capabilities),
            "limitations": list(report.limitations),
        }
    return states


def _unsupported_items(engines: dict[str, dict]) -> list[UnsupportedItem]:
    items: list[UnsupportedItem] = []
    for engine_id in sorted(engines):
        state = engines[engine_id]
        if state["state"] == ParserState.OK.value:
            continue
        reason = state["message"] or f"{engine_id} did not run"
        for capability in state["capabilities"]:
            items.append(
                UnsupportedItem(
                    capability=capability,
                    reason=f"{engine_id} {state['state']}: {reason}",
                    status=state["state"],
                    source=engine_id,
                )
            )

    for limitation in PT_901_LIMITATIONS:
        status = support_status(limitation.capability)
        if status is SupportStatus.SUPPORTED:
            continue
        items.append(
            UnsupportedItem(
                capability=limitation.capability,
                reason=unsupported_reason(limitation.capability) or limitation.reason,
                status=status.value,
                source="documented-pt-901-limitation",
            )
        )

    seen: set[tuple[str, str, str]] = set()
    unique: list[UnsupportedItem] = []
    for item in items:
        key = (item.capability, item.status, item.source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return sorted(unique, key=lambda item: (item.status, item.capability, item.source))


def build_evidence(
    model: NetworkModel,
    adapter_results: list[AdapterResult],
    *,
    source_sha256: str = "",
    source_path: str = "",
    cfg: Settings | None = None,
) -> NetworkEvidence:
    """Project a normalised model into :class:`NetworkEvidence`.

    Public so tests and downstream callers can rebuild evidence from an existing
    model without re-running the engines. ``reconstruct`` is the normal entry
    point.
    """
    cfg = cfg or default_settings
    warnings: list[str] = list(model.warnings)

    devices = [_device_record(model, dev) for dev in model.devices.values()]
    devices.sort(key=lambda dev: dev.name)

    links = sorted(
        (_link_record(link) for link in model.links),
        key=lambda link: (link.a_device, link.a_port, link.b_device, link.b_port),
    )
    vlans = _vlan_records(model, warnings)
    routes = _route_records(model)
    acls = _acl_records(model, warnings)
    engines = _engine_states(model, adapter_results)

    return NetworkEvidence(
        devices=devices,
        links=links,
        vlans=vlans,
        routes=routes,
        acls=acls,
        discrepancies=_discrepancies(model),
        unsupported=_unsupported_items(engines),
        engines=engines,
        source_sha256=source_sha256 or model.file_sha256,
        model=model,
        source_path=source_path,
        snapshot_id=model.snapshot_id,
        snapshot_ambiguous=model.snapshot_ambiguous,
        consensus_policy=cfg.consensus_policy,
        consensus_required=_required_engines(cfg.consensus_policy),
        warnings=warnings,
    )


def _required_engines(policy: str) -> int:
    if policy == "strict":
        return 3
    if policy == "two_engine":
        return 2
    return 1


# ---------------------------------------------------------------------------
# Reconstruction
# ---------------------------------------------------------------------------


def _run_analysis(ingested: IngestedFile, cfg: Settings) -> AnalysisOutcome:
    """Run the async pipeline from synchronous code, including inside a loop."""

    coroutine = analyze(ingested, _FORENSICS_QUESTION, cfg=cfg, use_ai=False)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)

    outcome: dict[str, Any] = {}

    def runner() -> None:
        try:
            outcome["value"] = asyncio.run(coroutine)
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            outcome["error"] = exc

    thread = threading.Thread(target=runner, name="trident-forensics", daemon=True)
    thread.start()
    thread.join()
    if "error" in outcome:
        raise outcome["error"]
    if "value" not in outcome:
        raise RuntimeError("analysis thread produced no result")
    return outcome["value"]


def reconstruct(path: str | Path, cfg: Settings | None = None) -> NetworkEvidence:
    """Read one ``.pkt``/``.pka`` and build a complete :class:`NetworkEvidence`.

    The source file is never written to. Its SHA-256 is taken before ingestion and
    re-taken afterwards; a mismatch raises :class:`EvidenceIntegrityError`.
    """
    cfg = cfg or default_settings
    target = Path(path)
    original = target.read_bytes()
    before = hashlib.sha256(original).hexdigest()

    ingested = ingest(target.name, original, cfg)
    outcome = _run_analysis(ingested, cfg)

    after = hashlib.sha256(target.read_bytes()).hexdigest()
    if after != before:
        raise EvidenceIntegrityError(
            f"source file changed during reconstruction: {before} -> {after}"
        )
    if ingested.sha256 != before:
        raise EvidenceIntegrityError(
            "ingestion did not preserve the source bytes exactly"
        )

    evidence = build_evidence(
        outcome.model,
        outcome.adapter_results,
        source_sha256=before,
        source_path=str(target),
        cfg=cfg,
    )
    for warning in outcome.response.warnings:
        if warning not in evidence.warnings:
            evidence.warnings.append(warning)
    return evidence


def write_evidence(evidence: NetworkEvidence, path: str | Path) -> Path:
    """Write ``network_evidence.json`` and return the file written.

    Passing a directory (or a path without a suffix) writes
    ``<directory>/network_evidence.json``.
    """
    target = Path(path)
    if (target.exists() and target.is_dir()) or target.suffix == "":
        target = target / EVIDENCE_FILENAME
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(evidence.as_dict(), indent=2, ensure_ascii=False)
    target.write_text(payload + "\n", encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Visible-instruction parsing
# ---------------------------------------------------------------------------

_LIST_MARKER_RE = re.compile(r"^(?:\d{1,3}[.)]|[-*\u2022\u00b7\u2013\u2014])\s+")
_SECTION_HEADER_RE = re.compile(r"^(?:task|part|step)\s+\d+\b", re.IGNORECASE)
_POINTS_ONLY_RE = re.compile(r"^\(?\d+\s*(?:points?|pts?)\)?\.?$", re.IGNORECASE)

_HEADER_NAMES = {
    "assessment",
    "background",
    "deliverables",
    "grading",
    "instructions",
    "introduction",
    "network requirements",
    "notes",
    "objectives",
    "overview",
    "requirements",
    "scenario",
    "submission",
    "tasks",
    "topology",
}

_IMPERATIVE_VERBS = {
    "add",
    "apply",
    "assign",
    "change",
    "configure",
    "connect",
    "create",
    "deny",
    "disable",
    "enable",
    "ensure",
    "install",
    "permit",
    "remove",
    "replace",
    "restrict",
    "save",
    "secure",
    "set",
    "test",
    "update",
    "use",
    "verify",
}

_NON_REQUIREMENT_PHRASES = (
    "click submit",
    "press submit",
    "when you are finished",
    "when finished",
    "you have ",
    "minutes to complete",
    "time limit",
    "read each",
    "read the ",
    "review the ",
    "do not ",
    "open the file",
    "close packet tracer",
    "good luck",
    "this assessment",
)

_SENTENCE_END = (".", "!", "?", ":", ";")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalise_line(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def _strip_marker(line: str) -> str | None:
    match = _LIST_MARKER_RE.match(line)
    if match is None:
        return None
    return line[match.end() :].strip()


def _is_non_requirement(line: str, *, first_line: bool) -> bool:
    text = _normalise_line(line)
    if not text:
        return True
    if _POINTS_ONLY_RE.match(text):
        return True

    lower = text.lower().rstrip(":.")
    if any(phrase in lower for phrase in _NON_REQUIREMENT_PHRASES):
        return True
    if lower in _HEADER_NAMES:
        return True
    if text.isupper() and len(text.split()) <= 12:
        return True
    if text.endswith(":") and len(text.split()) <= 10:
        return True
    if _SECTION_HEADER_RE.match(text) and _LIST_MARKER_RE.match(line) is None:
        return True

    if first_line and len(text.split()) <= 12 and text[-1] not in ".!?":
        words = re.findall(r"[a-z]+", text.lower())
        if not words or words[0] not in _IMPERATIVE_VERBS:
            return True
    return False


def load_requirements(text: str) -> list[str]:
    """Split VISIBLE assessment instructions into raw requirement lines.

    Handles numbered lists, bullet lists, blank lines, wrapped continuation
    lines, section headers and submission boilerplate. It deliberately does not
    interpret a requirement: numbering is stripped, the wording is preserved, and
    decomposition into a network intent is left to the requirements phase.
    """
    if not text or not text.strip():
        return []

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    first_content = True
    joinable = False

    for raw in lines:
        line = raw.strip()
        if not line:
            joinable = False
            continue

        body = _strip_marker(line)
        is_first = first_content
        first_content = False

        if body is not None:
            joinable = False
            if _is_non_requirement(body, first_line=is_first):
                continue
            requirement = _normalise_line(body)
            if requirement:
                out.append(requirement)
                joinable = True
            continue

        if _is_non_requirement(line, first_line=is_first):
            joinable = False
            continue

        requirement = _normalise_line(line)
        if joinable and out and not out[-1].endswith(_SENTENCE_END):
            out[-1] = f"{out[-1]} {requirement}"
        else:
            out.append(requirement)
            joinable = True

    return out
