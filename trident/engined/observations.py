"""Operational evidence for Engine D: the live half of a verdict.

Engine D's static analysis can prove a prediction from the uploaded
configuration; that is :class:`~trident.engined.verify.Status` ``DERIVED``.
``VERIFIED`` additionally requires that a live simulator observation agrees.
This module supplies that live half and nothing else:

* :func:`collect` opens one bounded, read-only Packet Tracer session, runs the
  collectors from :mod:`trident.deepcore.live_evidence`, and returns the raw
  output plus parsed facts, each labelled with its source.
* :func:`prediction_agrees` correlates one predicted boolean with one observed
  boolean. With no live observation it returns ``INCONCLUSIVE`` -- never
  ``VERIFIED``, because static evidence is not an observation.
* :class:`LiveObservationSet` keeps the source ``.pkt`` hash before and after the
  session and exposes only facts the simulator actually printed.

Honesty rules encoded here rather than documented only:

* Every parsed fact carries ``source`` (the source of the raw output it came
  from) and ``derivation`` (``PARSER_DERIVED``). A fact parsed out of a failed
  command is not produced at all; the failure is recorded with its error.
* A command that did not complete is ``UNSUPPORTED`` for that device and
  command; it never becomes an empty-but-successful observation.
* Packet Tracer 9.0.1 has two hard limitations that this module names explicitly
  instead of guessing around: end hosts have no CLI, and a behavioural ping is
  not available. Both are recorded in :data:`PT_901_LIMITATIONS`.
* ``runtime_state_available`` answers whether *any* live runtime state was read.
  File-state (``show running-config`` or the ``.pkt`` contents) is never counted
  as runtime state.
"""

from __future__ import annotations

import enum
import ipaddress
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from ..deepcore.live_evidence import (
    CollectorResult,
    Conclusion,
    EvidenceBudget,
    EvidenceSource,
    LiveEvidence,
    LiveEvidenceSession,
    open_live_evidence,
)
from ..evidence.parsers import parse_ip_interface_brief, parse_ip_route
from ..simulator.isolation import sha256_file

# ---------------------------------------------------------------------------
# Support vocabulary and the explicit UNSUPPORTED path
# ---------------------------------------------------------------------------


class SupportStatus(enum.StrEnum):
    """Whether this build can answer a capability, and if not, why not."""

    #: A bounded, read-only command answered this and produced runtime state.
    SUPPORTED = "SUPPORTED"
    #: The device or the build cannot answer this at all.
    UNSUPPORTED = "UNSUPPORTED"
    #: The capability exists in principle but no live backend answered it here.
    UNAVAILABLE = "UNAVAILABLE"
    #: Nothing is known about this capability; it is never assumed supported.
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class UnsupportedObservation:
    """One capability Packet Tracer cannot answer, with the evidence for that."""

    capability: str
    reason: str
    evidence: str = ""

    def as_dict(self) -> dict:
        return {
            "capability": self.capability,
            "reason": self.reason,
            "evidence": self.evidence,
        }


#: The two limitations that shape what this module is allowed to ask for.
#:
#: These are established facts from live Packet Tracer 9.0.1 runs, not
#: assumptions. The exact error strings are carried so a reader can check them
#: against ``docs/gauntlet/VERIFIED_GROUND_TRUTH.md`` and
#: ``docs/gauntlet/ERROR_ANALYSIS.md``.
PT_901_LIMITATIONS: tuple[UnsupportedObservation, ...] = (
    UnsupportedObservation(
        capability="end_host_cli",
        reason=(
            "Packet Tracer 9.0.1 implements no CLI on PC-PT or Server-PT: the Pc "
            "object has no enterCommand, so end-host state cannot be read as CLI "
            "output. Only routers and switches can be observed this way."
        ),
        evidence='IPC error from enterCommand: [\'Pc\', \'IPC call "enterCommand" not found\']',
    ),
    UnsupportedObservation(
        capability="behavioural_ping",
        reason=(
            "PduExecutor.send returns EXECUTION_ERROR with zero frames on this "
            "build, so a behavioural ping is not available. Reachability is "
            "never inferred by pretending a packet moved; only show output is "
            "used."
        ),
        evidence="DeliveryStatus.EXECUTION_ERROR, frames_seen=0",
    ),
)

#: Read-only commands this module is willing to ask for. Anything else is not
#: collected, because there is no safe way to interpret it.
_OBSERVABLE_CAPABILITIES: frozenset[str] = frozenset(
    {
        "show ip interface brief",
        "show running-config",
        "show vlan brief",
        "show interfaces trunk",
        "show ip route",
        "show interfaces status",
    }
)

#: (command, collector method on LiveEvidenceSession), in collection order.
_COLLECTORS: tuple[tuple[str, str], ...] = (
    ("show ip interface brief", "collect_ip_interface_brief"),
    ("show running-config", "collect_running_config"),
    ("show vlan brief", "collect_vlan_brief"),
    ("show interfaces trunk", "collect_interfaces_trunk"),
    ("show ip route", "collect_ip_route"),
    ("show interfaces status", "collect_interfaces_status"),
)


def support_status(capability: str) -> SupportStatus:
    """Classify a capability as supported, explicitly unsupported, or unknown.

    ``UNSUPPORTED`` is returned only for a documented PT 9.0.1 limitation. An
    unrecognised name is ``UNKNOWN`` rather than silently supported.
    """
    text = " ".join(capability.replace("_", " ").split()).lower()
    if text in _OBSERVABLE_CAPABILITIES:
        return SupportStatus.SUPPORTED
    if any(limitation.capability == capability.strip().lower() for limitation in PT_901_LIMITATIONS):
        return SupportStatus.UNSUPPORTED
    return SupportStatus.UNKNOWN


def unsupported_reason(capability: str) -> str | None:
    """The documented reason a capability is unsupported, or ``None``."""
    for limitation in PT_901_LIMITATIONS:
        if limitation.capability == capability.strip().lower():
            return limitation.reason
    return None


# ---------------------------------------------------------------------------
# Parsed facts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservedFact:
    """One parsed fact, with the source of the output it came from.

    ``source`` names where the raw text came from (``LIVE_SIMULATOR``,
    ``SCRIPTED_BACKEND`` or ``UNAVAILABLE``). ``derivation`` is always
    ``PARSER_DERIVED``: the value is a structured reading of that raw text, not
    a literal line. ``observed_live`` is True only when the raw text came from a
    live simulator.
    """

    fact: str
    value: object
    source: EvidenceSource
    device: str | None = None
    command: str | None = None
    observed_live: bool = False
    derivation: EvidenceSource = EvidenceSource.PARSER_DERIVED
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "fact": self.fact,
            "value": self.value,
            "source": self.source.value,
            "derivation": self.derivation.value,
            "device": self.device,
            "command": self.command,
            "observed_live": self.observed_live,
            "detail": self.detail,
        }


def _prefix_length(mask_or_prefix: object) -> int | None:
    """Prefix length from ``/30`` or ``255.255.255.252``, or ``None``."""
    if mask_or_prefix is None:
        return None
    text = str(mask_or_prefix).strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{text}").prefixlen
    except ValueError:
        return None


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass(frozen=True)
class RouteObservation:
    """One route parsed from ``show ip route``."""

    code: str
    network: str
    mask_or_prefix: str | None = None
    prefix_length: int | None = None
    next_hop: str | None = None
    interface: str | None = None
    metric: int | None = None
    source: EvidenceSource = EvidenceSource.UNAVAILABLE
    device: str | None = None
    observed_live: bool = False
    derivation: EvidenceSource = EvidenceSource.PARSER_DERIVED

    @property
    def is_default(self) -> bool:
        """The default route (``0.0.0.0/0``), not merely a zero network."""
        return self.network == "0.0.0.0" and self.prefix_length == 0

    @property
    def is_directly_connected(self) -> bool:
        """A connected (or local) route: an egress interface and no next hop."""
        return self.next_hop is None and self.interface is not None

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "network": self.network,
            "mask_or_prefix": self.mask_or_prefix,
            "prefix_length": self.prefix_length,
            "next_hop": self.next_hop,
            "interface": self.interface,
            "metric": self.metric,
            "source": self.source.value,
            "derivation": self.derivation.value,
            "device": self.device,
            "observed_live": self.observed_live,
            "is_default": self.is_default,
            "is_directly_connected": self.is_directly_connected,
        }


@dataclass(frozen=True)
class InterfaceObservation:
    """One interface parsed from ``show ip interface brief``."""

    interface: str
    status: str
    protocol: str
    ip: str | None = None
    ok: str = ""
    method: str = ""
    source: EvidenceSource = EvidenceSource.UNAVAILABLE
    device: str | None = None
    observed_live: bool = False
    derivation: EvidenceSource = EvidenceSource.PARSER_DERIVED

    @property
    def is_up(self) -> bool:
        """Line and protocol are both up. Merely not-down is not up."""
        return self.status == "up" and self.protocol == "up"

    @property
    def is_administratively_down(self) -> bool:
        return self.status == "administratively down"

    def as_dict(self) -> dict:
        return {
            "interface": self.interface,
            "status": self.status,
            "protocol": self.protocol,
            "ip": self.ip,
            "ok": self.ok,
            "method": self.method,
            "source": self.source.value,
            "derivation": self.derivation.value,
            "device": self.device,
            "observed_live": self.observed_live,
            "is_up": self.is_up,
            "is_administratively_down": self.is_administratively_down,
        }


def parse_route_output(
    text: str,
    *,
    device: str | None = None,
    source: EvidenceSource = EvidenceSource.UNAVAILABLE,
    observed_live: bool = False,
) -> list[RouteObservation]:
    """Parse ``show ip route`` into structured routes.

    Reuses the Phase 2 parser rather than re-implementing IOS route grammar, so
    this module and the evidence layer cannot drift. Empty or unparsable text
    yields an empty list; it is never filled with a guessed default.
    """
    if not text or not text.strip():
        return []
    rows, _notes, _ok = parse_ip_route(text)
    routes: list[RouteObservation] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        mask_or_prefix = _optional_text(row.get("mask_or_prefix"))
        metric = row.get("metric")
        routes.append(
            RouteObservation(
                code=str(row.get("code") or "").strip(),
                network=str(row.get("network") or "").strip(),
                mask_or_prefix=mask_or_prefix,
                prefix_length=_prefix_length(mask_or_prefix),
                next_hop=_optional_text(row.get("next_hop")),
                interface=_optional_text(row.get("interface")),
                metric=metric if isinstance(metric, int) else None,
                source=source,
                device=device,
                observed_live=observed_live,
            )
        )
    return routes


def parse_interface_output(
    text: str,
    *,
    device: str | None = None,
    source: EvidenceSource = EvidenceSource.UNAVAILABLE,
    observed_live: bool = False,
) -> dict[str, InterfaceObservation]:
    """Parse ``show ip interface brief`` into per-interface states.

    The Phase 2 parser is reused, including its refusal to coerce a malformed
    line. A row it skips is absent here too, rather than invented.
    """
    if not text or not text.strip():
        return {}
    rows, _notes, _ok = parse_ip_interface_brief(text)
    interfaces: dict[str, InterfaceObservation] = {}
    for name, row in rows.items():
        if not isinstance(row, dict):
            continue
        interfaces[str(name)] = InterfaceObservation(
            interface=str(name),
            status=str(row.get("status") or "").strip().lower(),
            protocol=str(row.get("protocol") or "").strip().lower(),
            ip=_optional_text(row.get("ip")),
            ok=str(row.get("ok") or "").strip(),
            method=str(row.get("method") or "").strip(),
            source=source,
            device=device,
            observed_live=observed_live,
        )
    return interfaces


# ---------------------------------------------------------------------------
# Per-device and per-session observation sets
# ---------------------------------------------------------------------------


@dataclass
class DeviceObservation:
    """Everything one device answered, plus what was parsed out of it."""

    device: str
    evidence: dict[str, LiveEvidence] = field(default_factory=dict)
    raw: dict[str, str] = field(default_factory=dict)
    routes: list[RouteObservation] = field(default_factory=list)
    interfaces: dict[str, InterfaceObservation] = field(default_factory=dict)
    facts: list[ObservedFact] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def live_evidence(self) -> list[LiveEvidence]:
        return [item for item in self.evidence.values() if item.is_live]

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "commands": sorted(self.evidence),
            "raw_line_counts": {command: len(text.splitlines()) for command, text in self.raw.items()},
            "routes": [route.as_dict() for route in self.routes],
            "interfaces": {name: item.as_dict() for name, item in self.interfaces.items()},
            "facts": [fact.as_dict() for fact in self.facts],
            "errors": dict(self.errors),
            "notes": list(self.notes),
            "live_commands": [item.command for item in self.live_evidence],
        }


@dataclass
class LiveObservationSet:
    """One bounded collection pass over a set of devices.

    ``source_sha256_before`` and ``source_sha256_after`` are the hash of the
    caller's ``.pkt``. ``source_intact`` is True only when both were computed and
    are equal. The simulator only ever opens its own disposable working copy, so
    a changed source hash is a hard failure of the isolation promise.
    """

    model_path: str
    devices: dict[str, DeviceObservation] = field(default_factory=dict)
    source_sha256_before: str | None = None
    source_sha256_after: str | None = None
    source_intact: bool | None = None
    commands_run: int = 0
    budget_seconds: float = 0.0
    cleanup_status: str = "NOT_STARTED"
    notes: list[str] = field(default_factory=list)
    unsupported: list[UnsupportedObservation] = field(
        default_factory=lambda: list(PT_901_LIMITATIONS)
    )
    collection_error: str | None = None

    # -- lookups -----------------------------------------------------------

    def device(self, name: str) -> DeviceObservation | None:
        return self.devices.get(name)

    def raw_output(self, device: str, command: str) -> str | None:
        observation = self.devices.get(device)
        if observation is None:
            return None
        return observation.raw.get(command)

    def evidence_for(self, device: str, command: str) -> LiveEvidence | None:
        observation = self.devices.get(device)
        if observation is None:
            return None
        return observation.evidence.get(command)

    def command_support(self, device: str, command: str) -> SupportStatus:
        """Did this device answer this command with live runtime state?"""
        evidence = self.evidence_for(device, command)
        if evidence is None:
            return SupportStatus.UNKNOWN
        if evidence.ok and evidence.is_live:
            return SupportStatus.SUPPORTED
        if evidence.ok:
            return SupportStatus.UNAVAILABLE
        return SupportStatus.UNSUPPORTED

    def device_errors(self) -> dict[str, dict[str, str]]:
        return {
            name: dict(observation.errors)
            for name, observation in self.devices.items()
            if observation.errors
        }

    # -- the two required views -------------------------------------------

    def routing_table(self, device: str) -> list[RouteObservation]:
        """Routes parsed from ``show ip route`` on ``device``.

        Empty when the command failed or returned nothing. It is not replaced by
        a static route table: that would be a different source pretending to be
        a live observation.
        """
        observation = self.devices.get(device)
        return list(observation.routes) if observation is not None else []

    def interface_states(self, device: str) -> dict[str, str]:
        """``{interface: status}`` parsed from ``show ip interface brief``."""
        observation = self.devices.get(device)
        if observation is None:
            return {}
        return {name: item.status for name, item in observation.interfaces.items()}

    # -- reporting ---------------------------------------------------------

    @property
    def has_runtime_state(self) -> bool:
        return runtime_state_available(self)

    def as_dict(self) -> dict:
        return {
            "model_path": self.model_path,
            "source_sha256_before": self.source_sha256_before,
            "source_sha256_after": self.source_sha256_after,
            "source_intact": self.source_intact,
            "commands_run": self.commands_run,
            "budget_seconds": self.budget_seconds,
            "cleanup_status": self.cleanup_status,
            "collection_error": self.collection_error,
            "runtime_state_available": runtime_state_available(self),
            "devices": {name: item.as_dict() for name, item in self.devices.items()},
            "unsupported": [item.as_dict() for item in self.unsupported],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def _safe_hash(path: str | Path) -> str | None:
    try:
        return sha256_file(path)
    except (OSError, ValueError):
        return None


def _normalise_devices(devices: Iterable[str] | str) -> list[str]:
    if isinstance(devices, str):
        return [devices]
    seen: list[str] = []
    for name in devices:
        text = str(name).strip()
        if text and text not in seen:
            seen.append(text)
    return seen


@contextmanager
def _opened_session(
    model_path: str | Path,
    *,
    backend: object | None,
    close: object | None,
    budget: EvidenceBudget,
    session_id: str,
) -> Iterator[LiveEvidenceSession]:
    """Open either an injected backend or a fresh live runtime session."""
    if backend is not None:
        with LiveEvidenceSession(
            backend,  # type: ignore[arg-type]
            Path(model_path),
            close=close,  # type: ignore[arg-type]
            budget=budget,
            session_id=session_id,
        ) as live:
            yield live
        return
    with open_live_evidence(model_path, budget=budget, session_id=session_id or None) as live:
        yield live


def _observe_device(
    session: LiveEvidenceSession, device: str, command_timeout_s: float
) -> DeviceObservation:
    observation = DeviceObservation(device=device)
    for command, method_name in _COLLECTORS:
        collector = getattr(session, method_name, None)
        if collector is None:
            observation.errors[command] = f"collector {method_name} is unavailable"
            continue
        try:
            result: CollectorResult = collector(device, timeout=command_timeout_s)
        except Exception as exc:  # noqa: BLE001 - recorded, never guessed around
            observation.errors[command] = f"{type(exc).__name__}: {exc}"
            observation.notes.append(f"{device}: {command} raised {type(exc).__name__}: {exc}")
            continue
        observation.evidence[command] = result.evidence
        if result.evidence.raw:
            observation.raw[command] = result.evidence.raw
        if not result.evidence.ok:
            observation.errors[command] = result.evidence.error or "the command did not complete"
        observation.notes.extend(f"{device}: {note}" for note in result.notes)

    brief = observation.evidence.get("show ip interface brief")
    try:
        observation.interfaces = parse_interface_output(
            observation.raw.get("show ip interface brief", ""),
            device=device,
            source=brief.source if brief is not None else EvidenceSource.UNAVAILABLE,
            observed_live=bool(brief is not None and brief.is_live),
        )
    except Exception as exc:  # noqa: BLE001 - a parser fault must not invent rows
        observation.notes.append(f"{device}: show ip interface brief parse failed: {exc}")

    route = observation.evidence.get("show ip route")
    try:
        observation.routes = parse_route_output(
            observation.raw.get("show ip route", ""),
            device=device,
            source=route.source if route is not None else EvidenceSource.UNAVAILABLE,
            observed_live=bool(route is not None and route.is_live),
        )
    except Exception as exc:  # noqa: BLE001 - a parser fault must not invent routes
        observation.notes.append(f"{device}: show ip route parse failed: {exc}")

    observation.facts = _facts_from(observation)
    return observation


def _facts_from(observation: DeviceObservation) -> list[ObservedFact]:
    facts: list[ObservedFact] = []
    for command, evidence in observation.evidence.items():
        facts.append(
            ObservedFact(
                fact=f"{observation.device}:{command}",
                value="ok" if evidence.ok else "failed",
                source=evidence.source,
                device=observation.device,
                command=command,
                observed_live=evidence.is_live,
                detail=evidence.error or "",
            )
        )
    for name, interface in observation.interfaces.items():
        facts.append(
            ObservedFact(
                fact=f"{observation.device}:{name}:status",
                value=interface.status,
                source=interface.source,
                device=observation.device,
                command="show ip interface brief",
                observed_live=interface.observed_live,
                detail=interface.protocol,
            )
        )
    for route in observation.routes:
        facts.append(
            ObservedFact(
                fact=f"{observation.device}:route:{route.network}",
                value=route.mask_or_prefix,
                source=route.source,
                device=observation.device,
                command="show ip route",
                observed_live=route.observed_live,
                detail=route.code,
            )
        )
    return facts


def collect(
    model_path: str | Path,
    devices: Iterable[str] | str,
    *,
    budget_seconds: float = 180.0,
    command_timeout_s: float = 30.0,
    backend: object | None = None,
    close: object | None = None,
    session_id: str = "",
    budget: EvidenceBudget | None = None,
) -> LiveObservationSet:
    """Collect runtime state for ``devices`` from one bounded live session.

    The session is always a context manager, so ``close`` runs even when a
    command raises. The source file is hashed before and after; the result says
    whether it was intact. The session is bounded by ``budget_seconds``, a
    per-command timeout, and a command count derived from the device count.

    An injected ``backend`` exists so the whole path can be tested without
    Packet Tracer. It must expose ``run_cli``, ``close``, ``kind`` and
    ``version`` exactly like :class:`~trident.simulator.backends.LiveBackend`.
    A backend that reports ``SCRIPTED`` produces ``SCRIPTED_BACKEND`` evidence,
    which :func:`runtime_state_available` correctly refuses to call runtime
    state.
    """
    device_list = _normalise_devices(devices)
    effective_budget = budget or EvidenceBudget(
        command_timeout_s=command_timeout_s,
        overall_budget_s=budget_seconds,
        max_commands=max(len(_COLLECTORS) * max(len(device_list), 1), len(_COLLECTORS)),
    )

    before = _safe_hash(model_path)
    session: LiveEvidenceSession | None = None
    device_observations: dict[str, DeviceObservation] = {}
    notes: list[str] = []
    collection_error: str | None = None

    if not device_list:
        notes.append("no devices were supplied; nothing was collected")
    else:
        try:
            with _opened_session(
                model_path,
                backend=backend,
                close=close,
                budget=effective_budget,
                session_id=session_id,
            ) as live:
                session = live
                for device in device_list:
                    device_observations[device] = _observe_device(
                        live, device, effective_budget.command_timeout_s
                    )
        except Exception as exc:  # noqa: BLE001 - reported as an empty, labelled set
            collection_error = f"{type(exc).__name__}: {exc}"
            notes.append(f"collection failed: {collection_error}")

    after = _safe_hash(model_path)
    intact = None if before is None or after is None else before == after
    if intact is False:
        notes.append("SOURCE CHANGED during the session; the isolation promise was violated")

    if session is not None:
        notes.extend(session.notes)
        cleanup_status = session.cleanup_status
        commands_run = session.commands_run
    else:
        cleanup_status = "NOT_STARTED"
        commands_run = 0

    return LiveObservationSet(
        model_path=str(model_path),
        devices=device_observations,
        source_sha256_before=before,
        source_sha256_after=after,
        source_intact=intact,
        commands_run=commands_run,
        budget_seconds=effective_budget.overall_budget_s,
        cleanup_status=cleanup_status,
        notes=notes,
        collection_error=collection_error,
    )


# ---------------------------------------------------------------------------
# Correlation and the state question
# ---------------------------------------------------------------------------


def prediction_agrees(fact: str, predicted: bool, observed: bool | None) -> Conclusion:
    """Correlate one predicted boolean with one live observation.

    ``observed`` is ``None`` when no live runtime observation exists for
    ``fact``. That is ``INCONCLUSIVE`` -- not ``DERIVED`` and emphatically not
    ``VERIFIED``. Static analysis alone never produces ``VERIFIED``; the
    agreement of a live observation does.

    ``fact`` labels the correlation for the caller's report. It cannot change the
    conclusion.
    """
    if observed is None:
        return Conclusion.INCONCLUSIVE
    if observed == predicted:
        return Conclusion.VERIFIED
    return Conclusion.CONTRADICTED


RUNTIME_STATE_NOTE = (
    "File-state is what the configuration says should happen: the uploaded .pkt "
    "contents and 'show running-config' output. Runtime-state is what the "
    "simulator reports it is doing now: 'show ip interface brief', 'show ip "
    "route', 'show vlan brief', 'show interfaces trunk' and 'show interfaces "
    "status'. Only runtime-state can confirm or contradict a prediction. A fact "
    "read from a file is static analysis and never yields VERIFIED."
)


def runtime_state_note() -> str:
    """Prose explaining the file-state / runtime-state distinction."""
    return RUNTIME_STATE_NOTE


def runtime_state_available(observation_set: LiveObservationSet) -> bool:
    """True only when at least one live command actually completed.

    A scripted backend, a failed command, an empty set and a collection error all
    return False. "No runtime state" and "reachable" are never conflated: this
    only says whether an observation exists to correlate at all.
    """
    if observation_set.collection_error:
        return False
    for observation in observation_set.devices.values():
        for evidence in observation.evidence.values():
            if evidence.ok and evidence.is_live:
                return True
    return False


__all__ = [
    "PT_901_LIMITATIONS",
    "RUNTIME_STATE_NOTE",
    "DeviceObservation",
    "InterfaceObservation",
    "LiveObservationSet",
    "ObservedFact",
    "RouteObservation",
    "SupportStatus",
    "UnsupportedObservation",
    "collect",
    "parse_interface_output",
    "parse_route_output",
    "prediction_agrees",
    "runtime_state_available",
    "runtime_state_note",
    "support_status",
    "unsupported_reason",
]
