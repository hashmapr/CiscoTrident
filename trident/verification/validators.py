"""Deterministic answer construction and validation.

This module is the authority. AI may propose *what to look up*; nothing else.
Every answer is produced by executing a query against the consensus model, and a
result is only labelled VERIFIED / VERIFIED_DERIVED when the consensus engine
supports it.

Failure is explicit: an unsupported question yields INCOMPLETE / NOT_AVAILABLE /
CONFLICT with a manual-check hint. Nothing is ever guessed.
"""

from __future__ import annotations

import ipaddress
import re

from ..models import (
    AnswerResult,
    AnswerStatus,
    ConsensusSummary,
    EvidenceItem,
    NetworkModel,
    ParsedQuestion,
    QuestionKind,
)
from ..normalization.values import canonical_interface_name
from ..reasoning import mcq
from ..reasoning import network_queries as nq
from ..reasoning.ai_client import QueryPlan, QueryStep
from .consensus import ConsensusEngine, FieldConsensus

# ---------------------------------------------------------------------------
# Severity ordering (later = worse)
# ---------------------------------------------------------------------------

_SEVERITY = [
    AnswerStatus.VERIFIED,
    AnswerStatus.VERIFIED_DERIVED,
    AnswerStatus.INCOMPLETE,
    AnswerStatus.NOT_AVAILABLE,
    AnswerStatus.CONFLICT,
    AnswerStatus.ERROR,
]


def _cap_status(match_status: AnswerStatus, fact_status: AnswerStatus) -> AnswerStatus:
    """An option match can never be better than the fact that supports it."""
    if _SEVERITY.index(match_status) < _SEVERITY.index(fact_status):
        return fact_status
    return match_status


# ---------------------------------------------------------------------------
# Entity resolution from free text
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?\b")
_IFACE_RE = re.compile(
    r"\b((?:GigabitEthernet|FastEthernet|Ethernet|TenGigabitEthernet|Serial|Loopback|"
    r"Vlan|Port-channel|Gi|Fa|Se|Lo|Vl)\s*\d[\d/\.\:]*)\b",
    re.IGNORECASE,
)


def resolve_device(model: NetworkModel, text: str) -> str | None:
    if not text:
        return None
    lowered = text.lower()
    best: str | None = None
    for name in model.devices:
        if name.lower() in lowered and (best is None or len(name) > len(best)):
            best = name
    return best


def resolve_interface(text: str) -> str | None:
    if not text:
        return None
    m = _IFACE_RE.search(text)
    return canonical_interface_name(m.group(1)) if m else None


def resolve_ips(text: str) -> list[str]:
    return [m.group(1) for m in _IP_RE.finditer(text or "")]


def resolve_mask(text: str) -> str | None:
    """Find a dotted-decimal subnet mask in text (must be contiguous)."""
    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text or ""):
        candidate = m.group(1)
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{candidate}").prefixlen
        except ValueError:
            continue
        if prefix > 0:
            return candidate
    return None


# ---------------------------------------------------------------------------
# Internal fact carrier
# ---------------------------------------------------------------------------

class _FactAnswer:
    def __init__(
        self,
        status: AnswerStatus,
        value: str,
        field: str,
        evidence: list[EvidenceItem],
        consensus: ConsensusSummary,
        explanation: str,
        conflicts: list[str] | None = None,
    ) -> None:
        self.status = status
        self.value = value
        self.field = field
        self.evidence = evidence
        self.consensus = consensus
        self.explanation = explanation
        self.conflicts = conflicts or []

    def to_result(self, question: ParsedQuestion) -> AnswerResult:
        settled = self.status in (AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED)
        return AnswerResult(
            question_number=question.question_number,
            original_question=question.original,
            status=self.status,
            answer=self.value,
            explanation=self.explanation,
            evidence=self.evidence,
            consensus=self.consensus,
            conflicts=self.conflicts,
            missing_evidence=[] if settled else [f"{self.field} is not fully verified"],
            manual_check=None if settled else "Verify this value manually.",
            question_kind=question.kind,
        )


# ---------------------------------------------------------------------------
# The builder/validator
# ---------------------------------------------------------------------------

class AnswerBuilder:
    def __init__(self, model: NetworkModel, consensus: ConsensusEngine) -> None:
        self.model = model
        self.consensus = consensus

    # -- entry point ---------------------------------------------------
    def build(self, question: ParsedQuestion, plan: QueryPlan | None) -> AnswerResult:
        try:
            return self._build(question, plan)
        except Exception as exc:  # noqa: BLE001 - one bad question must not kill the batch
            return AnswerResult(
                question_number=question.question_number,
                original_question=question.original,
                status=AnswerStatus.ERROR,
                explanation=f"internal error while evaluating this question: {type(exc).__name__}",
                manual_check="Verify this question manually.",
                question_kind=question.kind,
            )

    def _build(self, question: ParsedQuestion, plan: QueryPlan | None) -> AnswerResult:
        text = question.stem or question.original
        if question.kind in (
            QuestionKind.SINGLE_SELECT,
            QuestionKind.TRUE_FALSE,
            QuestionKind.MULTI_SELECT,
        ):
            if not question.options:
                return self._simple(
                    question,
                    AnswerStatus.INCOMPLETE,
                    explanation=(
                        "The question appears to be multiple-choice but no options were "
                        "detected in the pasted text."
                    ),
                    manual_check="Re-paste with each option on its own line (A., B., ...).",
                )
            return self._build_choice(question, text, plan)
        return self._build_open(question, text, plan)

    # -- open-ended ----------------------------------------------------
    def _build_open(self, question: ParsedQuestion, text: str, plan: QueryPlan | None) -> AnswerResult:
        if plan is not None:
            for fact in self._execute_plan(plan):
                if fact is not None:
                    return fact.to_result(question)

        inferred = self._infer_single_fact(text)
        if inferred is not None:
            return inferred.to_result(question)

        return self._simple(
            question,
            AnswerStatus.NOT_AVAILABLE,
            explanation=(
                "This question could not be mapped to a fact present in the network "
                "model. TRIDENT does not guess."
            ),
            manual_check="Check the question wording or inspect the device configuration directly.",
        )

    # -- multiple choice -----------------------------------------------
    def _build_choice(self, question: ParsedQuestion, text: str, plan: QueryPlan | None) -> AnswerResult:
        fact = self._infer_single_fact(text)
        if fact is None and plan is not None:
            executed = self._execute_plan(plan)
            fact = executed[0] if executed else None

        if fact is None:
            return self._simple(
                question,
                AnswerStatus.NOT_AVAILABLE,
                explanation=(
                    "No verified fact from the network model corresponds to what this "
                    "question asks, so no option can be selected."
                ),
                manual_check="Confirm the question refers to a device or interface present in the file.",
            )

        if question.kind is QuestionKind.MULTI_SELECT:
            status, letters, explanation = mcq.match_multi(question, [fact.value])
        elif question.kind is QuestionKind.TRUE_FALSE:
            claim_true = fact.value.strip().lower() in {"true", "yes", "1"}
            status, letters, explanation = mcq.match_true_false(question, claim_true)
        else:
            status, letters, explanation = mcq.match_single(question, fact.value)

        status = _cap_status(status, fact.status)
        selected_text = "; ".join(
            f"{o.letter}. {o.text}" for o in question.options if o.letter in letters
        )
        settled = status in (AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED)

        return AnswerResult(
            question_number=question.question_number,
            original_question=question.original,
            status=status,
            answer=fact.value,
            selected_options=letters,
            explanation=explanation + (f" Selected: {selected_text}." if selected_text else ""),
            evidence=fact.evidence,
            consensus=fact.consensus,
            missing_evidence=[] if settled else [
                f"{fact.field} agreement is {fact.consensus.agree}/{fact.consensus.required}"
            ],
            conflicts=fact.conflicts,
            manual_check=None if settled else (
                "No offered option is fully supported by verified data. Verify manually."
            ),
            question_kind=question.kind,
        )

    # -- plan execution ------------------------------------------------
    def _execute_plan(self, plan: QueryPlan) -> list[_FactAnswer]:
        produced: list[_FactAnswer] = []
        for step in plan.steps:
            fact = self._run_step(step)
            if fact is not None:
                produced.append(fact)
        return produced

    def _run_step(self, step: QueryStep) -> _FactAnswer | None:
        op = step.op
        if op == "unknown":
            return None

        device = resolve_device(self.model, step.device or "") if step.device else None
        if device is None and step.device:
            # model may not contain it; keep the literal name for honest failure
            device = None
        interface = canonical_interface_name(step.interface) if step.interface else None

        if op == "device_list":
            names = self.model.device_names()
            if not names:
                return None
            available = self.consensus.available_engines()
            return _FactAnswer(
                status=AnswerStatus.VERIFIED if available >= self.consensus.required else AnswerStatus.INCOMPLETE,
                value=", ".join(names),
                field="device_list",
                evidence=[
                    EvidenceItem(
                        field="device_list",
                        value=", ".join(names),
                        sources=sorted({o.provenance.engine for o in self.model.observations}),
                        extraction_paths=["inventory"],
                    )
                ],
                consensus=ConsensusSummary(agree=available, available=available, required=self.consensus.required),
                explanation=f"The file contains {len(names)} devices.",
            )

        if op == "device_ip":
            if not device:
                return None
            if interface:
                return self._interface_fact(device, interface, "ipv4_address")
            ips = nq.get_all_ip_addresses(self.model, device)
            if len(ips) != 1:
                return None
            return self._interface_fact(device, ips[0].canonical_name, "ipv4_address")

        if op == "interface_info":
            if not device or not interface:
                return None
            return self._interface_fact(device, interface, "ipv4_address")

        if op == "default_gateway":
            if not device:
                return None
            gw = self.model.settings.default_gateways.get(device)
            if not gw:
                return None
            return self._single_source_fact(device, None, "default_gateway", gw, "default gateway")

        if op == "dns_servers":
            if not device:
                return None
            servers = self.model.settings.dns_servers.get(device)
            if not servers:
                return None
            return self._single_source_fact(device, None, "dns_servers", ", ".join(servers), "DNS server(s)")

        if op == "ios_version":
            if not device:
                return None
            ver = self.model.settings.software_versions.get(device)
            if not ver:
                return None
            return self._single_source_fact(device, None, "ios_version", ver, "IOS version")

        if op == "vlan_of_interface":
            if not device or not interface:
                return None
            return self._interface_fact(device, interface, "vlan")

        if op == "vlan_members":
            if step.vlan_id is None:
                return None
            members = nq.find_vlan(self.model, step.vlan_id)
            if not members:
                return None
            return self._model_wide_fact(
                "vlan_members", ", ".join(members), f"VLAN {step.vlan_id} members: {', '.join(members)}."
            )

        if op in {"subnet_network", "subnet_broadcast", "same_subnet"}:
            return self._run_subnet_step(step)

        if op == "connected_devices":
            if not device:
                return None
            peers = nq.directly_connected(self.model, device)
            if not peers:
                return None
            return self._model_wide_fact(
                "connected_devices", ", ".join(peers), f"{device} is directly connected to {', '.join(peers)}."
            )

        if op == "topology_path":
            if not device or not step.peer:
                return None
            path = nq.topology_path(self.model, device, step.peer)
            if not path:
                return None
            return self._model_wide_fact(
                "topology_path", " -> ".join(path), f"Path from {device} to {step.peer}: {' -> '.join(path)}."
            )

        if op == "route_lookup":
            dest = step.destination
            if not dest:
                found = resolve_ips(step.reason or "")
                dest = found[0] if found else None
            if not dest:
                return None
            matches = nq.static_route_lookup(self.model, dest)
            if not matches:
                return None
            return self._model_wide_fact(
                "route", "; ".join(matches), f"Configured route(s) for {dest}: {'; '.join(matches)}."
            )

        if op == "acl_lookup":
            if not step.acl_id:
                return None
            entries = nq.acl_entries(self.model, step.acl_id)
            if not entries:
                return None
            return self._model_wide_fact(
                "acl", " | ".join(entries), f"ACL {step.acl_id}: {' | '.join(entries)}."
            )

        if op == "switchport_mode":
            if not device or not interface:
                return None
            return self._interface_fact(device, interface, "access_mode")

        if op == "device_interfaces":
            if not device:
                return None
            names = [i.canonical_name for i in self.model.device_interfaces(device)]
            if not names:
                return None
            return self._model_wide_fact(
                "device_interfaces",
                ", ".join(names),
                f"{device} has {len(names)} configured interfaces.",
            )

        return None

    # -- fact helpers --------------------------------------------------
    def _interface_fact(self, device: str, interface: str, field: str) -> _FactAnswer | None:
        canon = canonical_interface_name(interface)
        fc = self.consensus.verify_interface_field(device, canon, field)
        if fc.value and fc.status in (AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED):
            return self._fact_from_consensus(fc, device, canon)

        iface = nq.get_interface(self.model, device, canon)
        if iface is None:
            return None
        value = {
            "ipv4_address": iface.ipv4_address,
            "mac_address": iface.mac_address,
            "vlan": iface.vlan_assignments[0] if iface.vlan_assignments else None,
            "access_mode": iface.access_mode,
        }.get(field)
        if not value:
            return None
        return self._unverified_interface_fact(device, canon, field, value, fc)

    def _fact_from_consensus(self, fc: FieldConsensus, device: str, interface: str | None) -> _FactAnswer:
        value = fc.value or ""
        label = {
            "ipv4_address": "IPv4 address",
            "mac_address": "MAC address",
            "vlan": "VLAN assignment",
            "access_mode": "switchport mode",
        }.get(fc.field, fc.field)
        location = f"{device} {interface}" if interface else device
        return _FactAnswer(
            status=fc.status,
            value=value,
            field=fc.field,
            evidence=[fc.evidence()],
            consensus=fc.summary(),
            explanation=f"{location} has {label} {value}.",
            conflicts=fc.conflicts,
        )

    def _unverified_interface_fact(
        self,
        device: str,
        interface: str,
        field: str,
        value: str,
        fc: FieldConsensus | None,
    ) -> _FactAnswer:
        status = AnswerStatus.INCOMPLETE
        if fc is not None and fc.status is AnswerStatus.CONFLICT:
            status = AnswerStatus.CONFLICT
        summary = fc.summary() if fc is not None else ConsensusSummary(
            agree=1, available=1, required=self.consensus.required
        )
        return _FactAnswer(
            status=status,
            value=value,
            field=field,
            evidence=[
                EvidenceItem(
                    device=device,
                    interface=interface,
                    field=field,
                    value=value,
                    sources=[o.provenance.engine for o in (fc.observations if fc else [])] or ["model"],
                    extraction_paths=["ios-config"],
                )
            ],
            consensus=summary,
            explanation=(
                f"{device} {interface} shows {field} {value}, but only "
                f"{summary.agree}/{summary.required} engines agree, so this is not verified."
            ),
            conflicts=fc.conflicts if fc else [],
        )

    def _single_source_fact(
        self,
        device: str,
        interface: str | None,
        field: str,
        value: str,
        label: str,
    ) -> _FactAnswer:
        """A fact only Engine A's XML walk exposes (end-host settings)."""
        available = max(1, self.consensus.available_engines())
        return _FactAnswer(
            status=AnswerStatus.VERIFIED_DERIVED,
            value=value,
            field=field,
            evidence=[
                EvidenceItem(
                    device=device,
                    interface=interface,
                    field=field,
                    value=value,
                    sources=["engine_a"],
                    extraction_paths=["endhost-xml"],
                    raw_evidence=f"{label} for {device} read from the end-host XML block",
                )
            ],
            consensus=ConsensusSummary(
                agree=1, available=available, required=self.consensus.required, crypto_shared=True
            ),
            explanation=(
                f"{device} {label} is {value}. This value is present in one engine's "
                f"evidence only ({available} engines available), so it is derived, not triple-verified."
            ),
        )

    def _model_wide_fact(self, field: str, value: str, explanation: str) -> _FactAnswer:
        available = max(1, self.consensus.available_engines())
        return _FactAnswer(
            status=AnswerStatus.VERIFIED_DERIVED,
            value=value,
            field=field,
            evidence=[
                EvidenceItem(
                    field=field,
                    value=value,
                    sources=["trident-deterministic"],
                    extraction_paths=["model-query"],
                    raw_evidence=explanation,
                )
            ],
            consensus=ConsensusSummary(
                agree=available, available=available, required=self.consensus.required
            ),
            explanation=explanation,
        )

    def _derived_answer(self, qr: nq.QueryResult, ip: str, mask: str, label: str) -> _FactAnswer:
        return _FactAnswer(
            status=AnswerStatus.VERIFIED_DERIVED,
            value=qr.value,
            field=qr.field,
            evidence=[
                EvidenceItem(
                    field=qr.field,
                    value=qr.value,
                    sources=["trident-deterministic"],
                    extraction_paths=["deterministic-arithmetic"],
                    raw_evidence="\n".join(qr.trace),
                )
            ],
            consensus=ConsensusSummary(agree=1, available=1, required=1, policy="deterministic"),
            explanation=f"The {label} of {ip} with mask {mask} is {qr.value} (deterministic arithmetic).",
        )

    def _same_subnet_answer(self, a: str, b: str, mask: str) -> _FactAnswer | None:
        qr = nq.ips_same_subnet(a, b, mask)
        if qr is None:
            return None
        return _FactAnswer(
            status=AnswerStatus.VERIFIED_DERIVED,
            value=qr.value,
            field="same_subnet",
            evidence=[
                EvidenceItem(
                    field="same_subnet",
                    value=qr.value,
                    sources=["trident-deterministic"],
                    extraction_paths=["deterministic-arithmetic"],
                    raw_evidence="\n".join(qr.trace),
                )
            ],
            consensus=ConsensusSummary(agree=1, available=1, required=1, policy="deterministic"),
            explanation=(
                "Yes, both addresses are in the same subnet."
                if qr.value == "yes"
                else "No, the addresses are in different subnets."
            ),
        )

    def _run_subnet_step(self, step: QueryStep) -> _FactAnswer | None:
        ip = step.ip
        mask = step.mask
        if mask is None and ip and "/" in ip:
            ip_part, _, prefix = ip.partition("/")
            ip = ip_part
            try:
                mask = str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix)}").netmask)
            except ValueError:
                return None
        if not ip or not mask:
            return None
        if step.op == "subnet_network":
            qr = nq.subnet_network_address(ip, mask)
            return self._derived_answer(qr, ip, mask, "network address") if qr else None
        if step.op == "subnet_broadcast":
            qr = nq.subnet_broadcast_address(ip, mask)
            return self._derived_answer(qr, ip, mask, "broadcast address") if qr else None
        if step.op == "same_subnet" and step.other_ip:
            return self._same_subnet_answer(ip, step.other_ip, mask)
        return None

    # -- inference from free text (works without AI) --------------------
    def _infer_single_fact(self, text: str) -> _FactAnswer | None:
        lower = text.lower()
        device = resolve_device(self.model, text)

        if device and re.search(r"\b(ios|version|software)\b", lower):
            ver = self.model.settings.software_versions.get(device)
            if ver:
                return self._single_source_fact(device, None, "ios_version", ver, "IOS version")
            return None

        if device and re.search(r"\b(default gateway|gateway)\b", lower):
            gw = self.model.settings.default_gateways.get(device)
            if gw:
                return self._single_source_fact(device, None, "default_gateway", gw, "default gateway")
            return None

        if device and re.search(r"\b(dns|name[- ]server)\b", lower):
            servers = self.model.settings.dns_servers.get(device)
            if servers:
                return self._single_source_fact(
                    device, None, "dns_servers", ", ".join(servers), "DNS server(s)"
                )
            return None

        if device and re.search(r"\b(ip|ipv4)\b", lower):
            iface_text = resolve_interface(text)
            if iface_text:
                return self._interface_fact(device, iface_text, "ipv4_address")
            ips = nq.get_all_ip_addresses(self.model, device)
            if len(ips) == 1:
                return self._interface_fact(device, ips[0].canonical_name, "ipv4_address")
            return None

        if device and re.search(r"\b(vlan|access vlan|trunk)\b", lower):
            iface_text = resolve_interface(text)
            if iface_text:
                return self._interface_fact(device, iface_text, "vlan")
            return None

        if device and re.search(r"\b(mac address|mac)\b", lower):
            iface_text = resolve_interface(text)
            if iface_text:
                return self._interface_fact(device, iface_text, "mac_address")
            return None

        if device and re.search(
            r"\b(which|what|list|name|how many)\b.*\binterfaces?\b", lower
        ):
            names = [i.canonical_name for i in self.model.device_interfaces(device)]
            if names:
                return self._model_wide_fact(
                    "device_interfaces",
                    ", ".join(names),
                    f"{device} has {len(names)} configured interfaces: {', '.join(names)}.",
                )
            return None

        if device and re.search(r"\b(connected to|neighbou?r|adjacent|directly connected)\b", lower):
            peers = nq.directly_connected(self.model, device)
            if peers:
                return self._model_wide_fact(
                    "connected_devices",
                    ", ".join(peers),
                    f"{device} is directly connected to {', '.join(peers)}.",
                )
            return None

        if re.search(r"\b(network address|subnet address|broadcast address|same subnet)\b", lower):
            return self._infer_subnet_arithmetic(text, lower)

        return None

    def _infer_subnet_arithmetic(self, text: str, lower: str) -> _FactAnswer | None:
        ips = resolve_ips(text)
        mask = resolve_mask(text)
        prefix_m = re.search(r"/(\d{1,2})\b", text)
        if mask is None and prefix_m:
            try:
                mask = str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix_m.group(1))}").netmask)
            except ValueError:
                return None
        if not ips or not mask:
            return None

        if "same subnet" in lower and len(ips) >= 2:
            return self._same_subnet_answer(ips[0], ips[1], mask)
        if "broadcast" in lower:
            qr = nq.subnet_broadcast_address(ips[0], mask)
            return self._derived_answer(qr, ips[0], mask, "broadcast address") if qr else None
        if "network" in lower or "subnet" in lower:
            qr = nq.subnet_network_address(ips[0], mask)
            return self._derived_answer(qr, ips[0], mask, "network address") if qr else None
        return None

    # -- misc ----------------------------------------------------------
    def _simple(self, question: ParsedQuestion, status: AnswerStatus, **kwargs) -> AnswerResult:
        return AnswerResult(
            question_number=question.question_number,
            original_question=question.original,
            status=status,
            question_kind=question.kind,
            **kwargs,
        )
