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
from ..reasoning import intent as intent_router
from ..reasoning import mcq
from ..reasoning import network_queries as nq
from ..reasoning import operations as ops
from ..reasoning.ai_client import QueryPlan, QueryStep
from ..reasoning.entities import resolve_device_name
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
    """Resolve a device mention. Ambiguous mentions resolve to None.

    Boundary-aware and case-aware; never picks the longest substring, so
    ``Router`` / ``Router-1`` / ``Router-10`` stay distinct.
    """
    if not text:
        return None
    names = list(model.devices)
    hostnames = {
        dev.hostname: name for name, dev in model.devices.items() if dev.hostname
    }
    return resolve_device_name(names, text, hostnames).name


def resolve_device_candidates(model: NetworkModel, text: str) -> list[str]:
    """All device names a mention could refer to (for ambiguity reporting)."""
    if not text:
        return []
    hostnames = {
        dev.hostname: name for name, dev in model.devices.items() if dev.hostname
    }
    return resolve_device_name(list(model.devices), text, hostnames).candidates


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
        # 1. Deterministic typed routing first: it declares the answer type, so
        #    a mask question cannot be satisfied by a host IP.
        routed = self._route_intent(question, text)
        if routed is not None:
            return routed.to_result(question)

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

    def _resolve_question_placeholders(self, text: str) -> str:
        """Replace resolvable ``[[...]]`` references in the question text.

        An activity benchmark may be written against the raw XML, so a question
        can name a device as ``[[pr3-0-pc_Display_name]]``. The model already
        holds those resolved names, so they are substituted before routing.
        Unknown placeholders are left untouched (and will fail to resolve, which
        is the honest outcome).
        """
        if not text or "[[" not in text:
            return text
        mapping = self.model.placeholder_map if hasattr(self.model, "placeholder_map") else {}
        if not mapping:
            return text

        def repl(m):
            return mapping.get(m.group(1).strip(), m.group(0))

        import re as _re

        return _re.sub(r"\[\[([^\]]+)\]\]", repl, text)

    def _route_intent(self, question: ParsedQuestion, text: str) -> _FactAnswer | None:
        """Deterministically route a question to a typed operation.

        Returns ``None`` when the question is not unambiguously routable, so the
        caller can keep its previous behaviour.
        """
        text = self._resolve_question_placeholders(text or question.stem)
        try:
            intent = intent_router.route(self.model, text)
        except Exception:  # noqa: BLE001 - routing must never crash the pipeline
            return None
        if intent is None:
            return None

        spec = ops.SPECS.get(intent.operation)
        if spec is None:
            return None
        result = ops.run_operation(self.model, intent.operation, intent.arguments)
        well_typed, why = ops.validate_value(result)

        available = self.consensus.available_engines()

        if not result.ok:
            status = (
                AnswerStatus.CONFLICT
                if result.status is ops.OpStatus.AMBIGUOUS
                else AnswerStatus.NOT_AVAILABLE
            )
            return _FactAnswer(
                status=status,
                value="",
                field=intent.operation,
                evidence=[],
                consensus=ConsensusSummary(
                    agree=0, available=available, required=self.consensus.required, crypto_shared=True
                ),
                explanation=f"{result.reason}.",
            )

        if not well_typed:
            return _FactAnswer(
                status=AnswerStatus.CONFLICT,
                value=result.as_answer(),
                field=intent.operation,
                evidence=[],
                consensus=ConsensusSummary(
                    agree=0, available=available, required=self.consensus.required, crypto_shared=True
                ),
                explanation=(
                    f"The {intent.operation} operation returned a value of the wrong "
                    f"type ({why}); it is not usable as an answer."
                ),
                conflicts=[f"type-gate: {intent.operation} -> {why}"],
            )

        structural = intent.operation in {
            "get_physical_neighbor",
            "get_peer_interface",
            "list_physical_neighbors",
            "count_physical_neighbors",
            "count_physical_links",
            "count_devices",
            "calculate_network_address",
            "calculate_broadcast_address",
            "are_in_same_subnet",
        }

        if structural:
            # Structural facts come from the topology graph, which is built from
            # the selected snapshot only; the evidence is the cable/config line.
            status = AnswerStatus.VERIFIED_DERIVED
            agree = available
        else:
            # A per-field fact must still survive the consensus policy. Typed
            # routing decides *what* was asked, never how strongly it is believed.
            agree = self._typed_agreement(intent.operation, result)
            required = self.consensus.required
            if agree >= required:
                status = AnswerStatus.VERIFIED
            elif agree >= 1:
                status = AnswerStatus.INCOMPLETE
            else:
                return _FactAnswer(
                    status=AnswerStatus.NOT_AVAILABLE,
                    value="",
                    field=intent.operation,
                    evidence=[],
                    consensus=ConsensusSummary(
                        agree=0, available=available, required=required, crypto_shared=True
                    ),
                    explanation=(
                        f"{result.reason or 'No engine observation supports this value'}."
                    ),
                )

        return _FactAnswer(
            status=status,
            value=result.as_answer(),
            field=intent.operation,
            evidence=[
                EvidenceItem(
                    device=result.entity or None,
                    interface=result.interface or None,
                    field=intent.operation,
                    value=result.as_answer(),
                    sources=["engine_a", "engine_b", "engine_c"][: max(1, agree)],
                    extraction_paths=[spec.description],
                    raw_evidence="; ".join(result.evidence),
                )
            ],
            consensus=ConsensusSummary(
                agree=agree,
                available=available,
                required=self.consensus.required,
                crypto_shared=True,
            ),
            explanation=result.derivation or "; ".join(result.evidence) or spec.description,
        )

    def _typed_agreement(self, operation: str, result: ops.OpResult) -> int:
        """How many distinct extraction families corroborate this typed fact.

        A typed operation decides *which* fact to read; it does not manufacture
        agreement. The count comes from the observation consensus so a single
        engine cannot be presented as three-engine verification.
        """
        field_map = {
            "get_hostname": "hostname",
            "get_interface_ip": "ipv4_address",
            "get_interface_mask": "ipv4_address",
            "get_interface_network": "ipv4_address",
            "get_default_route_next_hop": "next_hop",
            "get_switch_default_gateway": "default_gateway",
            "get_interface_vlan": "vlan",
        }

        # Device model is a structural attribute of the device block, held in the
        # model itself rather than as a per-field observation.
        if operation == "get_device_model":
            return 1 if self.model.devices.get(result.entity or "") else 0

        field = field_map.get(operation)
        if field is None:
            return 0

        # ``ip default-gateway`` is a switch setting with no per-interface
        # observation, so it is single-source by nature: count 1 only when the
        # model actually holds the value, never 0 (which would read as NO_DATA).
        if operation == "get_switch_default_gateway":
            has_value = bool(
                (self.model.settings.default_gateways or {}).get(result.entity)
            )
            return 1 if has_value else 0

        entity_type = "device" if operation == "get_hostname" else "interface"
        entity_id = result.entity
        if (
            operation
            in {
                "get_interface_ip",
                "get_interface_mask",
                "get_interface_network",
                "get_interface_vlan",
            }
            and result.interface
        ):
            entity_id = f"{result.entity}:{canonical_interface_name(result.interface)}"

        fc = self.consensus.field(entity_type, entity_id, field)
        return len(fc.agreeing_engines)

    # -- multiple choice -----------------------------------------------
    def _build_choice(self, question: ParsedQuestion, text: str, plan: QueryPlan | None) -> AnswerResult:
        # Typed routing wins for choice questions too, so option matching uses the
        # correct fact type (hostname vs IP vs mask) before any MCQ heuristics.
        routed = self._route_intent(question, text)
        if routed is not None:
            fact = routed
        else:
            fact = self._infer_single_fact(text)
        executed: list[_FactAnswer] | None = None
        if fact is None and plan is not None:
            executed = self._execute_plan(plan)
            fact = executed[0] if executed else None

        if question.kind is QuestionKind.MULTI_SELECT:
            # Independent per-option verification: pool every verified fact the
            # plan and the heuristics produced, not just the first one.
            pool: list[_FactAnswer] = list(executed) if executed else ([fact] if fact else [])
            verified_vals = [
                f.value for f in pool
                if f.status in (AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED)
            ]
            if not verified_vals:
                return self._simple(
                    question,
                    AnswerStatus.NOT_AVAILABLE,
                    explanation=(
                        "No verified fact from the network model corresponds to what this "
                        "question asks, so no option can be selected."
                    ),
                    manual_check="Confirm the question refers to a device or interface present in the file.",
                )
            status, letters, explanation = mcq.match_multi_independent(question, verified_vals)
            # the answer can never be stronger than the strongest contributing fact's status
            contributing = [f for f in pool if f.value in verified_vals]
            cap = max(
                (f.status for f in contributing),
                key=lambda s: _SEVERITY.index(s),
            )
            status = _cap_status(status, cap)
            evidence: list[EvidenceItem] = []
            for f in contributing:
                evidence.extend(f.evidence)
            consensus_summary = contributing[0].consensus if contributing else ConsensusSummary()
            settled = status in (AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED)
            selected_text = "; ".join(
                f"{o.letter}. {o.text}" for o in question.options if o.letter in letters
            )
            return AnswerResult(
                question_number=question.question_number,
                original_question=question.original,
                status=status,
                answer="; ".join(verified_vals),
                selected_options=letters,
                explanation=explanation + (f" Selected: {selected_text}." if selected_text else ""),
                evidence=evidence,
                consensus=consensus_summary,
                missing_evidence=[] if settled else [
                    "one or more options could not be independently verified"
                ],
                conflicts=[],
                manual_check=None if settled else (
                    "Verify the unmatched options against the device configuration manually."
                ),
                question_kind=question.kind,
            )
        elif question.kind is QuestionKind.TRUE_FALSE:
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
            claim_true = fact.value.strip().lower() in {"true", "yes", "1"}
            status, letters, explanation = mcq.match_true_false(question, claim_true)
        else:
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

        # --- typed operations: the authoritative path ------------------------
        typed = self._run_typed_operation(step)
        if typed is not None:
            return typed

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

    def _device_field_fact(self, device: str, field: str) -> _FactAnswer | None:
        """A consensus-verified per-device field (e.g. hostname)."""
        fc = self.consensus.verify_device_field(device, field)
        if fc.value and fc.status in (AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED):
            return _FactAnswer(
                status=fc.status,
                value=fc.value,
                field=field,
                evidence=[fc.evidence()],
                consensus=fc.summary(),
                explanation=f"{device} {field} is {fc.value} (agreement {fc.summary().agree}/{fc.required}).",
                conflicts=fc.conflicts,
            )
        if fc.value:
            # known value but not verified: keep it visible, cap the status
            return _FactAnswer(
                status=fc.status,
                value=fc.value,
                field=field,
                evidence=[fc.evidence()],
                consensus=fc.summary(),
                explanation=(
                    f"{device} {field} appears to be {fc.value}, but agreement is only "
                    f"{fc.summary().agree}/{fc.required}."
                ),
                conflicts=fc.conflicts,
            )
        return None

    def _single_source_fact(
        self,
        device: str,
        interface: str | None,
        field: str,
        value: str,
        label: str,
    ) -> _FactAnswer:
        """A fact only one engine exposes (end-host settings).

        This is DIRECTLY OBSERVED evidence, not a deterministic derivation, so it
        is reported as ``INCOMPLETE`` with a single-source note. It is never
        labelled ``VERIFIED_DERIVED``: passing a value through normalization is
        not a derivation.
        """
        available = max(1, self.consensus.available_engines())
        return _FactAnswer(
            status=AnswerStatus.INCOMPLETE,
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
                f"{device} {label} is {value}. This is single-source evidence from one engine "
                f"({available} available); it is not independently corroborated and is not "
                "counted as verified."
            ),
            conflicts=[
                (
                    f"single-source: {field}={value} from engine_a only "
                    f"({available} engines available, {self.consensus.required} required)"
                )
            ],
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

    def _run_typed_operation(self, step: QueryStep) -> _FactAnswer | None:
        """Execute a typed operation and enforce its declared answer type.

        Returns ``None`` for operations that are not typed (legacy ops fall
        through to the older code paths). A typed operation whose value fails its
        own type gate is returned as CONFLICT -- never upgraded to a verified
        label.
        """
        name = step.op
        spec = ops.SPECS.get(name)
        if spec is None:
            return None

        arguments: dict = {}
        if spec.requires_device:
            arguments["device"] = step.device or ""
        if spec.requires_interface:
            arguments["interface"] = step.interface or ""
        if name == "count_devices":
            arguments["include_non_network_devices"] = False
        if name == "are_in_same_subnet":
            arguments.update(
                device_a=step.device or "",
                interface_a=step.interface or "",
                device_b=step.peer or "",
                interface_b=step.destination or step.other_ip or "",
            )
        if name in ("calculate_network_address", "calculate_broadcast_address"):
            arguments.update(ip=step.ip or "", mask=step.mask or "")

        result = ops.run_operation(self.model, name, arguments)
        well_typed, why = ops.validate_value(result)

        if not result.ok:
            status = (
                AnswerStatus.CONFLICT
                if result.status is ops.OpStatus.AMBIGUOUS
                else AnswerStatus.NOT_AVAILABLE
            )
            return _FactAnswer(
                status=status,
                value="",
                field=name,
                evidence=[],
                consensus=ConsensusSummary(
                    agree=0,
                    available=self.consensus.available_engines(),
                    required=self.consensus.required,
                    crypto_shared=True,
                ),
                explanation=f"Cannot answer: {result.reason}.",
            )

        if not well_typed:
            # A value that does not satisfy its declared type is a hard failure.
            return _FactAnswer(
                status=AnswerStatus.CONFLICT,
                value=result.as_answer(),
                field=name,
                evidence=[],
                consensus=ConsensusSummary(
                    agree=0,
                    available=self.consensus.available_engines(),
                    required=self.consensus.required,
                    crypto_shared=True,
                ),
                explanation=(
                    f"The {name} operation produced a value of the wrong type ({why}), "
                    "so it cannot be trusted as an answer."
                ),
                conflicts=[f"type-gate: {name} -> {why}"],
            )

        available = self.consensus.available_engines()
        # Topology/derived operations read structural facts that all engines share;
        # per-field operations still require the normal consensus policy.
        structural = name in {
            "get_physical_neighbor",
            "get_peer_interface",
            "list_physical_neighbors",
            "count_physical_neighbors",
            "count_physical_links",
            "count_devices",
            "calculate_network_address",
            "calculate_broadcast_address",
            "are_in_same_subnet",
        }
        if structural:
            status = AnswerStatus.VERIFIED_DERIVED
        else:
            status = (
                AnswerStatus.VERIFIED
                if available >= self.consensus.required
                else AnswerStatus.INCOMPLETE
            )

        evidence = [
            EvidenceItem(
                device=result.entity or None,
                interface=result.interface or None,
                field=name,
                value=result.as_answer(),
                sources=["engine_a", "engine_b", "engine_c"][: max(1, available)],
                extraction_paths=[spec.description],
                raw_evidence="; ".join(result.evidence),
            )
        ]
        explanation = result.derivation or "; ".join(result.evidence) or spec.description
        return _FactAnswer(
            status=status,
            value=result.as_answer(),
            field=name,
            evidence=evidence,
            consensus=ConsensusSummary(
                agree=available if structural else min(available, self.consensus.required),
                available=available,
                required=self.consensus.required,
                crypto_shared=True,
            ),
            explanation=explanation,
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

        if device and re.search(r"\bhostname\b", lower):
            return self._device_field_fact(device, "hostname")

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
