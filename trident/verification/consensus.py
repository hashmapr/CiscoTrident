"""Three-engine consensus verification.

Consensus policy (strict, the default)
--------------------------------------
An observation is **VERIFIED** only when *all* of the following hold:

1. At least ``required`` (default 3) **distinct extraction families** produced the
   field for the same canonical entity.
2. The normalised values agree exactly.
3. All evidence belongs to the same snapshot.
4. No conflicting evidence remains from a successful engine.

Independence caveat
-------------------
All three engines decode the container with the same public Twofish-EAX algorithm.
Decryption is therefore **not** three independent observations. Independence is
only claimed for the *extraction* step (IOS-config parsing / XML semantics).

TRIDENT records ``crypto_shared=True`` on every observation and surfaces it in the
consensus summary. A result can be VERIFIED at the extraction layer while still
reporting that the container decode was shared — it is never silently presented as
three fully independent confirmations.
"""

from __future__ import annotations

from collections import defaultdict

from ..config import Settings
from ..config import settings as default_settings
from ..models import (
    AnswerStatus,
    ConsensusSummary,
    EvidenceItem,
    NetworkModel,
    Observation,
)
from ..normalization.values import canonical_interface_name, normalize_mac

#: Fields whose values must be compared after MAC canonicalisation.
_MAC_FIELDS = {"mac_address", "endhost_mac"}
#: Fields compared after interface-name canonicalisation.
_IFACE_FIELDS = {"interface", "link_interface"}


class FieldConsensus:
    """Consensus for one (entity, field) pair."""

    def __init__(
        self,
        entity_type: str,
        entity_id: str,
        field: str,
        observations: list[Observation],
        required: int,
        policy: str,
    ) -> None:
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.field = field
        self.observations = observations
        self.required = required
        self.policy = policy

        self._by_value: dict[str, list[Observation]] = defaultdict(list)
        for obs in observations:
            self._by_value[_canonical(field, obs.value)].append(obs)

        self.engines = {obs.provenance.engine for obs in observations}
        self.crypto_shared = all(o.provenance.crypto_shared for o in observations)

    # -- state ------------------------------------------------------------
    @property
    def available(self) -> int:
        return len(self.engines)

    @property
    def status(self) -> AnswerStatus:
        if not self.observations:
            return AnswerStatus.NOT_AVAILABLE

        if len(self._by_value) > 1:
            return AnswerStatus.CONFLICT

        best_value = max(self._by_value, key=lambda v: len(self._by_value[v]))
        agreeing_engines = {o.provenance.engine for o in self._by_value[best_value]}

        if len(agreeing_engines) >= self.required:
            return AnswerStatus.VERIFIED

        # Deterministic policy: a single trusted derivation may be VERIFIED_DERIVED
        if self.policy == "deterministic" and len(agreeing_engines) >= 1 and self.required <= 2:
            return AnswerStatus.VERIFIED_DERIVED

        if len(agreeing_engines) >= 2 and self.policy == "two_engine" and self.required <= 2:
            return AnswerStatus.VERIFIED

        return AnswerStatus.INCOMPLETE

    @property
    def value(self) -> str | None:
        if not self._by_value:
            return None
        if len(self._by_value) > 1:
            return None
        return next(iter(self._by_value))

    @property
    def agreeing_engines(self) -> list[str]:
        val = self.value
        if val is None:
            return []
        return sorted({o.provenance.engine for o in self._by_value[val]})

    @property
    def conflicts(self) -> list[str]:
        if len(self._by_value) <= 1:
            return []
        parts = []
        for value, obs in sorted(self._by_value.items()):
            engines = sorted({o.provenance.engine for o in obs})
            parts.append(f"{value} (from {', '.join(engines)})")
        return [f"{self.entity_id}.{self.field}: " + " vs ".join(parts)]

    def summary(self) -> ConsensusSummary:
        agreeing = len(self.agreeing_engines)
        if self.status is AnswerStatus.CONFLICT:
            agreeing = max(len({o.provenance.engine for o in obs}) for obs in self._by_value.values())
        return ConsensusSummary(
            agree=agreeing,
            available=self.available,
            required=self.required,
            policy=self.policy,
            crypto_shared=self.crypto_shared,
        )

    def evidence(self) -> EvidenceItem:
        val = self.value
        if val is None and self._by_value:
            val = " | ".join(sorted(self._by_value))
        device, interface = _split_entity(self.entity_id, self.entity_type)
        raw_lines = []
        for obs in self.observations[:3]:
            if obs.raw_evidence and obs.raw_evidence not in raw_lines:
                raw_lines.append(obs.raw_evidence)
        return EvidenceItem(
            device=device,
            interface=interface,
            field=self.field,
            value=val or "",
            sources=self.agreeing_engines or sorted(self.engines),
            extraction_paths=sorted({o.provenance.extraction_path for o in self.observations}),
            raw_evidence="\n".join(raw_lines),
        )


def _canonical(field: str, value: str) -> str:
    if field in _MAC_FIELDS:
        return normalize_mac(value) or value.strip().lower()
    if field in _IFACE_FIELDS:
        return canonical_interface_name(value)
    return value.strip().lower()


def _split_entity(entity_id: str, entity_type: str) -> tuple[str | None, str | None]:
    if entity_type == "interface" and ":" in entity_id:
        device, iface = entity_id.split(":", 1)
        return device, iface
    if entity_type == "device":
        return entity_id, None
    return None, None


class ConsensusEngine:
    """Adjudicates consensus for a whole network model."""

    def __init__(self, model: NetworkModel, cfg: Settings | None = None) -> None:
        self.model = model
        self.cfg = cfg or default_settings
        self.policy = self.cfg.consensus_policy
        self._groups: dict[tuple[str, str, str], list[Observation]] = defaultdict(list)
        for obs in model.observations:
            self._groups[(obs.entity_type, obs.entity_id, obs.field)].append(obs)

    # ------------------------------------------------------------------
    def available_engines(self) -> int:
        return len({o.provenance.engine for o in self.model.observations})

    @property
    def required(self) -> int:
        """How many agreeing engines a VERIFIED result demands."""
        available = self.available_engines()
        if self.policy == "strict":
            return 3
        if self.policy == "two_engine":
            return min(2, max(available, 1))
        return min(3, max(available, 1))

    # ------------------------------------------------------------------
    def field(self, entity_type: str, entity_id: str, field: str) -> FieldConsensus:
        obs = self._groups.get((entity_type, entity_id, field), [])
        return FieldConsensus(entity_type, entity_id, field, obs, self.required, self.policy)

    def verify_interface_field(self, device: str, interface: str, field: str) -> FieldConsensus:
        canon = canonical_interface_name(interface)
        return self.field("interface", f"{device}:{canon}", field)

    def verify_device_field(self, device: str, field: str) -> FieldConsensus:
        return self.field("device", device, field)

    # ------------------------------------------------------------------
    def all_conflicts(self) -> list[str]:
        out: list[str] = []
        for (entity_type, entity_id, field), obs in sorted(self._groups.items()):
            fc = FieldConsensus(entity_type, entity_id, field, obs, self.required, self.policy)
            out.extend(fc.conflicts)
        return out

    def consensus_map(self) -> dict[str, dict]:
        """Compact machine-readable view used by the UI and exports."""
        result: dict[str, dict] = {}
        for (entity_type, entity_id, field), obs in sorted(self._groups.items()):
            fc = FieldConsensus(entity_type, entity_id, field, obs, self.required, self.policy)
            result[f"{entity_id}.{field}"] = {
                "status": fc.status.value,
                "value": fc.value,
                "agree": len(fc.agreeing_engines),
                "available": fc.available,
                "required": self.required,
                "engines": fc.agreeing_engines,
                "conflicts": fc.conflicts,
            }
        return result


def derived_result(
    value: str,
    field: str,
    inputs: list[FieldConsensus],
    trace: list[str],
    device: str | None = None,
    interface: str | None = None,
) -> tuple[AnswerStatus, str, list[EvidenceItem], ConsensusSummary]:
    """Build a VERIFIED_DERIVED answer from verified inputs.

    The derivation is only VERIFIED_DERIVED when *every* input is itself VERIFIED
    (or VERIFIED_DERIVED). Otherwise the status degrades honestly.
    """
    evidence: list[EvidenceItem] = []
    # Severity order: later entries are worse and win.
    severity = [
        AnswerStatus.VERIFIED,
        AnswerStatus.VERIFIED_DERIVED,
        AnswerStatus.INCOMPLETE,
        AnswerStatus.NOT_AVAILABLE,
        AnswerStatus.CONFLICT,
        AnswerStatus.ERROR,
    ]
    worst = AnswerStatus.VERIFIED_DERIVED
    for fc in inputs:
        evidence.append(fc.evidence())
        if severity.index(fc.status) > severity.index(worst):
            worst = fc.status

    if worst is AnswerStatus.VERIFIED_DERIVED:
        # add the calculation itself as explicit evidence
        evidence.append(
            EvidenceItem(
                device=device,
                interface=interface,
                field=field,
                value=value,
                sources=["trident-deterministic"],
                extraction_paths=["deterministic-arithmetic"],
                raw_evidence="\n".join(trace),
            )
        )

    agree = min((len(fc.agreeing_engines) for fc in inputs), default=0)
    available = max((fc.available for fc in inputs), default=0)
    summary = ConsensusSummary(
        agree=agree,
        available=available,
        required=inputs[0].required if inputs else 3,
        policy=inputs[0].policy if inputs else "strict",
        crypto_shared=all(fc.crypto_shared for fc in inputs) if inputs else True,
    )
    return worst, value, evidence, summary
