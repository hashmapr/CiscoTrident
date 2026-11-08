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


def _extraction_family(obs: Observation) -> str:
    """The independent extraction pipeline that produced this observation.

    Prefers the explicit ``extraction_family`` layer (B); falls back to the
    ``family:how`` prefix in ``extraction_path``. A missing family cannot
    participate in verification.
    """
    if obs.provenance.extraction_family:
        return obs.provenance.extraction_family.strip().lower()
    return (obs.provenance.extraction_path or "").split(":", 1)[0].strip().lower()


def _interpretation_family(obs: Observation) -> str:
    """Layer C. When every engine shares one parser, agreement is one opinion."""
    return (obs.provenance.interpretation_family or "").strip().lower()


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
        expected_snapshot: str = "",
    ) -> None:
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.field = field
        self.observations = observations
        self.required = required
        self.policy = policy
        self.expected_snapshot = expected_snapshot

        self._by_value: dict[str, list[Observation]] = defaultdict(list)
        for obs in observations:
            self._by_value[_canonical(field, obs.value)].append(obs)

        self.engines = {obs.provenance.engine for obs in observations}
        self.crypto_shared = all(o.provenance.crypto_shared for o in observations)

    # -- state ------------------------------------------------------------
    @property
    def available(self) -> int:
        return len(self.engines)

    def _verification_blockers(self, obs: list[Observation]) -> list[str]:
        """Structural checks that must hold before any verification status."""
        blockers: list[str] = []
        families = {_extraction_family(o) for o in obs}
        if "" in families:
            blockers.append("missing extraction family in provenance")
        snapshots = {o.provenance.snapshot for o in obs}
        if not self.expected_snapshot:
            blockers.append("model has no snapshot identity; cannot bind evidence to one snapshot")
        elif len(snapshots) > 1:
            blockers.append("observations reference different snapshots")
        elif snapshots != {self.expected_snapshot}:
            blockers.append(
                "observations do not carry the selected snapshot id"
            )
        return blockers

    @property
    def status(self) -> AnswerStatus:
        if not self.observations:
            return AnswerStatus.NOT_AVAILABLE

        if len(self._by_value) > 1:
            # Conflicting values remain a conflict regardless of policy.
            return AnswerStatus.CONFLICT

        best_value = max(self._by_value, key=lambda v: len(self._by_value[v]))
        agreeing = list(self._by_value[best_value])
        agreeing_engines = {o.provenance.engine for o in agreeing}

        # Policy floors: availability never lowers the verification bar.
        if self.policy == "strict":
            threshold = 3
        elif self.policy == "two_engine":
            threshold = 2
        else:  # deterministic
            threshold = 1

        if len(agreeing_engines) < threshold:
            return AnswerStatus.INCOMPLETE

        blockers = self._verification_blockers(agreeing)
        if blockers:
            return AnswerStatus.INCOMPLETE

        families = {_extraction_family(o) for o in agreeing}
        if len(families) < threshold:
            # Distinct extraction pipelines required: agreeing values that all
            # come from one extraction family are single-source evidence.
            return AnswerStatus.INCOMPLETE

        decoders = {o.provenance.decoder for o in agreeing if o.provenance.decoder}
        if len(decoders) == 1 and len(agreeing) > 1 and "shared" not in next(iter(decoders)):
            # One decoder claiming to be independent across engines is a lie we
            # cannot verify; treat as single-source rather than verifying.
            return AnswerStatus.INCOMPLETE

        if self.policy == "deterministic":
            return AnswerStatus.VERIFIED_DERIVED
        return AnswerStatus.VERIFIED

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
        if self.policy == "strict":
            return 3
        if self.policy == "two_engine":
            return 2
        return 1

    # ------------------------------------------------------------------
    def field(self, entity_type: str, entity_id: str, field: str) -> FieldConsensus:
        obs = self._groups.get((entity_type, entity_id, field), [])
        return FieldConsensus(
            entity_type, entity_id, field, obs, self.required, self.policy,
            expected_snapshot=self.model.snapshot_id,
        )

    def verify_interface_field(self, device: str, interface: str, field: str) -> FieldConsensus:
        canon = canonical_interface_name(interface)
        return self.field("interface", f"{device}:{canon}", field)

    def verify_device_field(self, device: str, field: str) -> FieldConsensus:
        return self.field("device", device, field)

    # ------------------------------------------------------------------
    def all_conflicts(self) -> list[str]:
        out: list[str] = []
        for (entity_type, entity_id, field), obs in sorted(self._groups.items()):
            fc = FieldConsensus(
                entity_type, entity_id, field, obs, self.required, self.policy,
                expected_snapshot=self.model.snapshot_id,
            )
            out.extend(fc.conflicts)
        return out

    def consensus_map(self) -> dict[str, dict]:
        """Compact machine-readable view used by the UI and exports."""
        result: dict[str, dict] = {}
        for (entity_type, entity_id, field), obs in sorted(self._groups.items()):
            fc = FieldConsensus(
                entity_type, entity_id, field, obs, self.required, self.policy,
                expected_snapshot=self.model.snapshot_id,
            )
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
