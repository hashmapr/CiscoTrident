"""TRIDENT unified network data model and API schemas.

Everything here is a Pydantic model so that parser output, AI structured output
and HTTP payloads all validate against the same contract.
"""

from __future__ import annotations

import enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AnswerStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    VERIFIED_DERIVED = "VERIFIED_DERIVED"
    CONFLICT = "CONFLICT"
    INCOMPLETE = "INCOMPLETE"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    ERROR = "ERROR"


class ParserState(str, enum.Enum):
    OK = "OK"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class QuestionKind(str, enum.Enum):
    SINGLE_SELECT = "SINGLE_SELECT"
    MULTI_SELECT = "MULTI_SELECT"
    TRUE_FALSE = "TRUE_FALSE"
    FACTUAL = "FACTUAL"
    REASONING = "REASONING"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

class Provenance(BaseModel):
    """Where one observation came from. Never empty for a trusted fact.

    The fields name the four independence layers explicitly:

    * ``decoder``            - Layer A, container decode implementation
    * ``extraction_family``  - Layer B, how the facts were pulled out
    * ``interpretation_family`` - Layer C, how text became semantics
    * ``validation``         - Layer D, checks applied afterwards
    """

    engine: str = Field(description="Engine identifier: engine_a | engine_b | engine_c")
    extraction_path: str = Field(
        description="How the value was obtained, e.g. 'ios-config' or 'raw-xml-walk'"
    )
    source_path: str = Field(default="", description="XML path / file within the engine output")
    snapshot: str = Field(default="", description="Network snapshot identifier")
    warnings: list[str] = Field(default_factory=list)
    crypto_shared: bool = Field(
        default=True,
        description="True when the container decode uses the shared public algorithm",
    )
    # --- explicit independence layers ---
    decoder: str = Field(
        default="", description="Layer A: container decode implementation (shared format)"
    )
    extraction_family: str = Field(
        default="", description="Layer B: independent extraction pipeline"
    )
    interpretation_family: str = Field(
        default="", description="Layer C: semantic interpretation implementation"
    )
    normalization: list[str] = Field(
        default_factory=list, description="Normalization operations applied"
    )
    validation: list[str] = Field(
        default_factory=list, description="Validation operations applied"
    )


class Observation(BaseModel):
    """A single field value asserted by a single engine."""

    field: str
    entity_type: Literal["device", "interface", "link", "route", "vlan", "acl", "settings"]
    entity_id: str = Field(description="Canonical device or interface identifier")
    value: str
    provenance: Provenance
    raw_evidence: str = Field(default="", description="Verbatim source line(s) supporting the value")


# ---------------------------------------------------------------------------
# Unified network model
# ---------------------------------------------------------------------------

class InterfaceInfo(BaseModel):
    device: str
    name: str
    canonical_name: str
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    prefix_length: int | None = None
    subnet_mask: str | None = None
    #: Default gateway configured on an end-host NIC. Parsed since the beginning
    #: as an ``endhost_gateway`` observation but never surfaced on the interface,
    #: so no reasoning code could ask "what gateway does this host have?".
    ipv4_gateway: str | None = None
    mac_address: str | None = None
    operational_state: str | None = None
    admin_state: str | None = None
    speed: str | None = None
    access_mode: str | None = None
    vlan_assignments: list[str] = Field(default_factory=list)
    #: Native VLAN on a trunk. ``None`` means "not stated", which is different
    #: from VLAN 1 (the IOS default): a trunk that omits the command is on 1,
    #: but only an explicit command lets us compare two ends honestly.
    native_vlan: int | None = None
    #: VLANs explicitly permitted by ``switchport trunk allowed vlan``.
    trunk_allowed: list[str] = Field(default_factory=list)
    description: str | None = None
    provenance: list[Provenance] = Field(default_factory=list)


class DeviceInfo(BaseModel):
    id: str
    name: str
    hostname: str | None = None
    device_type: str | None = None
    model: str | None = None
    ios_version: str | None = None
    configuration: list[str] = Field(default_factory=list)
    source_path: str = ""
    interfaces: list[str] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)


class LinkInfo(BaseModel):
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str
    media_type: str | None = None
    provenance: list[Provenance] = Field(default_factory=list)


class RouteInfo(BaseModel):
    destination: str
    next_hop: str | None = None
    outgoing_interface: str | None = None
    route_type: str
    #: Device that owns this route. Required to answer "the default route of X".
    device: str = ""
    administrative_distance: int | None = None
    protocol: str | None = None
    raw_config: str = ""
    provenance: list[Provenance] = Field(default_factory=list)


class VlanInfo(BaseModel):
    vlan_id: int
    name: str | None = None
    member_ports: list[str] = Field(default_factory=list)
    trunk_allowances: list[str] = Field(default_factory=list)
    native_vlan: int | None = None
    l3_interfaces: list[str] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)


class AclEntry(BaseModel):
    acl_id: str
    acl_type: str
    sequence: int | None = None
    action: str
    protocol: str | None = None
    source: str | None = None
    destination: str | None = None
    port_conditions: list[str] = Field(default_factory=list)
    applied_interface: str | None = None
    direction: str | None = None
    raw: str = ""
    provenance: list[Provenance] = Field(default_factory=list)


class SettingsInfo(BaseModel):
    default_gateways: dict[str, str] = Field(default_factory=dict)
    dns_servers: dict[str, list[str]] = Field(default_factory=dict)
    dhcp_configured: list[str] = Field(default_factory=list)
    #: Per-device DHCP pool settings, keyed device -> pool name -> settings.
    dhcp_details: dict[str, dict[str, dict]] = Field(default_factory=dict)
    #: Per-device excluded addresses from ``ip dhcp excluded-address``.
    dhcp_excluded: dict[str, list[str]] = Field(default_factory=dict)
    software_versions: dict[str, str] = Field(default_factory=dict)
    management: dict[str, list[str]] = Field(default_factory=dict)
    arp_entries: list[str] = Field(default_factory=list)
    cdp_neighbors: list[str] = Field(default_factory=list)
    interface_counters: list[str] = Field(default_factory=list)


class NetworkModel(BaseModel):
    """The unified, trusted network model built from parser observations."""

    devices: dict[str, DeviceInfo] = Field(default_factory=dict)
    interfaces: dict[str, InterfaceInfo] = Field(default_factory=dict)
    links: list[LinkInfo] = Field(default_factory=list)
    routes: list[RouteInfo] = Field(default_factory=list)
    vlans: list[VlanInfo] = Field(default_factory=list)
    acls: list[AclEntry] = Field(default_factory=list)
    settings: SettingsInfo = Field(default_factory=SettingsInfo)
    observations: list[Observation] = Field(default_factory=list)
    snapshot_id: str = ""
    snapshot_ambiguous: bool = False
    snapshot_notes: list[str] = Field(default_factory=list)
    #: Display-name placeholder table recovered from the source document
    #: (``pr3-rt_Display_name`` -> ``Node One Router (Our Loyal Minion)``).
    placeholder_map: dict[str, str] = Field(default_factory=dict)
    file_sha256: str = ""
    warnings: list[str] = Field(default_factory=list)

    def device_names(self) -> list[str]:
        return sorted(self.devices)

    def find_device(self, name: str) -> DeviceInfo | None:
        """Exact name/hostname lookup. Ambiguous aliases resolve to nothing."""
        if not name:
            return None
        key = name.strip().lower()
        for dev in self.devices.values():
            if dev.name.lower() == key:
                return dev
        for dev in self.devices.values():
            if dev.hostname and dev.hostname.lower() == key:
                return dev
        # Explicit alias rule (strip a single leading segment), but only when it
        # identifies exactly one device. Never pick arbitrarily between several.
        base = key.split("_")[0]
        if base != key:
            alias_hits = [d for d in self.devices.values() if d.name.lower().split("_")[0] == base]
            if len(alias_hits) == 1:
                return alias_hits[0]
        return None

    def device_interfaces(self, device_name: str) -> list[InterfaceInfo]:
        dev = self.find_device(device_name)
        if dev is None:
            return []
        out = []
        for canon in dev.interfaces:
            iface = self.interfaces.get(f"{dev.name}:{canon}")
            if iface is None:
                iface = self.interfaces.get(canon)
            if iface is not None:
                out.append(iface)
        return out


# ---------------------------------------------------------------------------
# Question + answer schemas
# ---------------------------------------------------------------------------

class QuestionOption(BaseModel):
    letter: str
    text: str


class ParsedQuestion(BaseModel):
    question_number: int
    original: str
    kind: QuestionKind = QuestionKind.UNKNOWN
    stem: str = ""
    options: list[QuestionOption] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    device: str | None = None
    interface: str | None = None
    field: str
    value: str
    sources: list[str] = Field(default_factory=list)
    extraction_paths: list[str] = Field(default_factory=list)
    raw_evidence: str = ""

    @field_validator("sources")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        seen: list[str] = []
        for s in v:
            if s not in seen:
                seen.append(s)
        return seen


class ConsensusSummary(BaseModel):
    agree: int = 0
    available: int = 0
    required: int = 3
    policy: str = "strict"
    crypto_shared: bool = True


class AnswerResult(BaseModel):
    question_number: int
    original_question: str
    status: AnswerStatus
    answer: str | None = None
    selected_options: list[str] = Field(default_factory=list)
    explanation: str = ""
    evidence: list[EvidenceItem] = Field(default_factory=list)
    consensus: ConsensusSummary = Field(default_factory=ConsensusSummary)
    missing_evidence: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    manual_check: str | None = None
    question_kind: QuestionKind = QuestionKind.UNKNOWN


class ParserReport(BaseModel):
    engine: str
    state: ParserState
    version: str | None = None
    message: str = ""
    duration_ms: int = 0
    device_count: int = 0
    interface_count: int = 0
    link_count: int = 0
    capabilities: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    #: Adapter notes (e.g. snapshot selection remarks) surfaced to the user.
    notes: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    file_name: str
    file_sha256: str
    file_bytes: int
    snapshot_id: str
    snapshot_ambiguous: bool
    snapshot_notes: list[str] = Field(default_factory=list)
    parsers: list[ParserReport] = Field(default_factory=list)
    consensus_policy: str
    ai_used: bool = False
    network_summary: dict[str, Any] = Field(default_factory=dict)
    results: list[AnswerResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    #: Phase 3 investigation summary. Present on every analysis so the caller can
    #: see which answers were resolved statically and which would need a
    #: simulator. Empty only when Phase 3 was explicitly disabled.
    phase3: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    version: str
    parsers: list[ParserReport]
    ai_configured: bool
    consensus_policy: str
