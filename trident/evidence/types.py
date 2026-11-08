"""Result types for operational CLI evidence ingestion.

These are frozen dataclasses, deliberately independent of Pydantic, so that a
record produced from pasted terminal output can be handed to the diagnostics
engine without any further validation layer.

The honesty rules of the ingestion layer are encoded structurally:

* ``ObservationSource`` is derived from ``EvidenceKind`` by
  :data:`SOURCE_BY_KIND`; a runtime ``show`` command can never be labelled
  ``STATIC_CONFIG``.
* an ``UNKNOWN`` kind can only be ``UNRECOGNISED`` and can never carry parsed
  data.
* a record without a device can never claim ``PARSED`` (it is unattributed).
* ``PARTIAL`` must explain itself with at least one note.
* ``captured_at`` is carried verbatim from the caller; nothing here reads a
  clock.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class EvidenceKind(enum.StrEnum):
    """The CLI artefact a record holds."""

    RUNNING_CONFIG = "RUNNING_CONFIG"
    IP_INTERFACE_BRIEF = "IP_INTERFACE_BRIEF"
    VLAN_BRIEF = "VLAN_BRIEF"
    INTERFACES_TRUNK = "INTERFACES_TRUNK"
    IP_ROUTE = "IP_ROUTE"
    SPANNING_TREE = "SPANNING_TREE"
    ETHERCHANNEL_SUMMARY = "ETHERCHANNEL_SUMMARY"
    ACCESS_LISTS = "ACCESS_LISTS"
    OSPF_NEIGHBOR = "OSPF_NEIGHBOR"
    UNKNOWN = "UNKNOWN"


class ObservationSource(enum.StrEnum):
    """Where the evidence comes from.

    This is the distinction the diagnostics engine depends on: a value read
    from ``show running-config`` is the *intended* configuration, while a value
    read from a runtime ``show`` command is the *observed* state. They may
    disagree, and the disagreement is itself a finding.
    """

    STATIC_CONFIG = "STATIC_CONFIG"
    RUNTIME_STATE = "RUNTIME_STATE"


class ParseStatus(enum.StrEnum):
    """How completely a paste was turned into structured data."""

    PARSED = "PARSED"
    PARTIAL = "PARTIAL"
    UNRECOGNISED = "UNRECOGNISED"


#: The single source of truth for the source/kind relationship.
#:
#: Only ``show running-config`` is recorded state; every other supported kind
#: reports live operational state. ``UNKNOWN`` is never static configuration:
#: when the artefact cannot be identified it is treated as unattributed runtime
#: text, never as a configuration claim.
SOURCE_BY_KIND: dict[EvidenceKind, ObservationSource] = {
    EvidenceKind.RUNNING_CONFIG: ObservationSource.STATIC_CONFIG,
    EvidenceKind.IP_INTERFACE_BRIEF: ObservationSource.RUNTIME_STATE,
    EvidenceKind.VLAN_BRIEF: ObservationSource.RUNTIME_STATE,
    EvidenceKind.INTERFACES_TRUNK: ObservationSource.RUNTIME_STATE,
    EvidenceKind.IP_ROUTE: ObservationSource.RUNTIME_STATE,
    EvidenceKind.SPANNING_TREE: ObservationSource.RUNTIME_STATE,
    EvidenceKind.ETHERCHANNEL_SUMMARY: ObservationSource.RUNTIME_STATE,
    EvidenceKind.ACCESS_LISTS: ObservationSource.RUNTIME_STATE,
    EvidenceKind.OSPF_NEIGHBOR: ObservationSource.RUNTIME_STATE,
    EvidenceKind.UNKNOWN: ObservationSource.RUNTIME_STATE,
}


@dataclass(frozen=True)
class CliRecord:
    """One pasted CLI artefact attributed to at most one device.

    ``device`` is supplied by the caller or detected from an unambiguous prompt
    in the paste. It is never guessed. ``captured_at`` is caller-supplied and is
    never generated. ``parsed`` is the kind-specific structured result and holds
    no prose.
    """

    device: str | None
    kind: EvidenceKind
    source: ObservationSource
    captured_at: str | None
    raw_text: str
    parsed: dict
    status: ParseStatus
    notes: tuple[str, ...]
    line_count: int

    def __post_init__(self) -> None:
        expected_source = SOURCE_BY_KIND.get(self.kind)
        if expected_source is None:
            raise ValueError(f"unknown evidence kind {self.kind!r}")
        if self.source is not expected_source:
            raise ValueError(
                f"kind {self.kind.value} must be sourced from {expected_source.value}, "
                f"not {self.source.value}"
            )
        if self.line_count < 0:
            raise ValueError("line_count cannot be negative")
        if self.kind is EvidenceKind.UNKNOWN:
            if self.status is not ParseStatus.UNRECOGNISED:
                raise ValueError("an UNKNOWN kind can only be UNRECOGNISED")
            if self.parsed:
                raise ValueError("an UNKNOWN kind can never carry parsed data")
        elif self.status is ParseStatus.UNRECOGNISED:
            raise ValueError(
                f"kind {self.kind.value} was recognised; status cannot be UNRECOGNISED"
            )
        if self.status is ParseStatus.PARTIAL and not self.notes:
            raise ValueError("a PARTIAL record must carry at least one explanatory note")
        if self.device is None and self.status is ParseStatus.PARSED:
            raise ValueError(
                "a record without a device is unattributed and cannot claim PARSED"
            )
