"""Operational CLI evidence ingestion for TRIDENT.

Paste the output of a Cisco IOS ``show`` command; get back a :class:`CliRecord`
that states exactly what was recognised, which device it belongs to (if any),
whether it is recorded configuration or live state, and what could not be
parsed.

The diagnostics engine consumes ``EvidenceBundle`` typed views rather than raw
text, so a diagnosis can always cite the artefact it came from.

Example
-------
>>> from trident.evidence import parse_cli_output
>>> record = parse_cli_output("SW1# show ip int brief\\nGi0/1 10.0.0.1 YES manual up up")
>>> record.kind.value, record.source.value, record.device
('IP_INTERFACE_BRIEF', 'RUNTIME_STATE', 'SW1')

Honesty guarantees
-------------------
* a device is only set when supplied or named unambiguously by a prompt
* ``captured_at`` is never generated
* text that is not a known command is ``UNKNOWN`` / ``UNRECOGNISED``
* a malformed row is skipped with a note; the rest is still parsed
* two devices pasted together are never merged
"""

from .api import parse_cli_output
from .bundle import EvidenceBundle
from .detect import detect_kind, strip_prompts
from .types import SOURCE_BY_KIND, CliRecord, EvidenceKind, ObservationSource, ParseStatus

__all__ = [
    "SOURCE_BY_KIND",
    "CliRecord",
    "EvidenceBundle",
    "EvidenceKind",
    "ObservationSource",
    "ParseStatus",
    "detect_kind",
    "parse_cli_output",
    "strip_prompts",
]
