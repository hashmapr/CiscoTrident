"""Command identification, prompt stripping and device detection.

Three jobs, all deterministic:

* recognise which ``show`` command produced a paste (and how sure we are),
* remove IOS prompt/echo prefixes so the body can be parsed,
* recover the device name from prompts **only** when exactly one device appears.

Nothing here guesses. A paste with no recognisable command is ``UNKNOWN``; a
paste with several device prompts is rejected rather than merged.
"""

from __future__ import annotations

import re

from .types import EvidenceKind

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

#: First words that can legitimately follow an IOS prompt. Used only as a guard
#: so a data line that happens to contain ``#`` is not mistaken for a prompt.
_PROMPT_COMMANDS = frozenset(
    {
        "show",
        "enable",
        "disable",
        "conf",
        "configure",
        "terminal",
        "exit",
        "end",
        "no",
        "yes",
        "ip",
        "ipv6",
        "interface",
        "switchport",
        "vlan",
        "spanning-tree",
        "router",
        "access-list",
        "line",
        "banner",
        "username",
        "service",
        "description",
        "shutdown",
        "speed",
        "duplex",
        "clock",
        "logging",
        "ntp",
        "snmp-server",
        "crypto",
        "aaa",
        "dot1x",
        "port-security",
        "channel-group",
        "channel-protocol",
        "hostname",
        "do",
        "clear",
        "copy",
        "write",
        "reload",
        "ping",
        "traceroute",
    }
)

_PROMPT_RE = re.compile(
    r"^(?P<device>[A-Za-z][A-Za-z0-9._-]{0,62})"
    r"(?:\((?P<context>[^)\r\n]{0,40})\))?"
    r"(?P<sep>[#>])"
    r"(?P<rest>.*)$"
)


def _is_prompt(device: str, rest: str) -> bool:
    remainder = rest.strip()
    if not remainder:
        return True
    if remainder.startswith("?"):
        return True
    head = remainder.split()[0].lower()
    return head in _PROMPT_COMMANDS


_COMMAND_ECHO_RE = re.compile(
    r"^(?:(?:do|no)\s+)?(?:"
    r"show\s+\S.*|"
    r"(?:configure|conf)\b[^#]*|"
    r"enable(?:\s+\S+)?|disable|end|exit|"
    r"(?:terminal|line|interface|ip|ipv6|router|vlan|spanning-tree|switchport|access-list|"
    r"banner|username|service|description|shutdown|speed|duplex|crypto|aaa|logging|ntp|"
    r"snmp-server|hostname|port-security|channel-group|channel-protocol|dot1x|clear|copy|"
    r"write|reload|ping|traceroute|clock)\b.*"
    r")$",
    re.IGNORECASE,
)


def _is_command_echo(remainder: str) -> bool:
    """True for the echoed command that follows a prompt, e.g. ``show ip int brief``."""
    return bool(_COMMAND_ECHO_RE.match(remainder.strip()))


def strip_prompts(text: str) -> tuple[list[str], list[str], list[str]]:
    """Return ``(body_lines, prompt_devices, echoed_commands)``.

    ``body_lines`` have the prompt/echo prefix removed. ``prompt_devices`` lists
    each distinct device in order of first appearance. ``echoed_commands`` holds
    the command text that followed each prompt, which is how a paste usually
    announces what it is even though it is not part of the output body.
    """
    body: list[str] = []
    devices: list[str] = []
    echoes: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        match = _PROMPT_RE.match(line)
        if match is not None and _is_prompt(match.group("device"), match.group("rest")):
            device = match.group("device")
            if device.lower() not in seen:
                seen.add(device.lower())
                devices.append(device)
            remainder = match.group("rest").strip()
            if remainder:
                echoes.append(remainder)
            continue
        body.append(line)
    return body, devices, echoes


# ---------------------------------------------------------------------------
# Kind detection
# ---------------------------------------------------------------------------

#: Command echoes, checked before any structural signature. A paste usually
#: begins with the command that produced it.
_ECHO_PATTERNS: tuple[tuple[EvidenceKind, re.Pattern[str]], ...] = (
    (EvidenceKind.RUNNING_CONFIG, re.compile(r"^show\s+(?:run|running-config)\b", re.IGNORECASE)),
    (
        EvidenceKind.IP_INTERFACE_BRIEF,
        re.compile(r"^show\s+ip\s+int(?:erface)?\s+brief\b", re.IGNORECASE),
    ),
    (EvidenceKind.VLAN_BRIEF, re.compile(r"^show\s+vlan\s+brief\b", re.IGNORECASE)),
    (EvidenceKind.INTERFACES_TRUNK, re.compile(r"^show\s+interfaces?\s+trunk\b", re.IGNORECASE)),
    (EvidenceKind.IP_ROUTE, re.compile(r"^show\s+ip\s+route\b", re.IGNORECASE)),
    (EvidenceKind.ACCESS_LISTS, re.compile(r"^show\s+(?:ip\s+)?access-lists?\b", re.IGNORECASE)),
    (EvidenceKind.OSPF_NEIGHBOR, re.compile(r"^show\s+ip\s+ospf\s+neighbor\b", re.IGNORECASE)),
    (
        EvidenceKind.ETHERCHANNEL_SUMMARY,
        re.compile(r"^show\s+etherchannel\s+summary\b", re.IGNORECASE),
    ),
    (EvidenceKind.SPANNING_TREE, re.compile(r"^show\s+spanning-tree\b", re.IGNORECASE)),
)

_IP_INT_HEADER_RE = re.compile(
    r"\bIP-Address\b.*\bOK\?.*\bMethod\b.*\bStatus\b.*\bProtocol\b", re.IGNORECASE
)
_VLAN_HEADER_RE = re.compile(r"^VLAN\s+Name\s+Status\s+Ports\b", re.IGNORECASE)
_TRUNK_HEADER_RE = re.compile(
    r"^Port\s+Mode\s+Encapsulation\s+Status\s+Native\s+vlan\b", re.IGNORECASE
)
_OSPF_HEADER_RE = re.compile(r"^Neighbor\s+ID\s+Pri\s+State\s+Dead\s+Time\b", re.IGNORECASE)
_ETHER_HEADER_RE = re.compile(r"^Group\s+Port-channel\s+Protocol\s+Ports\b", re.IGNORECASE)
_ACL_STRUCT_RE = re.compile(
    r"^(?:Standard|Extended)\s+IP\s+access\s+list\s+\S+", re.IGNORECASE | re.MULTILINE
)


def _structural_scores(lines: list[str]) -> dict[EvidenceKind, float]:
    scores: dict[EvidenceKind, float] = {}
    joined = "\n".join(lines)
    lowered = joined.lower()

    if "current configuration :" in lowered:
        scores[EvidenceKind.RUNNING_CONFIG] = 1.0
    elif "building configuration..." in lowered and "hostname " in lowered:
        scores[EvidenceKind.RUNNING_CONFIG] = 0.95
    elif (
        re.search(r"^hostname\s+\S+", joined, re.MULTILINE)
        and re.search(r"^interface\s+\S+", joined, re.MULTILINE)
        and re.search(r"^!$", joined, re.MULTILINE)
    ):
        scores[EvidenceKind.RUNNING_CONFIG] = 0.9

    if any(_IP_INT_HEADER_RE.search(line) for line in lines):
        scores[EvidenceKind.IP_INTERFACE_BRIEF] = 0.95
    if any(_VLAN_HEADER_RE.match(line.strip()) for line in lines):
        scores[EvidenceKind.VLAN_BRIEF] = 0.95
    if any(_TRUNK_HEADER_RE.match(line.strip()) for line in lines):
        scores[EvidenceKind.INTERFACES_TRUNK] = 0.95
    if "gateway of last resort" in lowered or (
        "codes:" in lowered and "c - connected" in lowered
    ):
        scores[EvidenceKind.IP_ROUTE] = 0.95
    if _ACL_STRUCT_RE.search(joined):
        scores[EvidenceKind.ACCESS_LISTS] = 0.95
    if any(_OSPF_HEADER_RE.match(line.strip()) for line in lines):
        scores[EvidenceKind.OSPF_NEIGHBOR] = 0.95
    if any(_ETHER_HEADER_RE.match(line.strip()) for line in lines):
        scores[EvidenceKind.ETHERCHANNEL_SUMMARY] = 0.95
    if "spanning tree enabled protocol" in lowered:
        scores[EvidenceKind.SPANNING_TREE] = 0.95

    return scores


def _detect_from_lines(
    lines: list[str], echoes: list[str] | None = None
) -> tuple[EvidenceKind, float]:
    echo_kinds: list[EvidenceKind] = []
    for line in list(echoes or ()) + lines:
        for kind, pattern in _ECHO_PATTERNS:
            if pattern.match(line.strip()) and kind not in echo_kinds:
                echo_kinds.append(kind)
    if len(echo_kinds) > 1:
        # Several distinct commands in one paste: not one artefact.
        return EvidenceKind.UNKNOWN, 0.1
    if len(echo_kinds) == 1:
        return echo_kinds[0], 0.99

    scores = _structural_scores(lines)
    if not scores:
        return EvidenceKind.UNKNOWN, 0.0
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_kind, best_score = ranked[0]
    if len(ranked) > 1 and ranked[1][1] == best_score:
        # Equally strong signals for two different artefacts.
        return EvidenceKind.UNKNOWN, 0.3
    confidence = 0.95 if len(ranked) == 1 else 0.85
    return best_kind, confidence


def detect_kind(text: str) -> tuple[EvidenceKind, float]:
    """Identify the CLI artefact in ``text`` and return ``(kind, confidence)``.

    ``confidence`` is 0.0 for unrecognised text and never exceeds 1.0. Prompt
    lines and echoed commands are stripped before matching.
    """
    lines, _devices, echoes = strip_prompts(text)
    return _detect_from_lines(lines, echoes)


def resolve_device(supplied: str | None, prompt_devices: list[str]) -> tuple[str | None, list[str]]:
    """Resolve the record's device without ever inventing one.

    Returns ``(device, notes)``. ``device`` is ``None`` when nothing was supplied
    and the paste does not name exactly one device.
    """
    notes: list[str] = []
    distinct: list[str] = []
    seen: set[str] = set()
    for name in prompt_devices:
        if name.lower() not in seen:
            seen.add(name.lower())
            distinct.append(name)

    if supplied:
        if len(distinct) > 1 or (distinct and distinct[0].lower() != supplied.lower()):
            notes.append(
                "caller-supplied device "
                f"{supplied!r} conflicts with prompt device(s) {distinct!r}; using the supplied device"
            )
        return supplied, notes

    if len(distinct) == 1:
        return distinct[0], notes
    if len(distinct) > 1:
        notes.append(
            "paste contains prompts for several devices "
            f"({', '.join(distinct)}); no single device is attributed"
        )
    return None, notes
