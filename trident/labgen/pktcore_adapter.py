"""Deepening layer for Engine B (``pkt_core``) lab generation.

``pkt_core`` is a **GPL-3.0-or-later** third-party distribution. This module is
an adapter: it imports the installed package through its public API and never
vendors, copies, or re-implements its source. Trident ships this adapter, not
pkt_core.

Engine B is both a *parser* (see :mod:`trident.parsers.pkt_core`) and an
*authoring* library. The authoring path is what this module hardens:

``gateway_support()``
    Measures, on the installed version, whether ``Lab.add_device(...,
    pc_ip=[ip, mask, gateway])`` actually writes the default gateway where
    Packet Tracer reads it (``<DEVICE><ENGINE><GATEWAY>``). Some releases write
    only the port-level ``<PORT_GATEWAY>`` and leave the ENGINE element at the
    donor template's value.

``postprocess_endhost_gateways(xml_bytes, hosts)``
    A surgical, byte-preserving fixup. It locates the ENGINE ``<GATEWAY>``
    element of each named end host, replaces only that element's text, and
    splices the result back into the original bytes. No element is moved, no
    formatting is normalised, and every byte outside the edited gateway spans is
    preserved exactly. Idempotent: a second call with the same mapping makes no
    changes.

``roundtrip_ok(path)``
    Decode -> re-encode fidelity check for a real ``.pkt``/``.pka`` file.

``semantic_compare(a_path, b_path)``
    Device / link / interface / running-config differences between two files,
    used to prove that a fault injected into a lab actually changes something.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.parsers import expat

__all__ = [
    "gateway_support",
    "postprocess_endhost_gateways",
    "roundtrip_ok",
    "semantic_compare",
]

#: Element path (relative to a device) that Packet Tracer actually reads.
ENGINE_GATEWAY_TAG = "GATEWAY"

#: End-host model used only for the measurement probe.
_PROBE_MODEL = "PC-PT"
_PROBE_NAME = "GWPROBE"
_PROBE_IP = "10.255.255.10"
_PROBE_MASK = "255.255.255.0"
_PROBE_GATEWAY = "10.255.255.254"

_GATEWAY_OPEN = b"<GATEWAY>"
_GATEWAY_CLOSE = b"</GATEWAY>"


def _module() -> Any:
    """Import the installed pkt_core distribution, or explain why it is absent."""
    try:
        import pkt_core
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise RuntimeError(
            "pkt_core is not importable; run: pip install 'pkt-core==0.2.2' "
            "(GPL-3.0-or-later, external dependency)"
        ) from exc
    return pkt_core


@dataclass(frozen=True, slots=True)
class _GatewaySpan:
    """Byte span of one ``<DEVICE><ENGINE><GATEWAY>`` element."""

    device: str
    start: int  # index of the opening '<'
    end: int  # index of '</GATEWAY>' or, for an empty tag, index after '/>'
    value: str
    empty: bool


def _scan_engine_gateways(xml: bytes) -> list[_GatewaySpan]:
    """Locate every ``<GATEWAY>`` that is a direct child of a device ``<ENGINE>``.

    Uses expat purely for byte offsets; ``ElementTree`` gives no offsets and a
    whole-tree re-serialise would rewrite formatting. The scanner records the
    device name from ``<ENGINE><NAME>`` so spans can be matched by name.
    """
    stack: list[str] = []
    spans: list[_GatewaySpan] = []
    state: dict[str, Any] = {"name": None, "chars": [], "start": None}
    parser = expat.ParserCreate()

    def start_element(tag: str, _attrs: dict[str, str]) -> None:
        stack.append(tag)
        if tag == "GATEWAY" and len(stack) >= 2 and stack[-2] == "ENGINE":
            state["start"] = parser.CurrentByteIndex
        elif tag == "NAME":
            state["chars"] = []

    def char_data(data: str) -> None:
        if stack and stack[-1] == "NAME":
            state["chars"].append(data)

    def end_element(tag: str) -> None:
        if tag == "NAME" and len(stack) >= 2 and stack[-2] == "ENGINE":
            state["name"] = "".join(state["chars"]).strip()
        elif tag == "GATEWAY" and state["start"] is not None:
            start = state["start"]
            end = parser.CurrentByteIndex
            gt = xml.index(b">", start)
            tag_bytes = xml[start : gt + 1]
            empty = tag_bytes.rstrip().endswith(b"/>")
            value = "" if empty else xml[gt + 1 : end].decode("utf-8", "replace")
            spans.append(
                _GatewaySpan(
                    device=state["name"] or "",
                    start=start,
                    end=gt + 1 if empty else end,
                    value=value,
                    empty=empty,
                )
            )
            state["start"] = None
        stack.pop()

    parser.StartElementHandler = start_element
    parser.CharacterDataHandler = char_data
    parser.EndElementHandler = end_element
    parser.Parse(xml, True)
    return spans


def _engine_gateway(xml: bytes, device: str) -> str | None:
    for span in _scan_engine_gateways(xml):
        if span.device == device:
            return span.value
    return None


def _l3_port_gateway(xml: bytes, device: str) -> str | None:
    """First non-empty ``<PORT_GATEWAY>`` under the named device's ENGINE."""
    root = ET.fromstring(xml)
    for dev in root.iter("DEVICE"):
        engine = dev.find("ENGINE")
        if engine is None:
            continue
        if (engine.findtext("NAME") or "").strip() != device:
            continue
        for port in engine.iter("PORT"):
            value = (port.findtext("PORT_GATEWAY") or "").strip()
            if value:
                return value
    return None


def gateway_support() -> tuple[bool, str]:
    """Measure whether pkt_core writes a usable ``<ENGINE><GATEWAY>``.

    A fresh PC is authored with a distinctive gateway, saved through the real
    container codec, and decoded again. The check reads the ENGINE element (the
    one Packet Tracer uses), not the port element. Returns ``(ok, reason)``
    where ``reason`` states the measured values and the installed version.
    """
    pkt_core = _module()
    version = getattr(pkt_core, "__version__", "unknown")
    import tempfile

    lab = pkt_core.Lab()
    lab.add_device(
        _PROBE_MODEL,
        _PROBE_NAME,
        100,
        100,
        pc_ip=[_PROBE_IP, _PROBE_MASK, _PROBE_GATEWAY],
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "gateway-probe.pkt"
        lab.save(path)
        xml = pkt_core.decode(path).xml

    engine_value = _engine_gateway(xml, _PROBE_NAME)
    port_value = _l3_port_gateway(xml, _PROBE_NAME)

    if engine_value == _PROBE_GATEWAY:
        return True, (
            f"pkt_core {version}: <ENGINE><GATEWAY>={engine_value!r} matches the "
            f"requested gateway {_PROBE_GATEWAY!r} for probe {_PROBE_NAME}"
        )
    return False, (
        f"pkt_core {version}: <ENGINE><GATEWAY>={engine_value!r} != requested "
        f"{_PROBE_GATEWAY!r} for probe {_PROBE_NAME}; port-level "
        f"<PORT_GATEWAY>={port_value!r}. Packet Tracer reads the ENGINE element, "
        "so the end-host gateway fixup is required."
    )


def _validate_gateway(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("gateway must be a non-empty string")
    if "<" in value or ">" in value or "\x00" in value:
        raise ValueError(f"gateway {value!r} contains characters that cannot be XML text")
    return value.encode("utf-8")


def postprocess_endhost_gateways(xml_bytes: bytes, hosts: dict[str, str]) -> bytes:
    """Write ``<ENGINE><GATEWAY>`` for each named end host, preserving all else.

    ``hosts`` maps device name -> dotted-quad gateway. Only the text of the
    ENGINE gateway element is changed (or the whole element when it was written
    empty). Every other byte, including indentation, element order, config text
    and the XML declaration, is retained: the result is the original bytes with
    a few in-place splices.

    The mapping must not name a device that is absent from the document; a typo
    is an error rather than a silent no-op. If a name occurs more than once
    (for example the three embedded networks of an activity), every matching
    ENGINE gateway is updated. Typical use is a single generated lab document.

    Idempotent: if the gateway already equals the requested value, nothing is
    rewritten.
    """
    spans = _scan_engine_gateways(xml_bytes)
    by_name: dict[str, list[_GatewaySpan]] = {}
    for span in spans:
        by_name.setdefault(span.device, []).append(span)

    missing = sorted(name for name in hosts if name not in by_name)
    if missing:
        available = ", ".join(sorted(by_name)) or "(none)"
        raise KeyError(
            f"no <ENGINE><GATEWAY> for device(s) {missing}; devices with an "
            f"ENGINE gateway: {available}"
        )

    edits: list[tuple[int, int, bytes]] = []
    for name, gateway in hosts.items():
        replacement = _validate_gateway(gateway)
        for span in by_name[name]:
            if span.value.encode("utf-8") == replacement:
                continue
            if span.empty:
                edits.append(
                    (span.start, span.end, _GATEWAY_OPEN + replacement + _GATEWAY_CLOSE)
                )
            else:
                gt = xml_bytes.index(b">", span.start)
                edits.append((gt + 1, span.end, replacement))

    # Apply right-to-left so earlier offsets stay valid.
    result = xml_bytes
    for start, end, payload in sorted(edits, key=lambda e: e[0], reverse=True):
        result = result[:start] + payload + result[end:]

    # Structural self-check: every requested gateway landed, and the document is
    # still well-formed with the same device names.
    after = _scan_engine_gateways(result)
    after_by_name: dict[str, list[str]] = {}
    for span in after:
        after_by_name.setdefault(span.device, []).append(span.value)
    for name, gateway in hosts.items():
        if any(value != gateway for value in after_by_name[name]):
            raise AssertionError(
                f"gateway fixup did not converge for {name}: {after_by_name[name]!r}"
            )
    if sorted(after_by_name) != sorted(by_name):
        raise AssertionError("gateway fixup changed the device inventory")

    # Well-formedness and byte-confinement proof for callers that want it.
    ET.fromstring(result)
    return result


def roundtrip_ok(path: str | Path) -> tuple[bool, str]:
    """Check decode -> re-encode fidelity for a real container file.

    Returns ``(ok, reason)``. ``ok`` is True only when the re-encoded bytes are
    byte-identical to the input, which is the strongest available statement and
    is what the bundled corpus produces.
    """
    try:
        pkt_core = _module()
        target = Path(path)
        raw = target.read_bytes()
        container = pkt_core.decode(target)
        rebuilt = pkt_core.encode_bytes(container.xml, container.format_name)
    except Exception as exc:  # noqa: BLE001 - report, never mask
        return False, f"{type(exc).__name__}: {exc}"

    if rebuilt == raw:
        return True, (
            f"lossless: {container.format_name}/{container.root_tag}, "
            f"{len(raw)} bytes re-encoded byte-identically"
        )
    return False, (
        f"lossy: {container.format_name}/{container.root_tag}, re-encode is "
        f"{len(rebuilt)} bytes vs {len(raw)} bytes on disk"
    )


_INTERFACE_FIELDS = (
    "TYPE",
    "MACADDRESS",
    "BANDWIDTH",
    "FULLDUPLEX",
    "IP",
    "SUBNET",
    "PORT_GATEWAY",
    "GATEWAY",
)


def _interface_rows(xml: bytes) -> dict[tuple[str, int], dict[str, str]]:
    """Stable-keyed view of every port on every device: media plus L3 state.

    Port index 0 is reserved for the ENGINE-level default gateway, which is not
    a physical port but is the value Packet Tracer reads for an end host. Every
    real port is indexed from 1.
    """
    root = ET.fromstring(xml)
    rows: dict[tuple[str, int], dict[str, str]] = {}
    for dev in root.iter("DEVICE"):
        engine = dev.find("ENGINE")
        if engine is None:
            continue
        name = (engine.findtext("NAME") or "").strip()
        engine_row = {field: "" for field in _INTERFACE_FIELDS}
        engine_row["TYPE"] = "ENGINE_GATEWAY"
        engine_row["GATEWAY"] = (engine.findtext("GATEWAY") or "").strip()
        rows[(name, 0)] = engine_row
        for index, port in enumerate(engine.iter("PORT"), start=1):
            rows[(name, index)] = {
                field: (port.findtext(field) or "").strip() for field in _INTERFACE_FIELDS
            }
    return rows


def _diff_interfaces(
    a: dict[tuple[str, int], dict[str, str]],
    b: dict[tuple[str, int], dict[str, str]],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b)):
        name, index = key
        if key not in a:
            changes.append({"device": name, "port": index, "added": True})
            continue
        if key not in b:
            changes.append({"device": name, "port": index, "removed": True})
            continue
        delta = {
            field: [a[key][field], b[key][field]]
            for field in _INTERFACE_FIELDS
            if a[key][field] != b[key][field]
        }
        if delta:
            changes.append({"device": name, "port": index, "changes": delta})
    return changes


def semantic_compare(a_path: str | Path, b_path: str | Path) -> dict[str, Any]:
    """Semantic device/link/interface/config difference between two labs.

    Device, link and running-config comparison is delegated to
    ``pkt_core.diff_labs`` (identity-based, so reordering is not a change).
    Interface state is compared here because the typed model does not expose
    L3 addressing; it reads the decoded XML of both files.

    Returns a dict with ``identical``, ``devices``, ``links``, ``interfaces``,
    ``configs``, ``meta``, ``summary`` and ``error`` (``None`` on success). On
    failure every bucket is empty, ``identical`` is False and ``error`` explains
    why, so callers never mistake an error for "no difference".
    """
    result: dict[str, Any] = {
        "identical": False,
        "devices": [],
        "links": [],
        "interfaces": [],
        "configs": [],
        "meta": {},
        "summary": [],
        "error": None,
    }
    try:
        pkt_core = _module()
        view_a = pkt_core.open_lab(a_path)
        view_b = pkt_core.open_lab(b_path)
        diff = pkt_core.diff_labs(view_a, view_b)
        xml_a = pkt_core.decode(a_path).xml
        xml_b = pkt_core.decode(b_path).xml
    except Exception as exc:  # noqa: BLE001 - report, never mask
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    for item in diff.devices:
        if item.added:
            result["devices"].append({"name": item.name, "added": True})
        elif item.removed:
            result["devices"].append({"name": item.name, "removed": True})
        elif item.changes:
            result["devices"].append(
                {"name": item.name, "changes": {k: list(v) for k, v in item.changes.items()}}
            )

    for link in diff.links:
        if link.added:
            result["links"].append({"identity": link.identity, "added": True})
        elif link.removed:
            result["links"].append({"identity": link.identity, "removed": True})
        elif link.changes:
            result["links"].append(
                {"identity": link.identity, "changes": {k: list(v) for k, v in link.changes.items()}}
            )

    for cfg in diff.configs:
        result["configs"].append(
            {
                "device": cfg.device,
                "added": [line.decode("utf-8", "backslashreplace") for line in cfg.added],
                "removed": [line.decode("utf-8", "backslashreplace") for line in cfg.removed],
            }
        )

    result["interfaces"] = _diff_interfaces(_interface_rows(xml_a), _interface_rows(xml_b))
    result["meta"] = {key: list(value) for key, value in diff.meta_changes.items()}
    result["summary"] = list(diff.summary_lines())
    if result["interfaces"]:
        result["summary"].append(f"~ {len(result['interfaces'])} interface change(s)")

    result["identical"] = not (
        result["devices"]
        or result["links"]
        or result["interfaces"]
        or result["configs"]
        or result["meta"]
    )
    return result
