"""Engine A adapter — cisco-pka-to-xml (MIT).

Engine A is a container decoder. It yields XML and nothing else, so its
*extraction* contribution is: the decoded XML bytes, plus the device/link facts
TRIDENT derives by walking that XML with its own deterministic walker.

Honesty rule: the extracted facts are recorded with
``extraction_path = "A:raw-xml-walk"`` because the walker is TRIDENT code, not
Engine A's. Engine A is credited for the decode, not for semantic parsing.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from ..config import REPO_ROOT
from ..models import ParserReport, ParserState
from ..normalization.configs import parse_running_config
from ..normalization.values import canonical_interface_name, normalize_mac
from .base import AdapterResult, ParserAdapter
from .snapshot import (
    SnapshotSelection,
    build_placeholder_map,
    select_snapshot,
)

VENDOR_DIR = REPO_ROOT / "vendor" / "engine_a"
PKG_DIR = VENDOR_DIR / "pka2xml"
#: The directory that must be on sys.path for ``import pka2xml`` to resolve.
IMPORT_ROOT = VENDOR_DIR

_TAG_RE = re.compile(r"<([A-Za-z0-9_]+)([^>]*)>")
_LINE_RE = re.compile(r"<LINE>(.*?)</LINE>", re.DOTALL)
_RUNNINGCONFIG_RE = re.compile(r"<RUNNINGCONFIG>(.*?)</RUNNINGCONFIG>", re.DOTALL)
_STARTUPCONFIG_RE = re.compile(r"<STARTUPCONFIG>(.*?)</STARTUPCONFIG>", re.DOTALL)


class EngineAAdapter(ParserAdapter):
    engine_id = "engine_a"
    display_name = "cisco-pka-to-xml"
    capabilities = (
        "container-decode",
        "raw-xml",
        "ios-config-text",
        "device-inventory",
        "physical-links",
        "mac-addresses",
        "end-host-ip-gateway-dns",
    )
    limitations = (
        "no vendor semantic parser; device facts come from TRIDENT's XML walk",
        "container algorithm is the same public format as engines B and C",
        "requires the native libtwofish shared library",
    )

    def _library_path(self) -> Path | None:
        if self.cfg.libtwofish:
            p = Path(self.cfg.libtwofish)
            return p if p.exists() else None
        for name in ("libtwofish.dylib", "libtwofish.so", "libtwofish.dll"):
            candidate = PKG_DIR / name
            if candidate.exists():
                return candidate
        return None

    def probe(self) -> tuple[bool, str]:
        if not PKG_DIR.is_dir():
            return False, f"vendored package missing at {PKG_DIR}"
        lib = self._library_path()
        if lib is None:
            return False, (
                "libtwofish not built. Run: ./vendor/engine_a/build.sh "
                "(or set LIBTWOFISH to an existing shared library)"
            )
        try:
            if str(IMPORT_ROOT) not in sys.path:
                sys.path.insert(0, str(IMPORT_ROOT))
            os.environ.setdefault("LIBTWOFISH", str(lib))
            import pka2xml  # noqa: F401
            return True, f"ready (libtwofish: {lib.name})"
        except Exception as exc:  # noqa: BLE001
            return False, f"import failed: {type(exc).__name__}: {exc}"

    def _extract(self, file_path: Path, workdir: Path) -> AdapterResult:
        if str(IMPORT_ROOT) not in sys.path:
            sys.path.insert(0, str(IMPORT_ROOT))
        lib = self._library_path()
        if lib is not None:
            os.environ.setdefault("LIBTWOFISH", str(lib))

        raw = file_path.read_bytes()

        if file_path.suffix.lower() == ".xml":
            # Already-decoded XML: TRIDENT inspects it directly. No container
            # decode happens, so this is reported as an XML-only analysis rather
            # than a successful PKA ingestion.
            xml_bytes = raw
        else:
            from pka2xml import decrypt_pka

            xml_bytes = decrypt_pka(raw)
        # The vendored decoder inflates before returning, so these checks run
        # after the fact and cannot stop a bomb in progress; they do refuse to
        # hand oversized output to downstream parsers. Real lab files inflate
        # ~10-13x, so the ratio cap is a backstop, not a primary control.
        if len(xml_bytes) > self.cfg.max_xml_bytes:
            raise ValueError("decoded XML exceeds configured maximum size")
        if len(xml_bytes) > max(1, len(raw)) * self.cfg.max_decompression_ratio:
            raise ValueError(
                "decoded XML exceeds the maximum decompression ratio "
                f"({self.cfg.max_decompression_ratio}x); refusing a possible bomb"
            )

        xml_text = xml_bytes.decode("utf-8", errors="replace")
        selection = select_snapshot(xml_text)

        result = AdapterResult(
            engine_id=self.engine_id,
            report=ParserReport(
                engine=self.engine_id,
                state=ParserState.OK,
                message=(_abstain_message(selection) if selection.abstained
                         else f"decoded {len(xml_bytes):,} bytes of XML"),
                version="MIT build",
            ),
            raw={
                "snapshot": selection.snapshot_id,
                "snapshot_ambiguous": selection.ambiguous,
                "snapshot_notes": selection.notes,
                "snapshot_abstained": selection.abstained,
                "snapshot_scope": "selection",  # the walk parse selection.xml_text only
                "placeholder_map": build_placeholder_map(xml_text),
                "notes": selection.notes,
            },
            extraction_family="raw-xml-walk",
        )

        if selection.abstained:
            # Abstain: contribute nothing rather than analyse the wrong snapshot.
            result.report.device_count = 0
            result.report.link_count = 0
            result.report.interface_count = 0
            return result

        walk = _walk_xml(selection.xml_text or "")
        result.devices = walk["devices"]
        result.configs = walk["configs"]
        result.links = walk["links"]
        result.end_hosts = walk["end_hosts"]
        result.raw["models"] = walk.get("models", {})
        result.report.notes = list(selection.notes)
        result.report.device_count = len(result.devices)
        result.report.link_count = len(result.links)
        result.report.interface_count = sum(
            len(parse_running_config(cfg).interfaces) for cfg in result.configs.values()
        )
        return result


# ---------------------------------------------------------------------------
# Snapshot selection
# ---------------------------------------------------------------------------

def _select_snapshot(xml_text: str) -> tuple[str, bool, list[str]]:
    """Back-compat wrapper around the shared policy in ``parsers.snapshot``."""
    sel = select_snapshot(xml_text)
    return sel.snapshot_id, sel.ambiguous, list(sel.notes)


# ---------------------------------------------------------------------------
# Minimal deterministic XML walk (Engine A supplies the decode only)
# ---------------------------------------------------------------------------

_DEVICE_BLOCK_RE = re.compile(r"<DEVICE>(.*?)</DEVICE>", re.DOTALL)
_ENGINE_RE = re.compile(r"<ENGINE>(.*?)</ENGINE>", re.DOTALL)
_NAME_RE = re.compile(r"<NAME[^>]*>(.*?)</NAME>", re.DOTALL)
_TYPE_RE = re.compile(r'<TYPE[^>]*model="([^"]*)"[^>]*>(.*?)</TYPE>', re.DOTALL)
_SAVEREF_RE = re.compile(r"<SAVE_REF_ID>(.*?)</SAVE_REF_ID>", re.DOTALL)
_GATEWAY_RE = re.compile(r"<GATEWAY>(.*?)</GATEWAY>", re.DOTALL)
_DNS_RE = re.compile(r"<SERVER_IP>(.*?)</SERVER_IP>", re.DOTALL)
_ENDHOST_IP_RE = re.compile(r"<IP>(.*?)</IP>", re.DOTALL)
_MAC_RE = re.compile(r"<MACADDRESS>(.*?)</MACADDRESS>", re.DOTALL)
_LINK_BLOCK_RE = re.compile(r"<LINK>(.*?)</LINK>", re.DOTALL)


def _device_config_lines(scope: str) -> list[str]:
    """Extract a device's *running* configuration lines.

    A device block carries both ``<RUNNINGCONFIG>`` and ``<STARTUPCONFIG>``.
    Concatenating every ``<LINE>`` in the block merges the two: the startup copy
    (the previously saved state) overwrites the running interfaces with stale
    IPs and hostnames, which then conflict against the other engines.

    The running configuration is authoritative for what the network is doing
    now; startup config is only a fallback when no running config is present.
    """
    for rx in (_RUNNINGCONFIG_RE, _STARTUPCONFIG_RE):
        m = rx.search(scope)
        if not m:
            continue
        lines = [line.strip() for line in _LINE_RE.findall(m.group(1))]
        if lines:
            return lines
    # No wrapped config section: fall back to bare LINE elements only when the
    # block has no RUNNINGCONFIG/STARTUPCONFIG at all (legacy layouts).
    if _RUNNINGCONFIG_RE.search(scope) or _STARTUPCONFIG_RE.search(scope):
        return []
    return [line.strip() for line in _LINE_RE.findall(scope)]



def _walk_xml(xml_text: str) -> dict:
    devices: list[str] = []
    configs: dict[str, list[str]] = {}
    end_hosts: dict[str, dict] = {}
    models: dict[str, str] = {}
    ref_to_name: dict[str, str] = {}

    for block in _DEVICE_BLOCK_RE.findall(xml_text):
        engine_m = _ENGINE_RE.search(block)
        scope = engine_m.group(1) if engine_m else block

        name_m = _NAME_RE.search(scope)
        if not name_m:
            continue
        name = name_m.group(1).strip()
        if not name:
            continue
        if name in devices:
            continue
        devices.append(name)

        # Hardware model is carried as an attribute on <TYPE model="2911">.
        type_m = _TYPE_RE.search(scope)
        if type_m:
            model = (type_m.group(1) or "").strip()
            if model and model.lower() != "power distribution device":
                models[name] = model

        lines = _device_config_lines(scope)
        if lines:
            configs[name] = lines

        ref = _SAVEREF_RE.search(scope)
        if ref and ref.group(1).strip():
            ref_to_name[ref.group(1).strip()] = name

        host: dict = {}
        gw = _GATEWAY_RE.search(scope)
        if gw and gw.group(1).strip():
            host["gateway"] = gw.group(1).strip()
        dns = [d.strip() for d in _DNS_RE.findall(scope) if d.strip()]
        if dns:
            host["dns"] = dns
        ip = _ENDHOST_IP_RE.search(scope)
        if ip and ip.group(1).strip():
            host["ip"] = ip.group(1).strip()
        mac = _MAC_RE.search(scope)
        if mac and normalize_mac(mac.group(1)):
            host["mac"] = normalize_mac(mac.group(1))
        if host:
            end_hosts[name] = host

    links: list[tuple[str, str, str, str, str | None]] = []
    for block in _LINK_BLOCK_RE.findall(xml_text):
        fields = {}
        for key in ("FROM", "PORT", "TO"):
            m = re.search(rf"<{key}>(.*?)</{key}>", block, re.DOTALL)
            fields[key] = m.group(1).strip() if m else ""
        # the second PORT occurrence is the TO port; parse positionally
        ports = re.findall(r"<PORT>(.*?)</PORT>", block, re.DOTALL)
        media_m = re.search(r"<TYPE>(.*?)</TYPE>", block, re.DOTALL)

        frm = ref_to_name.get(fields["FROM"])
        to = ref_to_name.get(fields["TO"])
        if not frm or not to or len(ports) < 2:
            continue
        links.append(
            (
                frm,
                canonical_interface_name(ports[0].strip()),
                to,
                canonical_interface_name(ports[1].strip()),
                media_m.group(1).strip() if media_m else None,
            )
        )

    return {
        "devices": devices,
        "configs": configs,
        "links": links,
        "end_hosts": end_hosts,
        "models": models,
    }


def _abstain_message(selection: SnapshotSelection) -> str:
    return "snapshot selection abstained: " + "; ".join(selection.notes)
