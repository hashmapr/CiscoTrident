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

VENDOR_DIR = REPO_ROOT / "vendor" / "engine_a"
PKG_DIR = VENDOR_DIR / "pka2xml"
#: The directory that must be on sys.path for ``import pka2xml`` to resolve.
IMPORT_ROOT = VENDOR_DIR

_TAG_RE = re.compile(r"<([A-Za-z0-9_]+)([^>]*)>")
_LINE_RE = re.compile(r"<LINE>(.*?)</LINE>", re.DOTALL)


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

        from pka2xml import decrypt_pka

        raw = file_path.read_bytes()
        xml_bytes = decrypt_pka(raw)
        if len(xml_bytes) > self.cfg.max_xml_bytes:
            raise ValueError("decoded XML exceeds configured maximum size")

        xml_text = xml_bytes.decode("utf-8", errors="replace")
        snapshot_id, snapshot_ambiguous, notes = _select_snapshot(xml_text)

        result = AdapterResult(
            engine_id=self.engine_id,
            report=ParserReport(
                engine=self.engine_id,
                state=ParserState.OK,
                message=f"decoded {len(xml_bytes):,} bytes of XML",
                version="MIT build",
            ),
            raw={"snapshot": snapshot_id, "snapshot_ambiguous": snapshot_ambiguous, "notes": notes},
        )

        walk = _walk_xml(xml_text)
        result.devices = walk["devices"]
        result.configs = walk["configs"]
        result.links = walk["links"]
        result.end_hosts = walk["end_hosts"]
        result.report.device_count = len(result.devices)
        result.report.link_count = len(result.links)
        result.report.interface_count = sum(
            len(parse_running_config(cfg).interfaces) for cfg in result.configs.values()
        )
        return result


# ---------------------------------------------------------------------------
# Snapshot selection
# ---------------------------------------------------------------------------

_SNAPSHOT_BLOCK_RE = re.compile(r"<PACKETTRACER5>(.*?)</PACKETTRACER5>", re.DOTALL)
_ACTIVITY_KEYS = ("<ACTIVITY>", "<COMPARISONS>", "<CLEAN_ACTIVITY>", "<INITIALSETUP>")


def _select_snapshot(xml_text: str) -> tuple[str, bool, list[str]]:
    """Pick one network snapshot; never merge and never read answer keys."""
    blocks = _SNAPSHOT_BLOCK_RE.findall(xml_text)
    notes: list[str] = []
    if not blocks:
        return "root", False, ["no <PACKETTRACER5> block; treating root as snapshot"]

    counts = [len(re.findall(r"<DEVICE[ />]", b)) for b in blocks]
    non_empty = [i for i, c in enumerate(counts) if c > 0]
    if not non_empty:
        return "block0", False, ["all snapshot blocks are empty"]

    if len(non_empty) > 1:
        best = max(non_empty, key=lambda i: counts[i])
        notes.append(
            "multiple non-empty snapshot blocks "
            f"(device counts {counts}); analysing block index {best} only"
        )
        return f"block{best}", True, notes

    return f"block{non_empty[0]}", False, notes


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
_LINK_FIELD_RE = {
    name: re.compile(rf"<{name}>(.*?)</{name}>", re.DOTALL)
    for name in ("TYPE", "FROM", "PORT", "TO", "TYPE")
}


def _walk_xml(xml_text: str) -> dict:
    devices: list[str] = []
    configs: dict[str, list[str]] = {}
    end_hosts: dict[str, dict] = {}
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

        lines = [line for line in _LINE_RE.findall(scope)]
        if lines:
            configs[name] = [line.strip() for line in lines]

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

    return {"devices": devices, "configs": configs, "links": links, "end_hosts": end_hosts}
