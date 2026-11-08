"""Engine C adapter — pt-convert (All Rights Reserved, external subprocess).

pt-convert ships no Python API and no server API: its logic is client-side
TypeScript. TRIDENT therefore runs it as a **separate Node.js process** through
``engine_c_bridge.mjs``. pt-convert source is never copied into this repository.

Availability requires:
  * ``TRIDENT_PT_CONVERT_DIR`` pointing at a checkout of pt-convert
  * ``node`` on PATH
  * that checkout's own node_modules containing pako / twofish / fast-xml-parser

Any missing piece yields UNAVAILABLE with an actionable message.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..models import ParserReport, ParserState
from ..normalization.configs import parse_running_config
from ..normalization.values import canonical_interface_name
from .base import AdapterResult, ParserAdapter
from .snapshot import (
    SnapshotSelection,
    build_placeholder_map,
    device_names_in,
    resolve_display_name,
    select_snapshot,
)

BRIDGE = Path(__file__).resolve().parent / "engine_c_bridge.mjs"


class EngineCAdapter(ParserAdapter):
    engine_id = "engine_c"
    display_name = "pt-convert"
    capabilities = (
        "container-decode",
        "independent-js-parser",
        "device-inventory",
        "physical-links-with-real-port-names",
        "ios-config-text",
        "activity-instructions-length",
    )
    limitations = (
        "All Rights Reserved license: executed as an external dependency, never vendored",
        "requires Node.js and a pt-convert checkout via TRIDENT_PT_CONVERT_DIR",
        "container algorithm is the same public format as engines A and B",
        "no MAC addresses or interface state in its simplified output",
    )

    def _node(self) -> str | None:
        return shutil.which(self.cfg.node_binary) or shutil.which("node")

    def _pt_dir(self) -> Path | None:
        if not self.cfg.pt_convert_dir:
            return None
        p = Path(self.cfg.pt_convert_dir).expanduser()
        return p if p.is_dir() else None

    def probe(self) -> tuple[bool, str]:
        node = self._node()
        if node is None:
            return False, "node executable not found on PATH (install Node.js 18+)"
        if not BRIDGE.exists():
            return False, f"bridge script missing at {BRIDGE}"
        pt = self._pt_dir()
        if pt is None:
            return False, (
                "TRIDENT_PT_CONVERT_DIR is not set to a pt-convert checkout. "
                "Clone https://github.com/semicolonmystery/pt-convert and set the variable "
                "(see README licensing note)."
            )
        for rel in ("src/lib/packet-crypto.ts", "src/lib/xml-simplifier.ts"):
            if not (pt / rel).exists():
                return False, f"pt-convert checkout missing {rel}"
        if not (pt / "node_modules").is_dir():
            return False, f"pt-convert dependencies not installed in {pt}/node_modules (run npm install there)"
        return True, f"ready (node at {node})"

    def _extract(self, file_path: Path, workdir: Path) -> AdapterResult:
        # A decoded XML upload is passed straight to the bridge: pt-convert's own
        # simplifyXmlToJson performs the extraction, so this engine stays an
        # independent extraction family for XML inputs as well as containers.

        node = self._node()
        pt = self._pt_dir()
        if node is None or pt is None:
            raise RuntimeError("engine C prerequisites disappeared between probe and run")

        try:
            proc = subprocess.run(
                [node, "--experimental-strip-types", str(BRIDGE), str(pt), str(file_path)],
                capture_output=True,
                text=True,
                timeout=self.cfg.parser_timeout,
                check=False,
                cwd=str(pt),
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("pt-convert bridge timed out") from exc

        stdout = (proc.stdout or "").strip()
        if not stdout:
            raise RuntimeError(
                "pt-convert bridge produced no output; stderr: "
                + (proc.stderr or "").strip()[-500:]
            )

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"pt-convert bridge returned non-JSON: {stdout[:300]}") from exc

        if "error" in payload:
            raise RuntimeError(str(payload["error"]))

        # Snapshot selection uses the SAME shared policy on pt-convert's own
        # decoded XML, so engines A, B and C always analyse the same block.
        # pt-convert's whole-document simplification is then filtered to the
        # selected snapshot's device inventory before anything is contributed.
        if "xml_text" not in payload:
            selection = SnapshotSelection(
                snapshot_id="abstain",
                xml_text=None,
                ambiguous=False,
                notes=[
                    ("bridge did not return decoded XML; cannot verify snapshot identity; "
                     "abstaining instead of trusting whole-document output")
                ],
                abstained=True,
            )
        else:
            selection = select_snapshot(payload.get("xml_text") or "")
        selected_names: set[str] | None = None
        if not selection.abstained:
            selected_names = set(device_names_in(selection.xml_text or ""))

        # pt-convert's simplifier keys devices by the raw XML name, which is still
        # a ``[[...]]`` placeholder in an activity file. Resolve through the same
        # STRING_VAR table used for the snapshot, or every real device is filtered
        # out against the resolved inventory.
        placeholder_map = build_placeholder_map(payload.get("xml_text") or "")

        def _resolve(name: str) -> str:
            return resolve_display_name(str(name), placeholder_map)

        devices_raw = payload.get("devices") or {}
        links_raw = payload.get("links") or []

        if selection.abstained:
            devices_raw, links_raw = {}, []

        resolved_devices: dict[str, dict] = {}
        for name, dev in devices_raw.items():
            resolved = _resolve(name)
            if selected_names is not None and resolved not in selected_names:
                continue
            resolved_devices[resolved] = dev if isinstance(dev, dict) else {}

        devices = sorted(resolved_devices)
        configs: dict[str, list[str]] = {}
        for name, dev in resolved_devices.items():
            cfg_lines = dev.get("config")
            if isinstance(cfg_lines, list) and cfg_lines:
                configs[str(name)] = [str(line) for line in cfg_lines]

        links: list[tuple[str, str, str, str, str | None]] = []
        for link in links_raw:
            if not isinstance(link, dict):
                continue
            a = link.get("FromDevice")
            b = link.get("ToDevice")
            if not a or not b:
                continue
            a_name, b_name = _resolve(a), _resolve(b)
            if selected_names is not None and (
                a_name not in selected_names or b_name not in selected_names
            ):
                continue
            links.append(
                (
                    a_name,
                    canonical_interface_name(str(link.get("FromPort") or "")),
                    b_name,
                    canonical_interface_name(str(link.get("ToPort") or "")),
                    None,
                )
            )

        report = ParserReport(
            engine=self.engine_id,
            state=ParserState.OK,
            version=str((payload.get("metadata") or {}).get("converterVersion") or "pt-convert"),
            message=(
                f"decoded {payload.get('xml_bytes', 0):,} chars of XML; "
                f"{len(devices)} devices, {len(links)} links (snapshot {selection.snapshot_id})"
            ),
            device_count=len(devices),
            link_count=len(links),
            interface_count=sum(
                len(parse_running_config(lines).interfaces) for lines in configs.values()
            ),
            notes=list(selection.notes),
        )
        if not devices:
            report.state = ParserState.ERROR if not selection.abstained else ParserState.OK
            report.message = (
                "snapshot selection abstained: " + "; ".join(selection.notes)
                if selection.abstained
                else "pt-convert returned zero devices (file may be an empty skeleton)"
            )

        return AdapterResult(
            engine_id=self.engine_id,
            report=report,
            devices=devices,
            configs=configs,
            links=links,
            extraction_family="pt-convert",
            raw={
                "metadata": payload.get("metadata", {}),
                "snapshot": selection.snapshot_id,
                "snapshot_ambiguous": selection.ambiguous,
                "snapshot_notes": selection.notes,
                "snapshot_abstained": selection.abstained,
                "activity_instruction_count": len(payload.get("activity_instructions") or []),
            },
        )
