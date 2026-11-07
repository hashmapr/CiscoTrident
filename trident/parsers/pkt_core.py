"""Engine B adapter — PKT-CORE (GPL-3.0-or-later, external dependency).

PKT-CORE is invoked through its documented public API and its own CLI. Its source
is **not** vendored into this repository; it is installed as a separate
distribution (``pip install pkt-core``). Users are responsible for GPL compliance.

Extraction used here:
  * ``pkt_core.open_lab`` for typed devices/links
  * ``pkt unpack`` for the NetBox-shaped topology JSON and per-device IOS configs

Both are real executions. If either fails the adapter reports ERROR/UNAVAILABLE
and contributes nothing to consensus.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ..models import ParserReport, ParserState
from ..normalization.values import canonical_interface_name
from .base import AdapterResult, ParserAdapter


class EngineBAdapter(ParserAdapter):
    engine_id = "engine_b"
    display_name = "PKT-CORE"
    capabilities = (
        "container-decode",
        "typed-lab-model",
        "device-inventory",
        "physical-links",
        "ios-config-text",
        "netbox-inventory-export",
        "interface-mac-and-media-type",
    )
    limitations = (
        "synthesises interface names as iface0..N in its topology export",
        "GPL-3.0-or-later: installed as an external distribution, not vendored",
        "container algorithm is the same public format as engines A and C",
    )

    def probe(self) -> tuple[bool, str]:
        try:
            import pkt_core

            return True, f"pkt-core {getattr(pkt_core, '__version__', 'unknown')}"
        except Exception as exc:  # noqa: BLE001
            return False, f"pkt-core not importable ({type(exc).__name__}: {exc}); run: pip install pkt-core"

    def _extract(self, file_path: Path, workdir: Path) -> AdapterResult:
        import pkt_core

        result = AdapterResult(
            engine_id=self.engine_id,
            report=ParserReport(
                engine=self.engine_id,
                state=ParserState.OK,
                version=getattr(pkt_core, "__version__", "unknown"),
                message="",
            ),
        )

        messages: list[str] = []

        # --- 1. typed lab model ------------------------------------------------
        devices: list[str] = []
        links: list[tuple[str, str, str, str, str | None]] = []
        try:
            lab = pkt_core.open_lab(file_path)
            for dev in lab.devices:
                if dev.name:
                    devices.append(dev.name)
            messages.append(f"typed model: {len(devices)} devices")
        except Exception as exc:  # noqa: BLE001
            messages.append(f"typed model failed: {type(exc).__name__}: {exc}")

        # --- 2. CLI unpack: topology.json + configs ----------------------------
        outdir = workdir / "pkt_core_out"
        outdir.mkdir(parents=True, exist_ok=True)
        cli_error: str | None = None
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pkt_core.cli.main", "unpack", str(file_path), "-o", str(outdir)],
                capture_output=True,
                text=True,
                timeout=self.cfg.parser_timeout,
                check=False,
            )
            if proc.returncode != 0:
                cli_error = (proc.stderr or proc.stdout or "").strip()[-500:]
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("pkt-core CLI timed out") from exc
        except FileNotFoundError:
            cli_error = "pkt-core CLI module not found"

        topology = _load_topology(outdir, cli_error, messages)
        if topology:
            cli_devices = [d.get("name") for d in topology.get("devices", []) if d.get("name")]
            for name in cli_devices:
                if name and name not in devices:
                    devices.append(name)
            result.raw["topology"] = topology

        # links from topology.json are not emitted; use DOT if present
        dot = next(outdir.glob("*.dot"), None)
        if dot is not None:
            links = _parse_dot(dot.read_text(encoding="utf-8", errors="replace"))

        # --- 3. per-device IOS configs ----------------------------------------
        configs: dict[str, list[str]] = {}
        cfg_dir = outdir / "configs"
        if cfg_dir.is_dir():
            for cfg_file in sorted(cfg_dir.glob("*.cfg")):
                name = cfg_file.stem
                lines = [
                    ln.rstrip("\r")
                    for ln in cfg_file.read_text(encoding="utf-8", errors="replace").splitlines()
                ]
                configs[name] = lines
            messages.append(f"configs: {len(configs)} devices")

        result.devices = sorted(set(devices))
        result.links = links
        result.configs = configs
        result.report.device_count = len(result.devices)
        result.report.link_count = len(links)
        result.report.interface_count = sum(1 for _ in configs)
        result.report.message = "; ".join(messages) or "unpacked"

        if not result.devices and not result.configs:
            result.report.state = ParserState.ERROR
            result.report.message = (
                "PKT-CORE returned no devices or configs. "
                + (f"CLI error: {cli_error}" if cli_error else "This file may be an empty activity skeleton.")
            )
        return result


def _load_topology(outdir: Path, cli_error: str | None, messages: list[str]) -> dict | None:
    topo = outdir / "topology.json"
    if not topo.exists():
        candidates = list(outdir.glob("*topology*.json"))
        topo = candidates[0] if candidates else topo
    if not topo.exists():
        if cli_error:
            messages.append(f"unpack failed: {cli_error}")
        return None
    try:
        data = json.loads(topo.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        messages.append(f"topology.json unreadable: {exc}")
        return None
    if not isinstance(data, dict):
        return None
    return data


_DOT_EDGE_RE = None


def _parse_dot(text: str) -> list[tuple[str, str, str, str, str | None]]:
    """Parse the ``dN [label=...]`` + ``dN -> dM`` Graphviz export from PKT-CORE."""
    import re

    labels: dict[str, str] = {}
    for m in re.finditer(r'^\s*(d\d+)\s*\[label="([^"]*)"', text, re.MULTILINE):
        raw = m.group(2).replace("\\\\n", "\\n").split("\\n")[0]
        labels[m.group(1)] = raw

    links: list[tuple[str, str, str, str, str | None]] = []
    for m in re.finditer(r'^\s*(d\d+)\s*->\s*(d\d+).*?label="([^"]*)"', text, re.MULTILINE):
        a_id, b_id, label = m.group(1), m.group(2), m.group(3)
        if "—" in label:
            parts = [p.strip() for p in label.split("—", 1)]
        elif "-" in label:
            parts = [p.strip() for p in label.split("-", 1)]
        else:
            parts = ["", ""]
        a_name, b_name = labels.get(a_id, a_id), labels.get(b_id, b_id)
        links.append(
            (
                a_name,
                canonical_interface_name(parts[0]),
                b_name,
                canonical_interface_name(parts[1]),
                None,
            )
        )
    return links
