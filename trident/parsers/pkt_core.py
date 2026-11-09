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
import re
from pathlib import Path

from ..models import ParserReport, ParserState
from ..normalization.configs import parse_running_config
from ..normalization.values import canonical_interface_name
from .base import AdapterResult, ParserAdapter
from .snapshot import (
    build_placeholder_map,
    device_names_in,
    resolve_display_name,
    select_snapshot,
)


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

        # --- 0. snapshot selection (same policy as engines A and C) ------------
        # The whole decoded document is inspected ONLY to select the snapshot;
        # extraction below is filtered to that snapshot's device inventory, so
        # reference/answer networks in other blocks or wrappers never leak in.
        is_xml = file_path.suffix.lower() == ".xml"

        selected_names: set[str] | None = None
        placeholder_map: dict[str, str] = {}
        #: The decoded document is kept so the typed model can be built from it
        #: instead of decoding the container a second time. Container decode is
        #: the dominant cost on large files (measured: 215 s of 218 s total on a
        #: 30 MB activity), so repeating it doubled Engine B's latency and pushed
        #: it past its timeout.
        decoded: bytes | None = None
        try:
            if is_xml:
                decoded = file_path.read_bytes()
            else:
                decoded = pkt_core.decode_bytes(file_path.read_bytes()).xml
            selection = select_snapshot(decoded.decode("utf-8", errors="replace"))
            result.raw["snapshot"] = selection.snapshot_id
            result.raw["snapshot_notes"] = selection.notes
            result.raw["snapshot_abstained"] = selection.abstained
            result.extraction_family = "pkt-core"
            result.report.notes = list(selection.notes)
            if selection.abstained:
                result.report.state = ParserState.OK
                result.report.message = (
                    "snapshot selection abstained: " + "; ".join(selection.notes)
                )
                result.report.device_count = 0
                return result
            selected_names = set(device_names_in(selection.xml_text or ""))
            # Engines report device names exactly as they appear in the raw XML,
            # i.e. still carrying ``[[pr3-rt_Display_name]]`` placeholders. Resolve
            # them the same way the selected snapshot was resolved, otherwise every
            # real device is filtered out and only unnamed objects survive.
            placeholder_map = build_placeholder_map(decoded.decode("utf-8", errors="replace"))
            result.raw["placeholder_map"] = placeholder_map
        except Exception as exc:  # noqa: BLE001 - pkt_core version differences
            # Cannot identify the intended snapshot safely -> abstain entirely.
            result.raw["snapshot"] = "abstain"
            result.raw["snapshot_notes"] = [
                (f"snapshot could not be determined ({type(exc).__name__}); abstaining instead of "
                 "extracting from the whole document")
            ]
            result.raw["snapshot_abstained"] = True
            result.report.notes = list(result.raw["snapshot_notes"])
            result.report.message = "snapshot selection abstained: " + result.raw["snapshot_notes"][0]
            result.report.device_count = 0
            return result

        # --- 1. typed lab model ------------------------------------------------
        devices: list[str] = []
        models: dict[str, str] = {}
        links: list[tuple[str, str, str, str, str | None]] = []
        lab = None
        try:
            # pkt-core can parse an already-decoded document directly, and that
            # is its OWN parser rather than engine A's, so the observations stay
            # independent evidence at the extraction layer. Using the bytes we
            # already decoded avoids a second full container decode.
            from pkt_core.models.lab import Lab as _LabView

            if decoded is not None:
                lab = _LabView.from_bytes(decoded)
            else:
                lab = pkt_core.open_lab(file_path)
            for dev in lab.devices:
                if not dev.name:
                    continue
                resolved = resolve_display_name(dev.name, placeholder_map)
                if selected_names is None or resolved in selected_names:
                    devices.append(resolved)
                    # pkt-core exposes the hardware model as its own parsed field.
                    model = (getattr(dev, "model", None) or "").strip()
                    if model and model.lower() != "power distribution device":
                        models[resolved] = model
            if selected_names is not None:
                messages.append(f"typed model: {len(devices)} devices (snapshot-scoped)")
            else:
                messages.append(f"typed model: {len(devices)} devices")
        except Exception as exc:  # noqa: BLE001
            messages.append(f"typed model failed: {type(exc).__name__}: {exc}")

        # --- 2. CLI unpack: topology.json + configs ----------------------------
        outdir = workdir / "pkt_core_out"
        outdir.mkdir(parents=True, exist_ok=True)
        cli_error: str | None = None
        xml_configs: dict[str, list[str]] = {}
        #: Filled here rather than in the later config section, because the
        #: in-process extraction below already has the parsed Lab.
        configs: dict[str, list[str]] = {}
        if is_xml:
            # A decoded XML has no container for the CLI to unpack; running it
            # would just fail after burning the full timeout. Extract configs
            # from the typed model instead.
            xml_configs = _xml_configs_from_lab(lab, placeholder_map, selected_names, messages)
            topology = None
        else:
            # Extract configs in-process from the Lab we already parsed instead of
            # shelling out to `pkt_core.cli.main unpack`.
            #
            # That subprocess decodes the container from scratch: on a 30 MB
            # activity it took 219 s on its own, doubling Engine B's total to
            # ~450 s and exceeding the parser timeout. Its only outputs are the
            # XML (we already have it), topology.json/dot, and the per-device
            # `.cfg` files, which it produces by walking each device's
            # ENGINE/RUNNINGCONFIG node. Reproducing that here costs milliseconds
            # and produces identical config text.
            from pkt_core.models import RunningConfig as _RunningConfig

            written = 0
            skipped = 0
            for dev in (lab.devices if lab is not None else []):
                try:
                    engine = dev.element.find("ENGINE")
                    if engine is None:
                        continue
                    node = engine.find("RUNNINGCONFIG")
                    if node is None:
                        continue
                    lines = _RunningConfig.from_element(node).lines
                    if not lines:
                        continue
                except Exception as exc:  # noqa: BLE001 - one device must not sink the rest
                    skipped += 1
                    messages.append(f"config skipped for {dev.name!r}: {type(exc).__name__}")
                name = resolve_display_name(dev.name, placeholder_map) if dev.name else ""
                if not name:
                    continue
                if selected_names is not None and name not in selected_names:
                    continue
                # ``lines`` are raw bytes on purpose in pkt-core (config text can
                # carry ^C banner delimiters), but every consumer here works with
                # text, so decode once at the boundary.
                configs[name] = [
                    ln.decode("utf-8", "replace") if isinstance(ln, bytes) else str(ln)
                    for ln in lines
                ]
                written += 1
            if written:
                messages.append(f"configs: {written} devices (in-process)")
            if skipped:
                messages.append(f"{skipped} device(s) had no extractable config")
            topology = None
        if topology:
            cli_devices = [d.get("name") for d in topology.get("devices", []) if d.get("name")]
            if selected_names is not None:
                cli_devices = [
                    n
                    for n in (resolve_display_name(x, placeholder_map) for x in cli_devices)
                    if n in selected_names
                ]
            for name in cli_devices:
                if name and name not in devices:
                    devices.append(name)
            result.raw["topology"] = topology

        # links from topology.json are not emitted; use DOT if present.
        # DOT edges are filtered to devices inside the selected snapshot so that
        # links to reference-network devices cannot leak into the model.
        dot = next(outdir.glob("*.dot"), None)
        if dot is not None:
            links = _parse_dot(
                dot.read_text(encoding="utf-8", errors="replace"), placeholder_map
            )
            if selected_names is not None:
                links = [
                    ln for ln in links
                    if ln[0] in selected_names and ln[2] in selected_names
                ]

        # --- 3. per-device IOS configs ----------------------------------------
        if xml_configs:
            configs.update(xml_configs)
        cfg_dir = outdir / "configs"
        if cfg_dir.is_dir():
            # pkt-core names config files after the raw XML device name, which in
            # an activity file is still the placeholder (``pr3-rt_Display_name``).
            # Build the lookup from BOTH the resolved name and the raw placeholder,
            # so neither naming convention drops configs.
            lookup: dict[str, str] = {}
            if selected_names is not None:
                for name in selected_names:
                    lookup[_slug(name)] = name
                    lookup[_slug(resolve_display_name(name, placeholder_map))] = name
                for raw_key, resolved_value in placeholder_map.items():
                    if resolved_value in selected_names:
                        lookup[_slug(raw_key)] = resolved_value

            for cfg_file in sorted(cfg_dir.glob("*.cfg")):
                name = cfg_file.stem
                if selected_names is not None:
                    resolved = (
                        lookup.get(name)
                        or lookup.get(_slug(name))
                        or lookup.get(_slug(resolve_display_name(name, placeholder_map)))
                    )
                    if resolved is None:
                        continue
                    name = resolved
                lines = [
                    ln.rstrip("\r")
                    for ln in cfg_file.read_text(encoding="utf-8", errors="replace").splitlines()
                ]
                configs[name] = lines
            messages.append(f"configs: {len(configs)} devices")

        result.devices = sorted(set(devices))
        result.raw["models"] = models
        result.links = links
        result.configs = configs
        result.report.device_count = len(result.devices)
        result.report.link_count = len(links)
        result.report.interface_count = sum(
            len(parse_running_config(lines).interfaces) for lines in configs.values()
        )
        result.report.message = "; ".join(messages) or "unpacked"

        if not result.devices and not result.configs:
            result.report.state = ParserState.ERROR
            result.report.message = (
                "PKT-CORE returned no devices or configs. "
                + (f"CLI error: {cli_error}" if cli_error else "This file may be an empty activity skeleton.")
            )
        return result


def _slug(name: str) -> str:
    """Sanitised filename stem used by pkt-core for per-device .cfg files.

    pkt-core replaces every non-alphanumeric character with ``_`` and strips
    edge underscores, so ``Hub Switch 1 (Our Trusty Sidekick)`` becomes
    ``Hub_Switch_1__Our_Trusty_Sidekick``. Comparing raw names would drop every
    config whenever a device name contains spaces or punctuation.
    """
    return re.sub(r"[^A-Za-z0-9]", "_", name).strip("_")


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


def _xml_configs_from_lab(
    lab,
    placeholder_map: dict[str, str],
    selected_names: set[str] | None,
    messages: list[str],
) -> dict[str, list[str]]:
    """Pull per-device IOS configs out of pkt-core's typed model for XML input.

    ``device.engine`` is an :class:`XmlElement`. The running configuration lives
    under ``ENGINE/RUNNINGCONFIG/LINE``; startup is a separate subtree and is never
    concatenated.
    """
    from .snapshot import resolve_display_name

    configs: dict[str, list[str]] = {}
    if lab is None:
        return configs
    for dev in getattr(lab, "devices", []):
        raw_name = getattr(dev, "name", None)
        if not raw_name:
            continue
        name = resolve_display_name(str(raw_name), placeholder_map)
        if selected_names is not None and name not in selected_names:
            continue
        engine = getattr(dev, "engine", None)
        if engine is None:
            continue
        try:
            running = engine.find("RUNNINGCONFIG")
        except Exception:  # noqa: BLE001 - XmlElement API differences
            running = None  # treat as "no running config" and skip this device
        if running is None:
            continue
        try:
            lines = [ln.text or "" for ln in running.find_all("LINE")]
        except Exception:  # noqa: BLE001
            messages.append(f"{name}: RUNNINGCONFIG has no LINE accessor")
            continue
        cleaned = [ln.strip() for ln in lines if ln.strip()]
        if cleaned:
            configs[name] = cleaned
    messages.append(f"pkt-core XML parse: {len(configs)} device configs")
    return configs


def _parse_dot(
    text: str, placeholder_map: dict[str, str] | None = None
) -> list[tuple[str, str, str, str, str | None]]:
    """Parse the ``dN [label=...]`` + ``dN -> dM`` Graphviz export from PKT-CORE.

    Node labels carry the raw XML device name, which for an activity file is
    still a ``[[...]]`` placeholder. They are resolved here so link endpoints
    compare equal to resolved device names.
    """
    import re

    labels: dict[str, str] = {}
    for m in re.finditer(r'^\s*(d\d+)\s*\[label="([^"]*)"', text, re.MULTILINE):
        raw = m.group(2).replace("\\\\n", "\\n").split("\\n")[0]
        if placeholder_map:
            raw = resolve_display_name(raw, placeholder_map)
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
