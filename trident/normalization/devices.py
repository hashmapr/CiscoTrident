"""Normalisation of adapter output into the unified network model.

The normalisation engine merges observations from whichever engines ran. It is
*not* the consensus engine: it produces the union of candidate facts plus the
per-field observation list, so that consensus can adjudicate afterwards.

Critical rule: an observation is recorded per (entity, field, engine). Values are
canonicalised on the way in via ``normalization.values`` so equivalent MAC
formats and interface aliases compare equal.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import (
    AclEntry,
    DeviceInfo,
    InterfaceInfo,
    LinkInfo,
    NetworkModel,
    Observation,
    Provenance,
    RouteInfo,
    SettingsInfo,
    VlanInfo,
)
from ..parsers.base import AdapterResult
from .configs import ParsedConfig, parse_running_config
from .values import normalize_mac

#: engines whose container decode is the same public algorithm
SHARED_CRYPTO = True

#: Extraction family per engine, populated by Normalizer from each adapter's
#: declared ``extraction_family``. Consensus needs provenance that names the
#: independent extraction pipeline, not only the engine ID.
_FAMILY_PREFIXES: dict[str, str] = {}
#: Snapshot id threaded from the agreed adapter snapshot selection.
_CURRENT_SNAPSHOT: str = ""


def _prov(engine: str, path: str, snapshot: str | None = None, raw: str = "") -> Provenance:
    family = _FAMILY_PREFIXES.get(engine, engine)
    return Provenance(
        engine=engine,
        extraction_path=f"{family}:{path}" if family else path,
        snapshot=_CURRENT_SNAPSHOT if snapshot is None else snapshot,
        source_path=raw,
        crypto_shared=SHARED_CRYPTO,
        # Layer A: all three engines implement the same public Twofish-EAX format.
        decoder="twofish-eax-qcompress-shared",
        # Layer B: the engine's own extraction pipeline.
        extraction_family=family,
        # Layer C: configs from every engine are parsed by ONE shared parser.
        interpretation_family="trident.parse_running_config",
        normalization=["canonical-interface", "normalize-value"],
        validation=[],
    )


class Normalizer:
    """Builds a NetworkModel from the successful adapter results."""

    def __init__(self, results: list[AdapterResult], snapshot_id: str = "root") -> None:
        global _FAMILY_PREFIXES, _CURRENT_SNAPSHOT
        self.results = [r for r in results if r.ok]
        self.snapshot_id = snapshot_id
        self.observations: list[Observation] = []
        self.warnings: list[str] = []
        _FAMILY_PREFIXES = {
            r.engine_id: (r.extraction_family or r.engine_id) for r in self.results
        }
        _CURRENT_SNAPSHOT = snapshot_id

    # ------------------------------------------------------------------
    def build(self) -> NetworkModel:
        model = NetworkModel(snapshot_id=self.snapshot_id)

        device_obs: dict[str, set[str]] = defaultdict(set)
        # 1. device inventory ---------------------------------------------------
        for res in self.results:
            for name in res.devices:
                device_obs[name].add(res.engine_id)
                self.observations.append(
                    Observation(
                        field="name",
                        entity_type="device",
                        entity_id=name,
                        value=name,
                        provenance=_prov(res.engine_id, "inventory"),
                    )
                )

        # 1b. hardware model (structural metadata, independently extracted by
        #     each engine that exposes it: A from <TYPE model="...">, B from
        #     pkt-core's parsed device model, C from pt-convert's simplified JSON).
        for res in self.results:
            models = (res.raw or {}).get("models") or {}
            if not isinstance(models, dict):
                continue
            for device, model_value in models.items():
                value = str(model_value).strip()
                if not value:
                    continue
                device_obs[device].add(res.engine_id)
                self.observations.append(
                    Observation(
                        field="hardware_model",
                        entity_type="device",
                        entity_id=device,
                        value=value,
                        provenance=_prov(
                            res.engine_id,
                            "structural-type",
                            raw=f"DEVICE/ENGINE/TYPE/@model = {value}",
                        ),
                    )
                )

        # 2. per-engine IOS configs --------------------------------------------
        parsed_by_engine: dict[str, dict[str, ParsedConfig]] = {}
        for res in self.results:
            parsed: dict[str, ParsedConfig] = {}
            for device, lines in res.configs.items():
                parsed[device] = parse_running_config(lines)
            parsed_by_engine[res.engine_id] = parsed
            for device, cfg in parsed.items():
                if device not in device_obs:
                    device_obs[device].add(res.engine_id)
                self._record_config_observations(res.engine_id, device, cfg)

        # 3. engine-specific end-host facts ------------------------------------
        for res in self.results:
            for device, host in res.end_hosts.items():
                device_obs[device].add(res.engine_id)
                for field_name in ("ip", "subnet", "gateway", "dns", "mac"):
                    if field_name in host:
                        val = host[field_name]
                        if isinstance(val, list):
                            val = ",".join(val)
                        self.observations.append(
                            Observation(
                                field=f"endhost_{field_name}",
                                entity_type="device",
                                entity_id=device,
                                value=str(val),
                                provenance=_prov(res.engine_id, "endhost-xml"),
                            )
                        )

        # 4. assemble devices + interfaces -------------------------------------
        best_cfg = _pick_best_configs(parsed_by_engine)

        for name in sorted(device_obs):
            engines = sorted(device_obs[name])
            iface_map: dict[str, InterfaceInfo] = {}

            for engine_id, cfgs in parsed_by_engine.items():
                cfg = cfgs.get(name)
                if cfg is None:
                    continue
                for canon, piface in cfg.interfaces.items():
                    iface = iface_map.get(canon)
                    if iface is None:
                        iface = InterfaceInfo(
                            device=name,
                            name=piface.name,
                            canonical_name=canon,
                            provenance=[],
                        )
                        iface_map[canon] = iface
                    _merge_interface(iface, piface, engine_id, self.snapshot_id)

            # End hosts (PC/Server) have no IOS running-config, so the loop
            # above creates no interface for them. Their NIC is described only
            # by engine-specific end-host facts (endhost_ip/endhost_subnet).
            # Without an InterfaceInfo, _endpoint_address() returns None for
            # every access port, and the VLAN/trunk/gateway detectors — which
            # correlate a switch port with the host on the other end — can
            # never run. That is why a 15-fault lab produced 2 findings.
            endhost_facts = _endhost_facts(self.results, name)
            if endhost_facts and not iface_map:
                nic_canon = "FastEthernet0"
                nic = InterfaceInfo(
                    device=name,
                    name=nic_canon,
                    canonical_name=nic_canon,
                    provenance=[
                        _prov(e, "endhost-xml", self.snapshot_id)
                        for e in sorted(endhost_facts["_engines"])
                    ],
                )
                nic.ipv4_address = endhost_facts.get("ip")
                nic.subnet_mask = endhost_facts.get("subnet")
                nic.ipv4_gateway = endhost_facts.get("gateway")
                nic.prefix_length = _prefix_from_mask(endhost_facts.get("subnet"))
                iface_map[nic_canon] = nic
            cfg_for_meta = best_cfg.get(name)
            dev = DeviceInfo(
                id=name,
                name=name,
                hostname=(cfg_for_meta.hostname if cfg_for_meta else None) or name,
                ios_version=cfg_for_meta.ios_version if cfg_for_meta else None,
                configuration=_raw_config_lines(self.results, name),
                source_path="NETWORK/DEVICES/DEVICE/ENGINE",
                interfaces=sorted(iface_map),
                provenance=[_prov(e, "inventory") for e in engines],
            )
            dev.device_type, dev.model = _infer_type_model(self.results, name)
            model.devices[name] = dev
            for canon, iface in iface_map.items():
                model.interfaces[f"{name}:{canon}"] = iface

        # 5. links --------------------------------------------------------------
        model.links = self._build_links(device_obs)

        # 6. routes / vlans / acls / settings -----------------------------------
        model.routes = _collect_routes(parsed_by_engine, self.snapshot_id)
        model.vlans = _collect_vlans(parsed_by_engine, model, self.snapshot_id)
        model.acls = _collect_acls(parsed_by_engine, model, self.snapshot_id)
        model.settings = _collect_settings(parsed_by_engine, self.results)

        model.observations = self.observations
        model.warnings = self.warnings
        if not self.results:
            self.warnings.append("no parser engine produced usable output")
        return model

    # ------------------------------------------------------------------
    def _record_config_observations(self, engine: str, device: str, cfg: ParsedConfig) -> None:
        for canon, piface in cfg.interfaces.items():
            if piface.ipv4_address:
                self.observations.append(
                    Observation(
                        field="ipv4_address",
                        entity_type="interface",
                        entity_id=f"{device}:{canon}",
                        value=piface.ipv4_address,
                        provenance=_prov(engine, "ios-config"),
                        raw_evidence=f"ip address {piface.ipv4_address} {piface.subnet_mask or ''}".strip(),
                    )
                )
            if piface.mac_address:
                self.observations.append(
                    Observation(
                        field="mac_address",
                        entity_type="interface",
                        entity_id=f"{device}:{canon}",
                        value=piface.mac_address,
                        provenance=_prov(engine, "ios-config"),
                        raw_evidence=f"mac-address {piface.mac_address}",
                    )
                )
            if piface.access_vlan:
                self.observations.append(
                    Observation(
                        field="vlan",
                        entity_type="interface",
                        entity_id=f"{device}:{canon}",
                        value=piface.access_vlan,
                        provenance=_prov(engine, "ios-config"),
                        raw_evidence=f"switchport access vlan {piface.access_vlan}",
                    )
                )
        if cfg.hostname:
            self.observations.append(
                Observation(
                    field="hostname",
                    entity_type="device",
                    entity_id=device,
                    value=cfg.hostname,
                    provenance=_prov(engine, "ios-config"),
                    raw_evidence=f"hostname {cfg.hostname}",
                )
            )

    # ------------------------------------------------------------------
    def _build_links(self, device_obs: dict[str, set[str]]) -> list[LinkInfo]:
        seen: set[tuple[str, str, str, str]] = set()
        links: list[LinkInfo] = []
        for res in self.results:
            for (a, ia, b, ib, media) in res.links:
                if a not in device_obs or b not in device_obs:
                    continue
                key = tuple(sorted([(a, ia), (b, ib)]))  # type: ignore[arg-type]
                flat = (key[0][0], key[0][1], key[1][0], key[1][1])
                if flat in seen:
                    # record additional provenance on the existing link
                    for link in links:
                        if (
                            link.device_a,
                            link.interface_a,
                            link.device_b,
                            link.interface_b,
                        ) == flat:
                            link.provenance.append(_prov(res.engine_id, "links", self.snapshot_id))
                            break
                    continue
                seen.add(flat)
                links.append(
                    LinkInfo(
                        device_a=key[0][0],
                        interface_a=key[0][1],
                        device_b=key[1][0],
                        interface_b=key[1][1],
                        media_type=media,
                        provenance=[_prov(res.engine_id, "links", self.snapshot_id)],
                    )
                )
        return sorted(links, key=lambda l: (l.device_a, l.interface_a, l.device_b, l.interface_b))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _endhost_facts(results, device: str) -> dict:
    """Merged end-host NIC facts for one device, plus which engines saw them.

    ``end_hosts`` is engine-specific (engines A and B populate it from the
    device XML). Facts are merged with the first non-empty value winning, in
    deterministic engine order, so two engines cannot produce a value that
    depends on dict ordering.
    """
    merged: dict = {"_engines": set()}
    for res in sorted(results, key=lambda r: r.engine_id):
        host = (res.end_hosts or {}).get(device)
        if not host:
            continue
        merged["_engines"].add(res.engine_id)
        for key in ("ip", "subnet", "gateway", "mac"):
            value = host.get(key)
            if value and not merged.get(key):
                merged[key] = value if isinstance(value, str) else str(value)
    return merged if merged["_engines"] else {}


def _prefix_from_mask(mask: str | None) -> int | None:
    """Convert a dotted-quad mask to a prefix length, or None if unusable.

    Rejects non-contiguous masks rather than guessing: ``255.0.255.0`` is not a
    mask, and treating it as /16 would silently mis-correlate subnets.
    """
    if not mask:
        return None
    try:
        octets = [int(part) for part in str(mask).split(".")]
    except (TypeError, ValueError):
        return None
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return None
    bits = "".join(f"{o:08b}" for o in octets)
    if "01" in bits:  # a zero followed by a one is a hole in the mask
        return None
    return bits.count("1")


def _merge_interface(iface: InterfaceInfo, piface, engine: str, snapshot: str) -> None:
    prov = _prov(engine, "ios-config", snapshot)
    if prov not in iface.provenance:
        iface.provenance.append(prov)
    if piface.description and not iface.description:
        iface.description = piface.description
    if piface.ipv4_address and not iface.ipv4_address:
        iface.ipv4_address = piface.ipv4_address
    if piface.subnet_mask and not iface.subnet_mask:
        iface.subnet_mask = piface.subnet_mask
    if piface.prefix_length is not None and iface.prefix_length is None:
        iface.prefix_length = piface.prefix_length
    if piface.ipv6_address and not iface.ipv6_address:
        iface.ipv6_address = piface.ipv6_address
    if piface.mac_address and not iface.mac_address:
        iface.mac_address = normalize_mac(piface.mac_address)
    if piface.admin_state and not iface.admin_state:
        iface.admin_state = piface.admin_state
    if piface.speed and piface.speed != "auto" and not iface.speed:
        iface.speed = piface.speed
    if piface.switchport_mode and not iface.access_mode:
        iface.access_mode = piface.switchport_mode
    elif piface.access_vlan and not iface.access_mode:
        iface.access_mode = "access"
    # Native VLAN. Parsed into ParsedInterface since the beginning but never
    # merged, so every trunk in the model reported native_vlan=None and a native
    # VLAN mismatch -- one of the most common real trunk faults -- could not be
    # detected at all.
    if piface.native_vlan and iface.native_vlan is None:
        try:
            iface.native_vlan = int(str(piface.native_vlan).strip())
        except (TypeError, ValueError):
            pass
    if piface.encapsulation_vlan and piface.encapsulation_vlan not in iface.vlan_assignments:
        iface.vlan_assignments.append(piface.encapsulation_vlan)
    if piface.access_vlan and piface.access_vlan not in iface.vlan_assignments:
        iface.vlan_assignments.append(piface.access_vlan)
    for vlan in piface.trunk_allowed:
        if vlan not in iface.vlan_assignments:
            iface.vlan_assignments.append(vlan)


def _pick_best_configs(parsed_by_engine: dict[str, dict[str, ParsedConfig]]) -> dict[str, ParsedConfig]:
    """Choose the richest config for metadata; ties resolved deterministically."""
    best: dict[str, ParsedConfig] = {}
    order = sorted(parsed_by_engine)
    for device in {d for cfgs in parsed_by_engine.values() for d in cfgs}:
        candidates = [(e, parsed_by_engine[e][device]) for e in order if device in parsed_by_engine[e]]
        candidates.sort(key=lambda pair: (-pair[1].line_count, pair[0]))
        if candidates:
            best[device] = candidates[0][1]
    return best


def _raw_config_lines(results: list[AdapterResult], device: str) -> list[str]:
    for res in sorted(results, key=lambda r: r.engine_id):
        if device in res.configs:
            return list(res.configs[device])
    return []


def _infer_type_model(results: list[AdapterResult], device: str) -> tuple[str | None, str | None]:
    """Resolve hardware model from any engine that exposes it.

    Engine A records ``<TYPE model="2911">``; pkt-core exposes it in its topology
    export. Preference is deterministic (engine order), never guesswork.
    """
    for res in sorted(results, key=lambda r: r.engine_id):
        raw = res.raw if isinstance(res.raw, dict) else None
        if not raw:
            continue
        models = raw.get("models")
        if isinstance(models, dict) and models.get(device):
            return None, str(models[device]).strip()
        topo = raw.get("topology")
        if not topo:
            continue
        for dev in topo.get("devices", []):
            if dev.get("name") != device:
                continue
            role = dev.get("device_role")
            dtype = dev.get("device_type") or {}
            return role, dtype.get("model")
    return None, None


def _collect_routes(
    parsed_by_engine: dict[str, dict[str, ParsedConfig]], snapshot: str
) -> list[RouteInfo]:
    merged: dict[tuple, RouteInfo] = {}
    for engine in sorted(parsed_by_engine):
        for device, cfg in parsed_by_engine[engine].items():
            for route in cfg.routes:
                # The device is part of the identity: two routers with the same
                # default route are two distinct routes, not one.
                key = (
                    device,
                    route.route_type,
                    route.destination,
                    route.next_hop,
                    route.outgoing_interface,
                    route.protocol,
                )
                prov = _prov(engine, "ios-config", snapshot, route.raw)
                if key in merged:
                    if prov not in merged[key].provenance:
                        merged[key].provenance.append(prov)
                    continue
                merged[key] = RouteInfo(
                    destination=route.destination,
                    next_hop=route.next_hop,
                    outgoing_interface=route.outgoing_interface,
                    route_type=route.route_type,
                    device=device,
                    protocol=route.protocol,
                    raw_config=route.raw,
                    provenance=[prov],
                )
    return list(merged.values())


def _collect_vlans(
    parsed_by_engine: dict[str, dict[str, ParsedConfig]],
    model: NetworkModel,
    snapshot: str,
) -> list[VlanInfo]:
    merged: dict[int, VlanInfo] = {}
    for engine in sorted(parsed_by_engine):
        for _device, cfg in parsed_by_engine[engine].items():
            for vlan in cfg.vlans:
                entry = merged.get(vlan.vlan_id)
                if entry is None:
                    entry = VlanInfo(vlan_id=vlan.vlan_id, name=vlan.name, provenance=[])
                    merged[vlan.vlan_id] = entry
                elif vlan.name and not entry.name:
                    entry.name = vlan.name
                prov = _prov(engine, "ios-config", snapshot, vlan.raw)
                if prov not in entry.provenance:
                    entry.provenance.append(prov)

    # member ports from the merged interface model
    for iface in model.interfaces.values():
        for vlan_id in iface.vlan_assignments:
            try:
                vid = int(vlan_id)
            except ValueError:
                continue
            entry = merged.setdefault(vid, VlanInfo(vlan_id=vid, provenance=[]))
            member = f"{iface.device}:{iface.canonical_name}"
            if member not in entry.member_ports:
                entry.member_ports.append(member)

    for entry in merged.values():
        entry.member_ports.sort()
    return sorted(merged.values(), key=lambda v: v.vlan_id)


def _collect_acls(
    parsed_by_engine: dict[str, dict[str, ParsedConfig]],
    model: NetworkModel,
    snapshot: str,
) -> list[AclEntry]:
    merged: dict[tuple, AclEntry] = {}
    for engine in sorted(parsed_by_engine):
        for _device, cfg in parsed_by_engine[engine].items():
            # An ACE belongs to the interface that applies it. `ip access-group N
            # in` names the ACL and the direction on a real interface; without
            # this binding every bound deny is invisible to the reasoning layer,
            # which compares `applied_interface` against the interface under test.
            bindings: dict[str, tuple[str, str]] = {}
            for iface in cfg.interfaces.values():
                if iface.acl_in:
                    bindings.setdefault(iface.acl_in, (iface.name, "in"))
                if iface.acl_out:
                    bindings.setdefault(iface.acl_out, (iface.name, "out"))

            for acl in cfg.acls:
                key = (acl.acl_id, acl.action, acl.protocol, acl.source, acl.destination, acl.raw)
                prov = _prov(engine, "ios-config", snapshot, acl.raw)
                if key in merged:
                    merged[key].provenance.append(prov)
                    continue
                interface, direction = bindings.get(acl.acl_id, (None, None))
                merged[key] = AclEntry(
                    acl_id=acl.acl_id,
                    acl_type=acl.acl_type,
                    sequence=acl.sequence,
                    action=acl.action,
                    protocol=acl.protocol,
                    source=acl.source,
                    destination=acl.destination,
                    port_conditions=acl.port_conditions,
                    applied_interface=interface,
                    direction=direction,
                    raw=acl.raw,
                    provenance=[prov],
                )

    return sorted(merged.values(), key=lambda a: (a.acl_id, a.raw))


def _collect_settings(
    parsed_by_engine: dict[str, dict[str, ParsedConfig]],
    results: list[AdapterResult],
) -> SettingsInfo:
    info = SettingsInfo()
    # DHCP pool contents and exclusions. Collected here rather than in the
    # detectors because they are facts about the configuration, and because a
    # detector that re-parsed raw config would be a second, divergent parser.
    for engine in sorted(parsed_by_engine):
        for device, cfg in sorted(parsed_by_engine[engine].items()):
            if cfg.dhcp_pool_details and device not in info.dhcp_details:
                info.dhcp_details[device] = {
                    name: dict(details)
                    for name, details in cfg.dhcp_pool_details.items()
                }
            if cfg.dhcp_excluded and device not in info.dhcp_excluded:
                info.dhcp_excluded[device] = list(cfg.dhcp_excluded)
    for engine in sorted(parsed_by_engine):
        for device, cfg in sorted(parsed_by_engine[engine].items()):
            if cfg.default_gateway and device not in info.default_gateways:
                info.default_gateways[device] = cfg.default_gateway
            if cfg.dns_servers and device not in info.dns_servers:
                info.dns_servers[device] = list(cfg.dns_servers)
            if cfg.dhcp_pools and device not in info.dhcp_configured:
                info.dhcp_configured.append(device)
            if cfg.ios_version and device not in info.software_versions:
                info.software_versions[device] = cfg.ios_version
            if cfg.management:
                info.management.setdefault(device, [])
                for item in cfg.management:
                    if item not in info.management[device]:
                        info.management[device].append(item)

    for res in results:
        for device, host in res.end_hosts.items():
            if "gateway" in host and device not in info.default_gateways:
                info.default_gateways[device] = host["gateway"]
            dns = host.get("dns")
            if dns:
                values = dns if isinstance(dns, list) else [dns]
                values = [v for v in values if v]
                if values and device not in info.dns_servers:
                    info.dns_servers[device] = values
    return info
