"""Deterministic question -> typed-operation router.

This runs before any heuristic inference or AI plan. It maps unambiguous question
phrasings onto the typed operations in :mod:`trident.reasoning.operations`, which
declare their own answer type and are gated on it.

Design rules:

* Only route when the intent is unambiguous. A phrase that mentions both a mask
  and an address is *not* routed by guesswork; it falls through.
* Entities are resolved from the model (longest bounded match), never by taking
  the first substring hit.
* Anything unrecognised returns ``None`` so the caller keeps its old behaviour.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import NetworkModel
from ..normalization.values import canonical_interface_name
from . import operations as ops

#: Interface mentions such as Gi0/0, Gi1/0/2, GigabitEthernet0/1, Fa0/1, Vlan1.
_IFACE_RE = re.compile(
    r"\b((?:gigabit|fast|ethernet|serial|ten|twenty|forty|port|vlan|loopback|tunnel)"
    r"[a-z\-]*\s*\d[\d/\.:]*|(?:gi|fa|se|te|po|vl)\s*\d[\d/\.:]*)\b",
    re.IGNORECASE,
)

_COUNT_LINKS_RE = re.compile(r"\bhow\s+many\s+(?:physical\s+)?(?:cables?|links?)\b", re.IGNORECASE)
_COUNT_DEVICES_RE = re.compile(r"\bhow\s+many\s+(?:devices?|nodes?|hosts?)\b", re.IGNORECASE)

_HOSTNAME_RE = re.compile(r"\bhostname\b", re.IGNORECASE)
_MASK_RE = re.compile(r"\b(subnet\s+mask|netmask|mask)\b", re.IGNORECASE)
_PREFIX_RE = re.compile(r"\b(prefix\s+length|cidr)\b", re.IGNORECASE)
_NETWORK_RE = re.compile(r"\bnetwork\s+(address|id)\b", re.IGNORECASE)
_IP_RE_Q = re.compile(r"\b(ip\s+address|ipv4\s+address|ip\b)", re.IGNORECASE)
_PEER_IF_RE = re.compile(
    r"\b(peer|remote|other|opposite|far[- ]end)\s+(interface|port)\b", re.IGNORECASE
)
_COUNT_NEIGHBORS_RE = re.compile(
    r"\bhow\s+many\s+(?:distinct\s+)?(?:physical\s+)?(?:neighbou?rs?|neighbou?ring\s+devices?|adjacent)\b",
    re.IGNORECASE,
)
_IFACE_ON_RE = re.compile(
    r"\bwhich\s+interface\s+on\s+(.+?)\s+is\s+physically\s+connected\s+to\b", re.IGNORECASE
)
_NEIGHBOR_RE = re.compile(
    r"\b(connected\s+to|connects?\s+to|neighbou?r|attached\s+to)\b", re.IGNORECASE
)
#: "on interface X" / "on port X" / "on its X port". X may be a plain port name
#: such as ``PC`` on an IP phone, which the general interface regex does not
#: recognise because it has no digits.
_ON_IFACE_RE = re.compile(
    r"\bon\s+(?:the\s+|its\s+)?(?:interface\s+|port\s+)?([A-Za-z][A-Za-z0-9/\\.:_-]*?)"
    r"(?:\s+port)?\s*(?:\?|\.|$)",
    re.IGNORECASE,
)
_MODEL_RE = re.compile(r"\b(model|hardware|platform)\b", re.IGNORECASE)
_GATEWAY_RE = re.compile(r"\bdefault[\s-]?gateway\b", re.IGNORECASE)
_DEFAULT_ROUTE_RE = re.compile(
    r"\b(default\s+route|route\s+of\s+last\s+resort|0\.0\.0\.0)\b", re.IGNORECASE
)
_SAME_SUBNET_RE = re.compile(
    r"\b(same\s+subnet|same\s+network|common\s+subnet|reachable\s+directly)\b", re.IGNORECASE
)


def _device_positions(model: NetworkModel, text: str) -> list[tuple[int, str]]:
    """Positions of device mentions in the text, display names preferred.

    Display-name mentions take precedence over hostnames for the same reason as
    device resolution: many devices share the hostname ``Router``/``Switch``, and
    the word "Router" inside the display name ``Internet (Router) 1`` must not
    register as a hostname hit for some unrelated device.
    """
    display: list[tuple[int, str, int]] = []
    for key, info in model.devices.items():
        if not info.name:
            continue
        m = re.search(
            rf"(?<![A-Za-z0-9_\-]){re.escape(info.name)}(?![A-Za-z0-9_\-])",
            text,
            re.IGNORECASE,
        )
        if m:
            display.append((m.start(), key, len(info.name)))

    if display:
        # Drop mentions that fall inside a longer display-name mention.
        display.sort(key=lambda item: item[0])
        kept: list[tuple[int, str]] = []
        for start, key, length in display:
            if any(s <= start < s + ln for s, _k, ln in display if ln > length and s != start):
                continue
            kept.append((start, key))
    else:
        kept = []

    # Uniquely-named hostname mentions always count, whether or not display
    # names also appear. A question can mix both forms, and dropping the
    # hostname-only device loses half the question.
    seen = {k for _s, k in kept}
    for key, info in model.devices.items():
        if not info.hostname or key in seen:
            continue
        host = info.hostname.lower()
        if sum(1 for i in model.devices.values() if (i.hostname or "").lower() == host) != 1:
            continue
        hm = re.search(
            rf"(?<![A-Za-z0-9_\-]){re.escape(info.hostname)}(?![A-Za-z0-9_\-])",
            text,
            re.IGNORECASE,
        )
        if hm:
            kept.append((hm.start(), key))

    kept.sort(key=lambda item: item[0])
    return kept


def resolve_interface_pairs(model: NetworkModel, text: str) -> list[tuple[str, str]]:
    """Attribute each interface mention to the device mentioned before it.

    A question like "A Gi0/0 and B Vlan1" mentions interfaces that exist on many
    devices (``Vlan1`` appears on 11 switches). The owning device is the closest
    device mention preceding the interface, which is how the question reads.
    """
    positions = _device_positions(model, text)
    if not positions:
        return []
    pairs: list[tuple[str, str]] = []
    for match in _IFACE_RE.finditer(text):
        canon = canonical_interface_name(match.group(1))
        if not canon:
            continue
        owner = None
        for pos, key in positions:
            if pos < match.start():
                owner = key
            else:
                break
        if owner is None:
            continue
        exists = any(
            info.device == owner
            and canonical_interface_name(info.name).lower() == canon.lower()
            for info in model.interfaces.values()
        )
        if not exists:
            continue
        pair = (owner, canon)
        if pair not in pairs:
            pairs.append(pair)
    return pairs


@dataclass(frozen=True)
class Intent:
    """A routed operation plus its resolved arguments."""

    operation: str
    arguments: dict


def _bounded_find(text: str, needle: str) -> bool:
    if not needle:
        return False
    return re.search(
        rf"(?<![A-Za-z0-9_\-]){re.escape(needle)}(?![A-Za-z0-9_\-])", text, re.IGNORECASE
    ) is not None


def resolve_device_refs_in_text(model: NetworkModel, text: str) -> list[tuple[str, str | None]]:
    """Device mentions in text as ``(device_key, mentioned_label)`` pairs.

    Precedence is strict:

    1. **Display-name mentions win outright.** If any packet-tracer display name
       appears in the text, hostname matches are ignored entirely. Many devices
       share the generic hostname ``Router``/``Switch``, so mixing the two would
       drag unrelated devices into every question.
    2. Hostnames are only used when no display name matched, and only when that
       hostname identifies exactly one device.
    3. Longest match wins among equals, so ``Router-10`` never loses to ``Router``.
    """
    display: list[tuple[str, str, int]] = []
    for key, info in model.devices.items():
        if info.name and _bounded_find(text, info.name):
            display.append((key, info.name, len(info.name)))

    if display:
        display.sort(key=lambda item: item[2], reverse=True)
        kept: list[tuple[str, str]] = []
        kept_labels: list[str] = []
        for key, label, _length in display:
            if any(label.lower() in longer.lower() for longer in kept_labels):
                continue
            kept.append((key, label))
            kept_labels.append(label)
        return kept

    # No display name matched: fall back to an unambiguous hostname mention.
    host_hits = [
        (key, info.hostname or "")
        for key, info in model.devices.items()
        if info.hostname and _bounded_find(text, info.hostname)
    ]
    if not host_hits:
        return []
    # A hostname shared by several devices cannot identify one of them.
    labels = {label.lower() for _, label in host_hits}
    if len(labels) > 1:
        host_hits.sort(key=lambda item: len(item[1]), reverse=True)
        host_hits = host_hits[:1]
    if len(host_hits) == 1:
        return [host_hits[0]]
    return []


def resolve_devices_in_text(model: NetworkModel, text: str) -> list[str]:
    """All device names mentioned in the text, longest-first, no substring errors.

    ``Router`` does not match inside ``Router-10`` because the boundaries are
    enforced. When a longer name contains a shorter one, only the longest is kept
    (``Main Hub Switch (Layer 3) (The Brainiac)`` wins over ``Main Hub Switch``).
    """
    # Collect display-name hits and hostname hits separately.
    display_hits: list[str] = []
    host_hits: list[str] = []
    for key, info in model.devices.items():
        if info.name and _bounded_find(text, info.name):
            display_hits.append(key)
        elif info.hostname and _bounded_find(text, info.hostname):
            host_hits.append(key)

    if display_hits:
        # A display name is an unambiguous identity and wins -- but a question can
        # mix both forms ("Bowser's Castle PC 1 ... to RajMahalS1"), and dropping
        # the hostname-only device silently loses half the question. Keep a
        # hostname hit only when it names a DISTINCT device whose hostname is
        # unique to it (shared names like "Router" stay excluded).
        extra: list[str] = []
        for key in host_hits:
            if key in display_hits:
                continue
            host = (model.devices[key].hostname or "").lower()
            same_host = [
                k for k, i in model.devices.items() if (i.hostname or "").lower() == host
            ]
            if len(same_host) == 1:
                extra.append(key)
        hits = display_hits + extra
    else:
        # Hostnames identify a device only when the matched hostname is unique to
        # it. Several devices sharing hostname "Router" is ambiguous; two
        # different unique hostnames naming two different devices is not.
        unique: list[str] = []
        for key in host_hits:
            host = (model.devices[key].hostname or "").lower()
            same_host = [
                k
                for k, i in model.devices.items()
                if (i.hostname or "").lower() == host
            ]
            if len(same_host) == 1:
                unique.append(key)
        hits = unique
    if not hits:
        return []

    hits.sort(key=lambda k: len(model.devices[k].name), reverse=True)
    kept: list[str] = []
    for name in hits:
        # skip a name fully contained in an already-kept longer name
        if any(
            model.devices[name].name.lower() in model.devices[longer].name.lower()
            for longer in kept
        ):
            continue
        kept.append(name)
    return kept


def _owning_device(model: NetworkModel, canon_iface: str) -> str | None:
    """Which device owns this canonical interface, when exactly one does."""
    owners = {
        info.device
        for info in model.interfaces.values()
        if canonical_interface_name(info.name).lower() == canon_iface.lower()
    }
    return next(iter(owners)) if len(owners) == 1 else None


def resolve_interfaces_in_text(model: NetworkModel, text: str, device: str | None) -> list[str]:
    """Interface mentions in the text, canonicalised and filtered to the device."""
    raw = [m.group(1) for m in _IFACE_RE.finditer(text)]
    out: list[str] = []
    for token in raw:
        canon = canonical_interface_name(token)
        if not canon:
            continue
        if device is not None:
            exists = any(
                info.device == device
                and canonical_interface_name(info.name).lower() == canon.lower()
                for info in model.interfaces.values()
            )
            if not exists:
                continue
        if canon not in out:
            out.append(canon)
    return out


def _order(question: str) -> list[str]:
    """Which property is being asked for? Used to break ties deterministically."""
    return question.lower().split()


def route(model: NetworkModel, question: str) -> Intent | None:
    """Map a question to a typed operation, or ``None`` when ambiguous/unknown."""
    q = question or ""
    if not q.strip():
        return None

    devices = resolve_devices_in_text(model, q)
    primary = devices[0] if devices else None
    interfaces = resolve_interfaces_in_text(model, q, primary)
    iface = interfaces[0] if interfaces else None

    # --- same-subnet comparison (needs two device+interface pairs) -----
    if _SAME_SUBNET_RE.search(q) and len(devices) >= 2:
        ordered = resolve_interface_pairs(model, q)
        if len(ordered) >= 2:
            (dev_a, if_a), (dev_b, if_b) = ordered[0], ordered[1]
            return Intent(
                "are_in_same_subnet",
                {
                    "device_a": dev_a,
                    "interface_a": if_a,
                    "device_b": dev_b,
                    "interface_b": if_b,
                },
            )
        return None

    # --- counting (no entities required) --------------------------------
    if _COUNT_LINKS_RE.search(q):
        return Intent("count_physical_links", {})
    if _COUNT_DEVICES_RE.search(q):
        return Intent("count_devices", {"include_non_network_devices": False})

    # --- "which interface on X is connected to Y <iface>" ----------------
    # Both devices are named and the local interface is the one on X, so the
    # answer is the peer interface on Y. The interface token in the question
    # belongs to Y, so it must be attributed to Y, not to X.
    m_on = _IFACE_ON_RE.search(q)
    if m_on:
        # The subject (A) is the device mentioned first in the question; the
        # interface token later in the sentence belongs to B.
        subject = devices[0] if devices else None
        tail = q[m_on.end():]
        tail_ifaces = [
            canonical_interface_name(x.group(1)) for x in _IFACE_RE.finditer(tail)
        ]
        tail_ifaces = [x for x in tail_ifaces if x]
        if tail_ifaces and devices:
            # Wording: "Which interface on A is connected to B interface X?"
            # X belongs to B; the answer is the interface on A. Resolve the cable
            # from the device that actually OWNS X, then report the other end --
            # which must be on A when the key is consistent.
            target_if = tail_ifaces[0]

            # The interface token belongs to the device named immediately BEFORE
            # it ("... to CSW1 interface Gi1/1/2" -> CSW1 owns Gi1/1/2). Several
            # devices can own a port with the same name, so positional
            # attribution is the only correct reading.
            owner = None
            for pos, key in _device_positions(model, q):
                if pos < m_on.end():
                    continue
                # the device mention that precedes the interface token
                if pos < q.lower().find(target_if.lower(), m_on.end()):
                    owner = key
            if owner is None:
                owners = [
                    d
                    for d in devices
                    if any(
                        info.device == d
                        and canonical_interface_name(info.name).lower() == target_if.lower()
                        for info in model.interfaces.values()
                    )
                ]
                owner = owners[0] if len(owners) == 1 else None

            if owner is not None:
                if owner == subject:
                    # X is on the device the answer must belong to; its peer is
                    # the interface on the other named device.
                    other = next((d for d in devices if d != subject), None)
                    return Intent(
                        "get_peer_interface",
                        {"device": subject, "interface": target_if, "peer": other or ""},
                    )
                # X belongs to the other device; the answer is X's far end,
                # which must sit on the subject device.
                return Intent(
                    "get_peer_interface",
                    {"device": owner, "interface": target_if, "peer": subject},
                )
            # X exists on no named device: abstain instead of guessing.
            return None
        return None

    # --- "which interface ... connected to ..." always wants an interface ----
    if re.search(r"\bwhich\s+interface\b", q, re.IGNORECASE):
        m_conn = re.search(r"connected\s+to\s+(.+?)\s+interface\b", q, re.IGNORECASE)
        if m_conn:
            target_devs = resolve_devices_in_text(model, m_conn.group(1))
            if target_devs:
                target = target_devs[0]
                target_ifaces = [
                    canonical_interface_name(x.group(1))
                    for x in _IFACE_RE.finditer(q[m_conn.end() - len("interface"):])
                ]
                target_ifaces = [x for x in target_ifaces if x]
                if not target_ifaces:
                    tail = q[m_conn.end():]
                    target_ifaces = [
                        canonical_interface_name(x.group(1))
                        for x in _IFACE_RE.finditer(tail)
                    ]
                    target_ifaces = [x for x in target_ifaces if x]
                if target_ifaces:
                    return Intent(
                        "get_peer_interface",
                        {"device": target, "interface": target_ifaces[0]},
                    )
        return None

    # --- neighbour count: no local interface mentioned -------------------
    if _COUNT_NEIGHBORS_RE.search(q) and primary:
        return Intent("count_physical_neighbors", {"device": primary})

    # --- peer interface: needs device + interface ------------------------
    if _PEER_IF_RE.search(q):
        if primary and iface:
            return Intent("get_peer_interface", {"device": primary, "interface": iface})
        return None

    # --- neighbor: "which device is connected to X Y" --------------------
    if _NEIGHBOR_RE.search(q):
        # An explicitly named local interface narrows the question to one cable.
        local_if = iface
        if primary and not local_if:
            m_on = _ON_IFACE_RE.search(q)
            if m_on:
                candidate = m_on.group(1).strip()
                # Accept the token only when the device actually owns such a port
                # (IP-phone ports are named PC / Switch, not Fa0/1).
                owned, _ = ops.find_interface(model, primary, candidate)
                if owned is not None:
                    local_if = candidate
        if primary and local_if:
            return Intent(
                "get_physical_neighbor", {"device": primary, "interface": local_if}
            )
        if primary and len(devices) == 1:
            return Intent("list_physical_neighbors", {"device": primary})
        return None

    if _HOSTNAME_RE.search(q):
        if primary:
            return Intent("get_hostname", {"device": primary})
        return None

    if _PREFIX_RE.search(q):
        if primary and iface:
            return Intent("get_interface_prefix_length", {"device": primary, "interface": iface})
        return None

    if _PREFIX_RE.search(q):
        if primary and iface:
            return Intent("get_interface_prefix_length", {"device": primary, "interface": iface})
        return None

    if _MASK_RE.search(q):
        if primary and iface:
            return Intent("get_interface_mask", {"device": primary, "interface": iface})
        return None

    if _NETWORK_RE.search(q):
        if primary and iface:
            return Intent("get_interface_network", {"device": primary, "interface": iface})
        return None

    if _MODEL_RE.search(q):
        if primary and _IP_RE_Q.search(q) is None:
            return Intent("get_device_model", {"device": primary})
        return None

    if _DEFAULT_ROUTE_RE.search(q):
        if primary:
            return Intent("get_default_route_next_hop", {"device": primary})
        return None

    if _GATEWAY_RE.search(q):
        if primary:
            return Intent("get_switch_default_gateway", {"device": primary})
        return None

    # --- plain IP address (checked last: "mask"/"network" win above) ----
    if _IP_RE_Q.search(q):
        if primary and iface:
            return Intent("get_interface_ip", {"device": primary, "interface": iface})
        return None

    return None
