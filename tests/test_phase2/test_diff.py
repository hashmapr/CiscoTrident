"""Tests for the before/after network comparison engine.

Coverage follows the honesty contract:

* a present device is reported added, a missing one removed (and critical)
* an interface address change cites both before and after evidence
* a route present only after the change is reported as added
* identical snapshots produce zero changes and a positive unchanged_count
* a name that resolves to several devices is ambiguous and never diffed
* ``Router-1`` is never merged with ``Router-10``
"""

from __future__ import annotations

from trident.diff import ChangeKind, Severity, compare
from trident.models import DeviceInfo, InterfaceInfo, NetworkModel, RouteInfo


def iface(device: str, name: str, **kwargs) -> InterfaceInfo:
    canonical = kwargs.pop("canonical_name", name)
    return InterfaceInfo(device=device, name=name, canonical_name=canonical, **kwargs)


def router(dev_id: str, **kwargs) -> DeviceInfo:
    fields = {
        "id": dev_id,
        "name": dev_id,
        "hostname": dev_id,
        "device_type": "router",
        "model": "ISR4331",
        "ios_version": "15.7",
        "interfaces": [],
    }
    fields.update(kwargs)
    return DeviceInfo(**fields)


def device(dev_id: str, **kwargs) -> DeviceInfo:
    return router(dev_id, **kwargs)


def model_with(devices: list[DeviceInfo], interfaces: list[InterfaceInfo], routes=None, snapshot="s") -> NetworkModel:
    model = NetworkModel(snapshot_id=snapshot)
    for dev in devices:
        model.devices[dev.id] = dev
        model.devices[dev.id].interfaces = [i.canonical_name for i in interfaces if i.device == dev.id]
    for info in interfaces:
        model.interfaces[f"{info.device}:{info.canonical_name}"] = info
    model.routes = list(routes or [])
    return model


def base_pair() -> tuple[NetworkModel, NetworkModel]:
    """Two snapshots of the same single-router network."""
    before = model_with(
        [router("R1")],
        [iface("R1", "GigabitEthernet0/0", ipv4_address="10.0.0.1", subnet_mask="255.255.255.0", prefix_length=24)],
        [RouteInfo(destination="0.0.0.0/0", next_hop="10.0.0.254", route_type="static", device="R1")],
        snapshot="before",
    )
    after = model_with(
        [router("R1")],
        [iface("R1", "GigabitEthernet0/0", ipv4_address="10.0.0.1", subnet_mask="255.255.255.0", prefix_length=24)],
        [RouteInfo(destination="0.0.0.0/0", next_hop="10.0.0.254", route_type="static", device="R1")],
        snapshot="after",
    )
    return before, after


# ---------------------------------------------------------------------------
# Device presence
# ---------------------------------------------------------------------------


def test_device_added() -> None:
    before, after = base_pair()
    after.devices["R2"] = router("R2")

    result = compare(before, after)

    assert result.added_devices == ("R2",)
    assert result.removed_devices == ()
    added = [c for c in result.changes if c.field == "device" and c.kind is ChangeKind.ADDED]
    assert len(added) == 1
    assert added[0].device == "R2"
    assert added[0].before is None
    assert added[0].after == "R2"
    assert "absent in before snapshot" in added[0].evidence_before
    assert "present in after snapshot" in added[0].evidence_after


def test_device_removed_is_critical() -> None:
    before, after = base_pair()
    before.devices["R2"] = router("R2")

    result = compare(before, after)

    assert result.removed_devices == ("R2",)
    assert result.added_devices == ()
    removed = [c for c in result.changes if c.field == "device" and c.kind is ChangeKind.REMOVED]
    assert len(removed) == 1
    assert removed[0].device == "R2"
    assert removed[0].severity is Severity.CRITICAL
    assert removed[0].after is None
    assert "present in before snapshot" in removed[0].evidence_before
    assert "absent in after snapshot" in removed[0].evidence_after
    # A removed device is not diffed field by field.
    assert all(c.device == "R2" and c.field == "device" for c in result.changes if c.device == "R2")


# ---------------------------------------------------------------------------
# Interface changes
# ---------------------------------------------------------------------------


def test_interface_address_change_has_before_after_and_evidence() -> None:
    before, after = base_pair()
    after.interfaces["R1:GigabitEthernet0/0"] = iface(
        "R1", "GigabitEthernet0/0", ipv4_address="10.0.0.9", subnet_mask="255.255.255.0", prefix_length=24
    )

    result = compare(before, after)

    ip_changes = [c for c in result.changes if c.field == "ipv4_address"]
    assert len(ip_changes) == 1
    change = ip_changes[0]
    assert change.device == "R1"
    assert change.interface == "GigabitEthernet0/0"
    assert change.before == "10.0.0.1"
    assert change.after == "10.0.0.9"
    assert change.kind is ChangeKind.MODIFIED
    assert change.severity is Severity.WARNING
    assert "10.0.0.1" in change.evidence_before
    assert "10.0.0.9" in change.evidence_after
    assert "before snapshot" in change.evidence_before
    assert "after snapshot" in change.evidence_after
    assert result.added_devices == ()
    assert result.removed_devices == ()


def test_subnet_mask_change_is_warning_and_description_is_info() -> None:
    before, after = base_pair()
    after.interfaces["R1:GigabitEthernet0/0"] = iface(
        "R1",
        "GigabitEthernet0/0",
        ipv4_address="10.0.0.1",
        subnet_mask="255.255.255.128",
        prefix_length=24,
        description="uplink to core",
    )

    result = compare(before, after)
    by_field = {c.field: c for c in result.changes}

    assert by_field["subnet_mask"].severity is Severity.WARNING
    assert by_field["subnet_mask"].kind is ChangeKind.MODIFIED
    assert by_field["description"].severity is Severity.INFO
    assert by_field["description"].kind is ChangeKind.ADDED
    assert by_field["description"].evidence_before.endswith("absent in before snapshot")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def test_route_added() -> None:
    before, after = base_pair()
    after.routes.append(RouteInfo(destination="192.168.10.0/24", next_hop="10.0.0.10", route_type="static", device="R1"))

    result = compare(before, after)

    route_changes = [c for c in result.changes if c.field.startswith("route:")]
    assert len(route_changes) == 1
    change = route_changes[0]
    assert change.kind is ChangeKind.ADDED
    assert change.before is None
    assert change.after == "10.0.0.10"
    assert change.field == "route:192.168.10.0/24"
    assert "absent in before snapshot" in change.evidence_before
    assert "192.168.10.0/24" in change.evidence_after
    assert "after snapshot" in change.evidence_after


def test_route_removed() -> None:
    before, after = base_pair()
    after.routes.clear()

    result = compare(before, after)

    route_changes = [c for c in result.changes if c.field.startswith("route:")]
    assert len(route_changes) == 1
    assert route_changes[0].kind is ChangeKind.REMOVED
    assert route_changes[0].after is None
    assert "0.0.0.0/0" in route_changes[0].field


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_identical_networks_produce_no_changes() -> None:
    before, after = base_pair()

    result = compare(before, after)

    assert result.changes == ()
    assert result.added_devices == ()
    assert result.removed_devices == ()
    assert result.ambiguous_devices == ()
    assert result.unchanged_count > 0
    assert result.before_snapshot == "before"
    assert result.after_snapshot == "after"


def test_router_1_never_merged_with_router_10() -> None:
    before = model_with([router("Router-1")], [], snapshot="before")
    after = model_with([router("Router-10")], [], snapshot="after")

    result = compare(before, after)

    assert result.removed_devices == ("Router-1",)
    assert result.added_devices == ("Router-10",)
    assert result.ambiguous_devices == ()
    # No change may pair the two devices together.
    assert not any("->" in c.device for c in result.changes)
    assert {c.device for c in result.changes} == {"Router-1", "Router-10"}


# ---------------------------------------------------------------------------
# Ambiguity
# ---------------------------------------------------------------------------


def test_ambiguous_device_name_is_reported_and_not_diffed() -> None:
    # Two before-side devices share a hostname; the after-side name matches both.
    before = model_with(
        [
            router("R1", hostname="shared"),
            router("R2", hostname="shared"),
        ],
        [],
        snapshot="before",
    )
    after = model_with(
        [router("R7", hostname="shared", model="ISR4451")],
        [],
        snapshot="after",
    )

    result = compare(before, after)

    assert "R7" in result.ambiguous_devices
    # The ambiguous device is neither diffed nor declared added.
    assert result.added_devices == ()
    assert all(c.device != "R7" for c in result.changes)
    # Both before-side candidates are not silently reported as removed.
    assert result.removed_devices == ()


def test_duplicate_claims_are_reported_not_silently_resolved() -> None:
    # Two after-side devices both claim the single before-side device.
    before = model_with([device("core")], [], snapshot="before")
    after = model_with(
        [
            device("core"),
            router("Core", name="core", model="ISR4451"),
        ],
        [],
        snapshot="after",
    )

    result = compare(before, after)

    assert result.ambiguous_devices, "duplicate claims on one device must be reported"
    assert result.added_devices == ()
    assert result.removed_devices == ()
    assert result.changes == ()


def test_display_name_alias_matches_placeholder_keyed_device() -> None:
    # Before: device keyed by the raw placeholder. After: keyed by display name.
    mapping = {"pr3-rt_Display_name": "Node One Router"}
    before = model_with([device("pr3-rt", hostname="pr3-rt")], [], snapshot="before")
    before.placeholder_map = dict(mapping)
    after = model_with([device("Node One Router", hostname="Node One Router")], [], snapshot="after")
    after.placeholder_map = dict(mapping)

    result = compare(before, after)

    assert result.added_devices == ()
    assert result.removed_devices == ()
    assert result.ambiguous_devices == ()
    assert len(result.changes) == 1
    assert result.changes[0].field == "hostname"
    assert result.changes[0].kind is ChangeKind.MODIFIED
    assert result.changes[0].severity is Severity.INFO


def test_removed_device_is_not_expanded_into_interface_or_route_changes() -> None:
    before = model_with(
        [device("R1"), device("R9")],
        [iface("R9", "GigabitEthernet0/1", ipv4_address="10.9.9.9")],
        [RouteInfo(destination="10.9.0.0/16", next_hop="10.9.9.1", route_type="static", device="R9")],
        snapshot="before",
    )
    after = model_with([device("R1")], [], snapshot="after")

    result = compare(before, after)

    assert result.removed_devices == ("R9",)
    r9_changes = [c for c in result.changes if c.device == "R9"]
    assert len(r9_changes) == 1
    assert r9_changes[0].field == "device"
    assert r9_changes[0].severity is Severity.CRITICAL
    assert not any(c.field.startswith("route:") for c in result.changes)
