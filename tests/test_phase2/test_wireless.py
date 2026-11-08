"""Tests for wireless, endpoint and service configuration analysis.

Coverage follows the honesty contract, not code paths:

* a WLC/AP with two WPA2 SSIDs is CONFIGURED and both SSIDs are parsed
* an SSID with no security directive is UNKNOWN, never OPEN
* an AP with no configuration is UNSUPPORTED, never MISSING or CONFIGURED
* an endpoint with a static address, gateway and DNS is parsed
* a router's DHCP server pool is detected as a pool
* ``ip helper-address`` is a relay and never a DHCP server pool
* the public surface exposes no connectivity/reachability verdict
* every CONFIGURED and MISSING result carries non-empty evidence
"""

from __future__ import annotations

import dataclasses
import inspect

import pytest

from trident import wireless
from trident.models import DeviceInfo, NetworkModel, Observation, Provenance
from trident.wireless import (
    SecurityMode,
    WirelessStatus,
    analyse_dhcp_relays,
    analyse_dns_resolvers,
    analyse_endpoints,
    analyse_services,
    analyse_wireless,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def device(name: str, config: list[str], category: str | None = "access point") -> DeviceInfo:
    return DeviceInfo(
        id=name,
        name=name,
        hostname=name,
        device_type=category,
        configuration=list(config),
    )


def model_of(*devices: DeviceInfo, observations: list[Observation] | None = None) -> NetworkModel:
    return NetworkModel(
        devices={dev.name: dev for dev in devices},
        observations=list(observations or []),
        snapshot_id="wireless-test",
    )


def wireless_one(model: NetworkModel, name: str):
    records = [record for record in analyse_wireless(model) if record.device == name]
    assert len(records) == 1, f"expected exactly one wireless record for {name}"
    return records[0]


def obs(entity_id: str, field: str, value: str) -> Observation:
    return Observation(
        field=field,
        entity_type="device",
        entity_id=entity_id,
        value=value,
        provenance=Provenance(engine="engine_a", extraction_path="raw-xml-walk:endhost-xml"),
        raw_evidence=f"{field}={value}",
    )


# --- configurations --------------------------------------------------------

WLC_TWO_SSIDS = [
    "hostname WLC1",
    "!",
    "wlan CORP 1 CORP",
    " security wpa akm psk",
    " security wpa wpa2 ciphers aes",
    " no shutdown",
    "!",
    "wlan GUEST 2 GUEST",
    " security wpa akm psk",
    " security wpa wpa2 ciphers aes",
    " no shutdown",
    "!",
    "interface GigabitEthernet0/0",
    " ip address 10.0.0.10 255.255.255.0",
    "!",
]

AP_TWO_SSIDS_WPA2 = [
    "hostname AP1",
    "!",
    "dot11 ssid CORP-NET",
    " authentication open",
    " authentication key-management wpa version 2",
    " wpa-psk ascii 7 045802150C2E1D1D",
    "!",
    "dot11 ssid GUEST-NET",
    " authentication open",
    " authentication key-management wpa version 2",
    " wpa-psk ascii 7 110A1016141D",
    "!",
    "interface Dot11Radio0",
    " ssid CORP-NET",
    " ssid GUEST-NET",
    " no shutdown",
    "!",
]

AP_SSID_NO_SECURITY = [
    "hostname AP2",
    "!",
    "dot11 ssid OPENISH",
    " guest-mode",
    "!",
    "interface Dot11Radio0",
    " ssid OPENISH",
    " no shutdown",
    "!",
]

AP_WITH_RADIO_NO_SSID = [
    "hostname AP3",
    "!",
    "interface Dot11Radio0",
    " channel 6",
    " no shutdown",
    "!",
]

ROUTER_DHCP_SERVER = [
    "hostname R1",
    "!",
    "service dhcp",
    "!",
    "ip dhcp pool LAN",
    " network 192.168.10.0 255.255.255.0",
    " default-router 192.168.10.1",
    " dns-server 8.8.8.8 1.1.1.1",
    " lease 0 12",
    "!",
    "interface GigabitEthernet0/0",
    " ip address 192.168.10.1 255.255.255.0",
    " no shutdown",
    "!",
]

ROUTER_DHCP_RELAY = [
    "hostname R2",
    "!",
    "interface GigabitEthernet0/1",
    " ip address 192.168.20.1 255.255.255.0",
    " ip helper-address 10.10.10.5",
    " no shutdown",
    "!",
]

PC_STATIC = [
    "hostname PC1",
    "!",
    "interface FastEthernet0",
    " ip address 192.168.10.50 255.255.255.0",
    " ip default-gateway 192.168.10.1",
    " ip name-server 8.8.8.8",
    " no shutdown",
    "!",
]


# ---------------------------------------------------------------------------
# wireless: configured
# ---------------------------------------------------------------------------


def test_wlc_two_ssids_wpa2_is_configured() -> None:
    model = model_of(device("WLC1", WLC_TWO_SSIDS, category="wireless lan controller"))

    record = wireless_one(model, "WLC1")

    assert record.status is WirelessStatus.CONFIGURED
    assert record.is_controller is True
    assert [ssid.ssid for ssid in record.ssids] == ["CORP", "GUEST"]
    assert all(ssid.security_mode is SecurityMode.WPA2 for ssid in record.ssids)


def test_ap_two_ssids_wpa2_is_configured_with_psk_redacted() -> None:
    model = model_of(device("AP1", AP_TWO_SSIDS_WPA2))

    record = wireless_one(model, "AP1")

    assert record.status is WirelessStatus.CONFIGURED
    assert record.radios_enabled == 1
    assert [ssid.ssid for ssid in record.ssids] == ["CORP-NET", "GUEST-NET"]
    assert all(ssid.security_mode is SecurityMode.WPA2 for ssid in record.ssids)
    assert all(ssid.psk_configured for ssid in record.ssids)
    # The raw key must never be echoed into evidence.
    joined = " ".join(entry for ssid in record.ssids for entry in ssid.evidence)
    assert "045802150C2E1D1D" not in joined
    assert "110A1016141D" not in joined


# ---------------------------------------------------------------------------
# wireless: unknown security, silence
# ---------------------------------------------------------------------------


def test_ssid_without_security_directive_is_unknown_not_open() -> None:
    model = model_of(device("AP2", AP_SSID_NO_SECURITY))

    record = wireless_one(model, "AP2")

    assert len(record.ssids) == 1
    ssid = record.ssids[0]
    assert ssid.security_mode is SecurityMode.UNKNOWN
    assert ssid.security_mode is not SecurityMode.OPEN
    # A device whose only SSID is UNKNOWN is PARTIAL, never CONFIGURED.
    assert record.status is WirelessStatus.PARTIAL
    assert any("security mode is not stated" in entry for entry in ssid.evidence)


def test_ssid_unknown_evidence_has_no_cited_security_line() -> None:
    model = model_of(device("AP2", AP_SSID_NO_SECURITY))

    ssid = wireless_one(model, "AP2").ssids[0]

    assert all(
        "security mode is not stated" in entry or entry.startswith("running-config line")
        for entry in ssid.evidence
    )


# ---------------------------------------------------------------------------
# wireless: unsupported vs missing
# ---------------------------------------------------------------------------


def test_ap_with_no_configuration_is_unsupported() -> None:
    model = model_of(device("AP-EMPTY", []))

    record = wireless_one(model, "AP-EMPTY")

    assert record.status is WirelessStatus.UNSUPPORTED
    assert record.ssids == ()
    assert record.radios_enabled == 0
    assert record.evidence and record.evidence[0].startswith("not observable:")
    assert record.status is not WirelessStatus.MISSING
    assert record.status is not WirelessStatus.CONFIGURED


def test_ap_with_config_but_no_wireless_lines_is_missing() -> None:
    model = model_of(device("AP-EMPTY", ["hostname AP-EMPTY", "!"]), )

    record = wireless_one(model, "AP-EMPTY")

    assert record.status is WirelessStatus.MISSING
    assert record.evidence and record.evidence[0].startswith("not present:")


def test_router_with_no_wireless_lines_is_missing_by_category() -> None:
    model = model_of(device("R1", ROUTER_DHCP_SERVER, category="router"))

    record = wireless_one(model, "R1")

    assert record.status is WirelessStatus.MISSING
    assert "router" in record.evidence[0]


def test_radio_without_ssid_is_partial() -> None:
    model = model_of(device("AP3", AP_WITH_RADIO_NO_SSID))

    record = wireless_one(model, "AP3")

    assert record.radios_enabled == 1
    assert record.ssids == ()
    assert record.status is WirelessStatus.PARTIAL


def test_wireless_status_rejects_missing_with_ssids() -> None:
    from trident.wireless import SsidConfig, WirelessDevice

    with pytest.raises(ValueError):
        WirelessDevice(
            device="X",
            is_controller=False,
            ssids=(
                SsidConfig(
                    ssid="A",
                    security_mode=SecurityMode.WPA2,
                    psk_configured=False,
                    evidence=("running-config line 1: dot11 ssid A",),
                ),
            ),
            radios_enabled=0,
            status=WirelessStatus.MISSING,
            evidence=("not present: anything",),
        )


def test_wireless_status_rejects_configured_with_unknown_ssid() -> None:
    from trident.wireless import SsidConfig, WirelessDevice

    with pytest.raises(ValueError):
        WirelessDevice(
            device="X",
            is_controller=True,
            ssids=(
                SsidConfig(
                    ssid="A",
                    security_mode=SecurityMode.UNKNOWN,
                    psk_configured=False,
                    evidence=("running-config line 1: dot11 ssid A",),
                ),
            ),
            radios_enabled=0,
            status=WirelessStatus.CONFIGURED,
            evidence=("running-config line 1: dot11 ssid A",),
        )


def test_security_mode_requires_a_cited_line_or_is_unknown() -> None:
    from trident.wireless import SsidConfig

    with pytest.raises(ValueError):
        SsidConfig(
            ssid="A",
            security_mode=SecurityMode.WPA2,
            psk_configured=False,
            evidence=("not present: anything",),
        )


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------


def test_endpoint_static_ip_gateway_dns_parsed() -> None:
    model = model_of(device("PC1", PC_STATIC, category="pc"))

    endpoints = analyse_endpoints(model)

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.kind == "pc"
    assert endpoint.ipv4 == "192.168.10.50"
    assert endpoint.mask == "255.255.255.0"
    assert endpoint.gateway == "192.168.10.1"
    assert endpoint.dns == ("8.8.8.8",)
    assert endpoint.dhcp_enabled is False
    assert endpoint.evidence


def test_endpoint_from_observations_when_config_is_absent() -> None:
    model = model_of(
        device("LAPTOP1", [], category="laptop"),
        observations=[
            obs("LAPTOP1", "endhost_ip", "10.5.5.20"),
            obs("LAPTOP1", "endhost_gateway", "10.5.5.1"),
            obs("LAPTOP1", "endhost_dns", "8.8.8.8,1.1.1.1"),
        ],
    )

    endpoints = analyse_endpoints(model)

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.kind == "laptop"
    assert endpoint.ipv4 == "10.5.5.20"
    assert endpoint.gateway == "10.5.5.1"
    assert endpoint.dns == ("8.8.8.8", "1.1.1.1")
    # Silence about the address method is None, never assumed static.
    assert endpoint.dhcp_enabled is None


def test_laptop_with_dhcp_directive_sets_true() -> None:
    model = model_of(
        device(
            "LAPTOP2",
            [
                "hostname LAPTOP2",
                "!",
                "interface FastEthernet0",
                " ip address dhcp",
                " no shutdown",
                "!",
            ],
            category="laptop",
        )
    )

    endpoint = analyse_endpoints(model)[0]

    assert endpoint.dhcp_enabled is True
    assert any("dhcp" in entry.lower() for entry in endpoint.evidence)


def test_router_is_not_reported_as_endpoint() -> None:
    model = model_of(device("R1", ROUTER_DHCP_SERVER, category="router"))

    assert analyse_endpoints(model) == ()


# ---------------------------------------------------------------------------
# services: DHCP server vs relay
# ---------------------------------------------------------------------------


def test_dhcp_server_pool_detected_on_router() -> None:
    model = model_of(device("R1", ROUTER_DHCP_SERVER, category="router"))

    dhcp = [record for record in analyse_services(model) if record.service == "dhcp"]

    assert len(dhcp) == 1
    record = dhcp[0]
    assert record.enabled is True
    assert len(record.pools) == 1
    assert record.pools[0]["name"] == "LAN"
    assert record.pools[0]["network"] == "192.168.10.0"
    assert record.pools[0]["mask"] == "255.255.255.0"
    assert record.pools[0]["default_router"] == "192.168.10.1"
    assert record.evidence


def test_helper_address_is_relay_not_server_pool() -> None:
    model = model_of(device("R2", ROUTER_DHCP_RELAY, category="router"))

    dhcp_records = [r for r in analyse_services(model) if r.service == "dhcp"]
    relays = analyse_dhcp_relays(model)

    # No DHCP server pool is invented from a relay line.
    assert dhcp_records == []
    assert len(relays) == 1
    relay = relays[0]
    assert relay.device == "R2"
    assert relay.interface == "GigabitEthernet0/1"
    assert relay.server == "10.10.10.5"
    assert any("helper-address" in entry for entry in relay.evidence)
    assert all(not record.pools for record in analyse_services(model))


def test_relay_and_pool_on_same_device_stay_distinct() -> None:
    config = [
        "hostname R3",
        "!",
        "ip dhcp pool LAN",
        " network 192.168.30.0 255.255.255.0",
        " default-router 192.168.30.1",
        "!",
        "interface GigabitEthernet0/1",
        " ip address 192.168.40.1 255.255.255.0",
        " ip helper-address 10.10.10.9",
        " no shutdown",
        "!",
    ]
    model = model_of(device("R3", config, category="router"))

    dhcp = [r for r in analyse_services(model) if r.service == "dhcp"]
    relays = analyse_dhcp_relays(model)

    assert len(dhcp) == 1
    assert [pool["name"] for pool in dhcp[0].pools] == ["LAN"]
    assert len(relays) == 1
    assert relays[0].server == "10.10.10.9"
    assert "10.10.10.9" not in {pool.get("default_router") for pool in dhcp[0].pools}


def test_no_service_dhcp_records_disabled() -> None:
    config = [
        "hostname R4",
        "!",
        "no service dhcp",
        "!",
    ]
    model = model_of(device("R4", config, category="router"))

    dhcp = [r for r in analyse_services(model) if r.service == "dhcp"]

    assert len(dhcp) == 1
    assert dhcp[0].enabled is False
    assert dhcp[0].pools == ()


# ---------------------------------------------------------------------------
# DNS: resolver vs server
# ---------------------------------------------------------------------------


def test_name_server_is_resolver_not_dns_service() -> None:
    config = [
        "hostname R5",
        "!",
        "ip name-server 8.8.8.8",
        "!",
    ]
    model = model_of(device("R5", config, category="router"))

    resolvers = analyse_dns_resolvers(model)
    dns_services = [r for r in analyse_services(model) if r.service == "dns"]

    assert len(resolvers) == 1
    assert resolvers[0].servers == ("8.8.8.8",)
    assert dns_services == []


def test_ip_dns_server_is_dns_service_not_resolver() -> None:
    config = [
        "hostname R6",
        "!",
        "ip dns server",
        "!",
    ]
    model = model_of(device("R6", config, category="router"))

    dns_services = [r for r in analyse_services(model) if r.service == "dns"]

    assert len(dns_services) == 1
    assert dns_services[0].enabled is True
    assert analyse_dns_resolvers(model) == ()


# ---------------------------------------------------------------------------
# honesty: no connectivity verdict on the public surface
# ---------------------------------------------------------------------------

_FORBIDDEN = (
    "connected",
    "connectivity",
    "reachable",
    "reachability",
    "online",
    "associated",
    "association",
    "leased",
    "lease_acquired",
    "ping",
    "transmit",
)


def test_public_api_exposes_no_connectivity_verdict() -> None:
    """The public surface must not name a connectivity/reachability verdict."""
    public = getattr(wireless, "__all__", [])
    assert public, "the package must declare __all__"

    for name in public:
        lowered = name.lower()
        assert not any(word in lowered for word in _FORBIDDEN), (
            f"public name {name!r} suggests a connectivity verdict"
        )
        attribute = getattr(wireless, name)
        if inspect.isfunction(attribute):
            signature = inspect.signature(attribute)
            for parameter in signature.parameters.values():
                assert not any(word in parameter.name.lower() for word in _FORBIDDEN)


def test_result_dataclasses_carry_no_connectivity_field() -> None:
    for name in wireless.__all__:
        attribute = getattr(wireless, name)
        if not (inspect.isclass(attribute) and dataclasses.is_dataclass(attribute)):
            continue
        for field_info in dataclasses.fields(attribute):
            assert not any(word in field_info.name.lower() for word in _FORBIDDEN), (
                f"{name}.{field_info.name} suggests a connectivity verdict"
            )


def test_module_docstring_states_the_rule() -> None:
    assert "Matching configuration is NOT connectivity" in wireless.__doc__


# ---------------------------------------------------------------------------
# evidence invariants
# ---------------------------------------------------------------------------


def _all_models() -> list[NetworkModel]:
    return [
        model_of(device("WLC1", WLC_TWO_SSIDS, category="wireless lan controller")),
        model_of(device("AP1", AP_TWO_SSIDS_WPA2)),
        model_of(device("AP2", AP_SSID_NO_SECURITY)),
        model_of(device("AP-EMPTY", [])),
        model_of(device("R1", ROUTER_DHCP_SERVER, category="router")),
        model_of(device("R2", ROUTER_DHCP_RELAY, category="router")),
    ]


@pytest.mark.parametrize("model", _all_models())
def test_every_configured_or_missing_result_has_evidence(model: NetworkModel) -> None:
    for record in analyse_wireless(model):
        if record.status in {WirelessStatus.CONFIGURED, WirelessStatus.MISSING}:
            assert record.evidence, f"{record.device} ({record.status}) has no evidence"
            assert all(entry.strip() for entry in record.evidence)
        for ssid in record.ssids:
            assert ssid.evidence, f"SSID {ssid.ssid} has no evidence"


@pytest.mark.parametrize("model", _all_models())
def test_every_service_and_endpoint_result_has_evidence(model: NetworkModel) -> None:
    for service in analyse_services(model):
        assert service.evidence
    for endpoint in analyse_endpoints(model):
        assert endpoint.evidence
    for relay in analyse_dhcp_relays(model):
        assert relay.evidence
    for resolver in analyse_dns_resolvers(model):
        assert resolver.evidence


def test_results_are_deterministic_and_sorted() -> None:
    model = model_of(
        device("AP1", AP_TWO_SSIDS_WPA2),
        device("AP2", AP_SSID_NO_SECURITY),
        device("R2", ROUTER_DHCP_RELAY, category="router"),
    )

    first = analyse_wireless(model)
    second = analyse_wireless(model)

    assert [record.device for record in first] == ["AP1", "AP2", "R2"]
    assert first == second
