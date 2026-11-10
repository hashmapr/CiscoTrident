"""IPv6 reasoning: on-link determination, routing, and the forwarding gate.

IPv6 is not IPv4 with longer addresses. The differences these tests pin:

* `ipv6 unicast-routing` is a separate gate from holding an address.
* On-link determination uses configured prefixes, not a mask comparison.
* A link-local next hop is only meaningful with an outgoing interface.
* The same link-local on two interfaces is normal, not a duplicate.
"""

from __future__ import annotations

import pytest

from trident.deepcore.ipv6 import (
    Outcome,
    duplicate_addresses,
    is_link_local,
    on_link_interface,
    predict,
    problems,
)
from trident.deepcore.protocols import parse_protocols


def _config(*lines):
    return parse_protocols(list(lines)).ipv6


ROUTER = [
    "ipv6 unicast-routing",
    "interface GigabitEthernet0/0",
    " ipv6 address 2001:db8:1::1/64",
]


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("fe80::1", True),
        ("fe80::1/64", True),
        ("2001:db8::1", False),
        ("::1", False),
        ("not-an-address", False),
    ],
)
def test_link_local_detection(address, expected):
    assert is_link_local(address) is expected


# ---------------------------------------------------------------------------
# On-link determination
# ---------------------------------------------------------------------------


def test_a_destination_inside_a_configured_prefix_is_on_link():
    config = _config(*ROUTER)
    assert on_link_interface(config, "2001:db8:1::99") == "GigabitEthernet0/0"


def test_a_destination_outside_every_prefix_is_not_on_link():
    config = _config(*ROUTER)
    assert on_link_interface(config, "2001:db8:9::1") is None


def test_link_local_addresses_do_not_establish_on_link():
    """A link-local destination is not matched by a global prefix."""
    config = _config(*ROUTER)
    assert on_link_interface(config, "fe80::99") is None


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------


def test_an_on_link_destination_delivers():
    result = predict(_config(*ROUTER), "2001:db8:1::1", "2001:db8:1::99", device="R1")
    assert result.outcome is Outcome.DELIVERS
    assert result.steps[0].on_link is True
    # The neighbor exchange is runtime state and the caveat says so.
    assert any("neighbor discovery" in caveat.lower() for caveat in result.caveats)


def test_an_off_link_destination_without_a_route_drops():
    result = predict(_config(*ROUTER), "2001:db8:1::1", "2001:db8:9::1", device="R1")
    assert result.outcome is Outcome.DROPS
    assert result.failure_point == "R1"
    assert any("no IPv6 route" in step.detail for step in result.steps)


def test_an_off_link_destination_with_a_default_route_delivers():
    config = _config(*ROUTER, "ipv6 route ::/0 2001:db8:1::ff")
    result = predict(config, "2001:db8:1::1", "2001:db8:9::1", device="R1")
    assert result.outcome is Outcome.DELIVERS
    assert result.next_hop == "2001:db8:1::ff"


def test_addresses_without_unicast_routing_do_not_forward():
    """The common fault: IPv6 configured but forwarding never enabled."""
    config = _config(
        "interface GigabitEthernet0/0", " ipv6 address 2001:db8:1::1/64"
    )
    result = predict(config, "2001:db8:1::1", "2001:db8:9::1", device="R1")
    assert result.outcome is Outcome.FORWARDING_DISABLED
    assert any("unicast-routing" in caveat for caveat in result.caveats)


def test_a_device_with_no_ipv6_is_undecided():
    result = predict(_config(), "2001:db8:1::1", "2001:db8:9::1", device="R1")
    assert result.outcome is Outcome.UNDECIDED


def test_a_link_local_next_hop_is_undecided_not_guessed():
    """A link-local next hop needs its outgoing interface to mean anything."""
    config = _config(*ROUTER, "ipv6 route 2001:db8:9::/64 fe80::ff")
    result = predict(config, "2001:db8:1::1", "2001:db8:9::1", device="R1")
    assert result.outcome is Outcome.UNDECIDED
    assert any("link-local" in caveat for caveat in result.caveats)


def test_the_longest_prefix_route_wins():
    config = _config(
        *ROUTER,
        "ipv6 route ::/0 2001:db8:1::ff",
        "ipv6 route 2001:db8:9::/64 2001:db8:1::99",
    )
    result = predict(config, "2001:db8:1::1", "2001:db8:9::1", device="R1")
    assert result.next_hop == "2001:db8:1::99"


def test_a_return_path_caveat_is_stated():
    config = _config(*ROUTER, "ipv6 route ::/0 2001:db8:1::ff")
    result = predict(config, "2001:db8:1::1", "2001:db8:9::1", device="R1")
    assert any("route back" in caveat for caveat in result.caveats)


# ---------------------------------------------------------------------------
# Duplicates and configuration problems
# ---------------------------------------------------------------------------


def test_two_interfaces_with_the_same_global_address_is_a_conflict():
    config = _config(
        "interface Gi0/0", " ipv6 address 2001:db8:1::1/64",
        "interface Gi0/1", " ipv6 address 2001:db8:1::1/64",
    )
    duplicates = duplicate_addresses(config)
    assert duplicates
    assert len(duplicates[0][1]) == 2


def test_the_same_link_local_on_two_interfaces_is_normal():
    """Link-local scope is per-link, so this is not a conflict."""
    config = _config(
        "interface Gi0/0", " ipv6 address fe80::1 link-local",
        "interface Gi0/1", " ipv6 address fe80::1 link-local",
    )
    assert duplicate_addresses(config) == []


def test_an_address_without_unicast_routing_is_reported():
    config = _config("interface Gi0/0", " ipv6 address 2001:db8:1::1/64")
    reported = problems(config)
    assert any("unicast-routing" in problem for problem in reported)


def test_a_healthy_ipv6_config_reports_no_problems():
    assert problems(_config(*ROUTER)) == []


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def test_prediction_serialises():
    import json

    json.dumps(
        predict(_config(*ROUTER), "2001:db8:1::1", "2001:db8:1::99", device="R1").as_dict()
    )


def test_a_prediction_is_never_an_observation():
    payload = predict(
        _config(*ROUTER), "2001:db8:1::1", "2001:db8:1::99", device="R1"
    ).as_dict()
    assert "observed" not in payload
    assert payload["outcome"] in {"DELIVERS", "DROPS", "UNDECIDED", "FORWARDING_DISABLED"}
