"""NAT and PAT translation reasoning.

The distinction that matters: this module predicts what the *rules* would do to a
matching packet. It never claims a flow was actually translated — that needs
`show ip nat translations`. Dynamic PAT port assignments are never guessed,
because they depend on runtime allocation order.
"""

from __future__ import annotations

import pytest

from trident.deepcore.nat import (
    Outcome,
    role_problems,
    translate_outbound,
)
from trident.deepcore.protocols import parse_protocols


def _nat(*lines):
    return parse_protocols(list(lines)).nat


BASIC = [
    "interface GigabitEthernet0/0",
    " ip nat outside",
    "interface GigabitEthernet0/1",
    " ip nat inside",
]


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


def test_rules_without_an_inside_interface_do_nothing():
    nat = _nat("interface Gi0/0", " ip nat outside", "ip nat inside source static 10.0.0.5 203.0.113.5")
    result = translate_outbound(nat, "10.0.0.5", "8.8.8.8")
    assert result.outcome is Outcome.MISSING_ROLE
    assert any("inside" in problem for problem in result.problems)


def test_rules_without_an_outside_interface_do_nothing():
    nat = _nat("interface Gi0/1", " ip nat inside", "ip nat inside source static 10.0.0.5 203.0.113.5")
    result = translate_outbound(nat, "10.0.0.5", "8.8.8.8")
    assert result.outcome is Outcome.MISSING_ROLE


def test_an_interface_marked_both_roles_is_reported():
    nat = _nat("interface Gi0/0", " ip nat outside", " ip nat inside")
    assert any("both inside and outside" in problem for problem in role_problems(nat))


def test_no_nat_configuration_means_no_translation():
    nat = _nat()
    result = translate_outbound(nat, "10.0.0.5", "8.8.8.8")
    assert result.outcome is Outcome.UNTRANSLATED
    assert result.translated_source == "10.0.0.5"


# ---------------------------------------------------------------------------
# Static NAT
# ---------------------------------------------------------------------------


def test_a_static_rule_translates_the_source():
    nat = _nat(*BASIC, "ip nat inside source static 10.0.0.5 203.0.113.5")
    result = translate_outbound(nat, "10.0.0.5", "8.8.8.8")
    assert result.outcome is Outcome.TRANSLATED
    assert result.translated_source == "203.0.113.5"
    assert result.translated_destination == "8.8.8.8"
    assert result.source_changed is True


def test_an_unmatched_source_is_left_alone():
    nat = _nat(*BASIC, "ip nat inside source static 10.0.0.5 203.0.113.5")
    result = translate_outbound(nat, "10.0.0.9", "8.8.8.8")
    assert result.outcome is Outcome.UNTRANSLATED
    assert result.source_changed is False


# ---------------------------------------------------------------------------
# PAT
# ---------------------------------------------------------------------------


PAT = [*BASIC, "ip nat inside source list 10 interface GigabitEthernet0/0 overload"]
ACL = {"10": ["permit ip 10.0.0.0 0.0.0.255 any"]}


def test_pat_translates_to_the_outside_address():
    result = translate_outbound(
        _nat(*PAT), "10.0.0.9", "8.8.8.8", ACL, egress_interface="203.0.113.2"
    )
    assert result.outcome is Outcome.TRANSLATED
    assert result.translated_source == "203.0.113.2"
    assert result.overloaded is True


def test_pat_never_invents_the_translated_port():
    result = translate_outbound(
        _nat(*PAT), "10.0.0.9", "8.8.8.8", ACL, egress_interface="203.0.113.2"
    )
    assert result.port_note
    assert "cannot be predicted" in result.port_note


def test_pat_without_a_known_address_is_undecided():
    """The interface name is not an address, so nothing is invented."""
    result = translate_outbound(_nat(*PAT), "10.0.0.9", "8.8.8.8", ACL)
    assert result.outcome is Outcome.UNDECIDED
    assert any("not an address" in problem for problem in result.problems)


def test_a_dynamic_rule_without_its_acl_body_is_undecided():
    result = translate_outbound(_nat(*PAT), "10.0.0.9", "8.8.8.8")
    assert result.outcome is Outcome.UNDECIDED
    assert any("ACL 10" in problem for problem in result.problems)


def test_a_source_outside_the_acl_is_not_translated():
    result = translate_outbound(
        _nat(*PAT), "192.168.9.9", "8.8.8.8", ACL, egress_interface="203.0.113.2"
    )
    assert result.outcome is Outcome.UNTRANSLATED


# ---------------------------------------------------------------------------
# ACL matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "address", "expected"),
    [
        ("permit ip 10.0.0.0 0.0.0.255 any", "10.0.0.9", True),
        ("permit ip 10.0.0.0 0.0.0.255 any", "10.0.1.9", False),
        ("permit ip any any", "8.8.8.8", True),
        ("permit ip host 10.0.0.5 any", "10.0.0.5", True),
        ("permit ip host 10.0.0.5 any", "10.0.0.6", False),
        ("deny ip any any", "8.8.8.8", True),
        ("remark something", "8.8.8.8", False),
    ],
)
def test_acl_matching(line, address, expected):
    from trident.deepcore.nat import _acl_matches

    assert _acl_matches(line, address) is expected


# ---------------------------------------------------------------------------
# Pools
# ---------------------------------------------------------------------------


def test_a_pool_reference_to_an_undefined_pool_is_misconfigured():
    nat = _nat(*BASIC, "ip nat inside source list 10 pool MISSING")
    result = translate_outbound(nat, "10.0.0.9", "8.8.8.8", ACL)
    assert result.outcome is Outcome.MISCONFIGURED
    assert any("not defined" in problem for problem in result.problems)


def test_a_defined_pool_is_reported_with_its_range():
    nat = _nat(
        *BASIC,
        "ip nat pool PUBLIC 203.0.113.1 203.0.113.10 netmask 255.255.255.0",
        "ip nat inside source list 10 pool PUBLIC",
    )
    result = translate_outbound(nat, "10.0.0.9", "8.8.8.8", ACL)
    assert result.outcome is Outcome.TRANSLATED
    assert result.translated_source == "203.0.113.1"
    # The allocation order is runtime state, which the caveat says.
    assert any("allocation order" in caveat for caveat in result.caveats)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def test_translation_serialises():
    import json

    json.dumps(
        translate_outbound(_nat(*BASIC, "ip nat inside source static 10.0.0.5 203.0.113.5"),
                           "10.0.0.5", "8.8.8.8").as_dict()
    )


def test_no_prediction_is_ever_called_an_observation():
    result = translate_outbound(
        _nat(*BASIC, "ip nat inside source static 10.0.0.5 203.0.113.5"), "10.0.0.5", "8.8.8.8"
    )
    payload = result.as_dict()
    assert "observed" not in payload
    assert payload["outcome"] == "TRANSLATED"
