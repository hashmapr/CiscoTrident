"""Reproduction: ACL facts parsed from a real lab config, end to end.

No simulator needed. The input is the `show access-lists` / running-config text
captured from ISP A in the authorized CCNA Mega Lab (see
docs/oracle/evidence/differential_megalab.json), so the ACEs are real Cisco lines
with real wildcard masks, not a hand-drawn case.
"""

from __future__ import annotations

from trident.models import AclEntry, NetworkModel
from trident.normalization.configs import parse_running_config

# Verbatim from `show running-config` on ISP A, CCNA Mega Lab, PT 9.0.1.
REAL_CONFIG = """\
hostname ISP-A
!
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.0
 ip access-group 100 in
!
access-list 100 deny ip 10.0.0.0 0.255.255.255 any
access-list 100 deny ip 172.16.0.0 0.15.255.255 any
access-list 100 deny ip 192.168.0.0 0.0.255.255 any
access-list 100 permit ip any any
"""


def _parse():
    return parse_running_config(REAL_CONFIG.splitlines())


def test_wildcard_is_not_stored_as_a_destination():
    """`deny ip 10.0.0.0 0.255.255.255 any` has wildcard/32 as the mask.

    The ACE's destination is `any`. If the wildcard lands in the destination
    field, the rule's real destination is lost and later matching is wrong.
    """
    cfg = _parse()
    deny = [a for a in cfg.acls if a.action == "deny"]
    assert deny, "expected deny ACEs"
    for ace in deny:
        assert ace.destination != "0.255.255.255", (
            f"wildcard stored as destination for {ace.raw!r}: {ace.destination}"
        )


def test_acl_binding_to_interface_is_recorded():
    """The interface the ACL is applied to must survive into the model.

    `ip access-group 100 in` names an ACL and a direction on a real interface.
    `AclEntry.applied_interface` is what the reasoning layer compares against, so
    it must be populated at collection time or every bound deny is invisible.
    """
    from trident.normalization.devices import _collect_acls

    cfg = _parse()
    collected = _collect_acls({"engine_a": {"ISP-A": cfg}}, NetworkModel(), "block0")
    bound = [a for a in collected if a.acl_id == "100"]
    assert bound, "expected collected ACEs for ACL 100"
    assert any(a.applied_interface for a in bound), (
        "no collected ACE for ACL 100 carries an applied_interface; "
        f"interfaces parsed: {[i.name for i in cfg.interfaces.values()]}"
    )
    assert all(a.direction == "in" for a in bound if a.applied_interface)


def test_wildcard_deny_matches_a_real_source_address():
    """`10.0.0.0 0.255.255.255` covers all of 10/8, not the single host 10.0.0.0."""
    from trident.deepcore.nat import _acl_matches

    line = "deny ip 10.0.0.0 0.255.255.255 any"
    assert _acl_matches(line, "10.5.5.5") is True
    assert _acl_matches(line, "11.5.5.5") is False


def test_model_level_acl_verdict_denies_a_covered_source():
    """The reasoning layer must deny a source the real ACE covers."""
    from trident.deepcore.path import DeepCore

    model = NetworkModel(
        devices={},
        interfaces={},
        acls=[
            AclEntry(
                acl_id="100",
                acl_type="extended",
                action="deny",
                protocol="ip",
                source="10.0.0.0 0.255.255.255",
                destination="any",
                applied_interface="GigabitEthernet0/0",
                direction="in",
                raw="access-list 100 deny ip 10.0.0.0 0.255.255.255 any",
            )
        ],
    )
    core = DeepCore(model)
    verdict = core.acl_verdict(
        "ISP-A", "GigabitEthernet0/0", "8.8.8.8", source_address="10.5.5.5"
    )
    assert verdict == "deny", f"covered source 10.5.5.5 reported as {verdict!r}"


def test_a_source_outside_the_deny_is_not_denied():
    """The same ACE must not deny a source it does not cover.

    `deny ip 10.0.0.0 0.255.255.255 any` denies 10/8 as a source and nothing
    else. A destination-only reading reports every address as denied, because
    the destination operand is `any`.
    """
    from trident.deepcore.path import DeepCore

    model = NetworkModel(
        devices={},
        interfaces={},
        acls=[
            AclEntry(
                acl_id="100",
                acl_type="extended",
                action="deny",
                protocol="ip",
                source="10.0.0.0 0.255.255.255",
                destination="any",
                applied_interface="GigabitEthernet0/0",
                direction="in",
                raw="access-list 100 deny ip 10.0.0.0 0.255.255.255 any",
            )
        ],
    )
    verdict = DeepCore(model).acl_verdict(
        "ISP-A", "GigabitEthernet0/0", "8.8.8.8", source_address="192.168.1.5"
    )
    assert verdict == "permit", f"uncovered source reported as {verdict!r}"


def test_unknown_source_is_unknown_not_permit():
    """Without the source address the deny cannot be ruled out.

    Returning `permit` here would silently convert an unevaluated ACE into
    permission, which is how a blocked path reports as healthy.
    """
    from trident.deepcore.path import DeepCore

    model = NetworkModel(
        devices={},
        interfaces={},
        acls=[
            AclEntry(
                acl_id="100",
                acl_type="extended",
                action="deny",
                protocol="ip",
                source="10.0.0.0 0.255.255.255",
                destination="any",
                applied_interface="GigabitEthernet0/0",
                direction="in",
                raw="access-list 100 deny ip 10.0.0.0 0.255.255.255 any",
            )
        ],
    )
    verdict = DeepCore(model).acl_verdict("ISP-A", "GigabitEthernet0/0", "8.8.8.8")
    assert verdict == "unknown", f"unevaluated deny reported as {verdict!r}"
