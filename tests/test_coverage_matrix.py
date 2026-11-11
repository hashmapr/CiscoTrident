"""Coverage matrix honesty.

The failure this guards against is claiming a protocol is "supported" because its
configuration text can be read. Each level must be earned, and a level that is
claimed must name the test that establishes it.
"""

from __future__ import annotations

import json

import pytest

from trident.deepcore.coverage import CoverageMatrix, Feature, Level


@pytest.fixture()
def matrix() -> CoverageMatrix:
    return CoverageMatrix()


def test_levels_are_ordered_and_distinct():
    assert Level.UNSUPPORTED < Level.PARSED < Level.MODELLED
    assert Level.MODELLED < Level.STATICALLY_VERIFIED < Level.SIMULATOR_TESTED


def test_a_feature_reports_its_highest_earned_level():
    feature = Feature(name="x", parsed=True, modelled=True)
    assert feature.level is Level.MODELLED


def test_parsing_alone_is_not_a_higher_level():
    feature = Feature(name="x", parsed=True)
    assert feature.level is Level.PARSED
    assert feature.level is not Level.MODELLED


def test_nothing_claimed_means_unsupported():
    assert Feature(name="x").level is Level.UNSUPPORTED


# ---------------------------------------------------------------------------
# Evidence requirements
# ---------------------------------------------------------------------------


def test_every_claimed_feature_names_its_evidence(matrix):
    """A level without a test is an assertion, not a measurement."""
    for feature in matrix.features:
        if feature.level is Level.UNSUPPORTED:
            continue
        assert feature.evidence, f"{feature.name} claims {feature.level.name} with no evidence"


def test_simulator_tested_features_name_a_live_test(matrix):
    for feature in matrix.features:
        if feature.simulator_tested:
            joined = " ".join(feature.evidence)
            assert any(
                marker in joined
                for marker in ("live", "simulator", "test_live_integration", "differential_live")
            ), f"{feature.name} claims simulator testing without a live test"


def test_an_unsupported_feature_claims_no_capability():
    feature = Feature(name="qos")
    assert not feature.parsed
    assert not feature.modelled
    assert feature.level is Level.UNSUPPORTED


# ---------------------------------------------------------------------------
# Honest specifics
# ---------------------------------------------------------------------------


def test_ospf_is_parsed_but_not_modelled(matrix):
    """Configured OSPF is not a formed adjacency, and the matrix says so."""
    ospf = matrix.get("ospf")
    assert ospf is not None
    assert ospf.parsed is True
    assert ospf.modelled is False
    assert ospf.level is Level.PARSED
    assert any("adjacency" in limitation for limitation in ospf.limitations)


def test_nat_and_stp_are_modelled_but_not_simulator_tested(matrix):
    """Both are now parsed and modelled, and neither claims a simulator test.

    The earlier form of this test asserted they were UNSUPPORTED, which was true
    when nothing parsed them. Typed parsers and reasoning modules now exist, so
    the honest claim moved to STATICALLY_VERIFIED. What must not move is the top
    level: no authorized lab carried NAT or STP root configuration, so neither
    may claim SIMULATOR_TESTED.
    """
    for name in ("nat", "stp"):
        feature = matrix.get(name)
        assert feature is not None
        assert feature.parsed is True, name
        assert feature.modelled is True, name
        assert feature.level is Level.STATICALLY_VERIFIED, name
        assert feature.simulator_tested is False, name
        assert feature.limitations


def test_acl_states_its_evaluation_limits(matrix):
    acl = matrix.get("acl")
    assert acl is not None
    assert acl.modelled is True
    assert any("denies" in limitation or "deny" in limitation for limitation in acl.limitations)


def test_ipv6_is_honestly_below_simulator_tested(matrix):
    """IPv6 is parsed and modelled, but no lab ran it with a populated table."""
    ipv6 = matrix.get("ipv6")
    assert ipv6 is not None
    assert ipv6.level is Level.STATICALLY_VERIFIED
    assert ipv6.simulator_tested is False
    assert ipv6.limitations


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_summary_counts_add_up(matrix):
    summary = matrix.summary()
    assert sum(summary["counts"].values()) == summary["total"] == len(matrix.features)
    assert len(summary["simulator_tested"]) == 2


def test_matrix_serialises_to_json(matrix):
    payload = matrix.as_dict()
    json.dumps(payload)
    assert payload["features"]
    for entry in payload["features"]:
        assert set(entry) >= {"name", "level", "parsed", "modelled", "limitations"}


def test_matrix_can_be_written_and_read_back(tmp_path, matrix):
    target = matrix.write(tmp_path / "coverage.json")
    data = json.loads(target.read_text())
    assert data["summary"]["total"] == len(matrix.features)
    assert data["features"][0]["name"] == matrix.features[0].name


def test_at_least_filtering(matrix):
    tested = matrix.at_least(Level.SIMULATOR_TESTED)
    assert "ipv4_addressing" in tested
    assert "qos" not in tested
    verified = matrix.at_least(Level.STATICALLY_VERIFIED)
    assert set(tested) <= set(verified)
