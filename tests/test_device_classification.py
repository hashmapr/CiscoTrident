"""Device classification: the directive's reliability order.

1. Explicit structural type.
2. Known hardware-model mapping.
3. Conservative inference.
4. Unknown.

Packet Tracer files record no structural device type — the `<TYPE>` element carries
only a model — so an unmatched model is genuinely unknown. It must say so rather
than being filed under a plausible guess.
"""

from __future__ import annotations

import pytest

from trident.deepcore.analyze import _device_kind
from trident.models import DeviceInfo


def _device(model=None, kind=None):
    return DeviceInfo(
        id="x", name="x", hostname="x", device_type=kind, model=model, configuration=[]
    )


# ---------------------------------------------------------------------------
# Model mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("2911", "Router"),
        ("2901", "Router"),
        ("ISR4331", "Router"),
        ("2960-24TT", "Switch"),
        ("2950-24", "Switch"),
        ("3560-24PS", "Multilayer Switch"),
        ("PC-PT", "PC"),
        ("Laptop-PT", "PC"),
        ("Server-PT", "Server"),
        ("ASA-5505", "Firewall"),
        ("WRT300N", "Wireless Router"),
        ("AccessPoint-PT", "Access Point"),
    ],
)
def test_known_models_map_to_their_family(model, expected):
    assert _device_kind(_device(model=model)) == expected


def test_longer_model_keys_win():
    """`2960-24TT` must not be matched by a shorter, looser key."""
    assert _device_kind(_device(model="2960-24TT")) == "Switch"


# ---------------------------------------------------------------------------
# Structural type beats the model
# ---------------------------------------------------------------------------


def test_an_explicit_structural_type_is_used_first():
    """A future parser that populates device_type takes precedence."""
    device = _device(model="mystery-box", kind="firewall")
    assert _device_kind(device) == "Firewall"


def test_a_structural_type_wins_over_a_contradicting_model():
    device = _device(model="2911", kind="switch")
    assert _device_kind(device) == "Switch"


# ---------------------------------------------------------------------------
# Conservative inference
# ---------------------------------------------------------------------------


def test_an_unrecognised_model_naming_a_router_is_inferred():
    assert _device_kind(_device(model="custom-router-x")) == "Router"


def test_an_unrecognised_model_naming_a_switch_is_inferred():
    assert _device_kind(_device(model="mystery-switch-9000")) == "Switch"


# ---------------------------------------------------------------------------
# Unknown is honest
# ---------------------------------------------------------------------------


def test_an_unmatched_model_is_unknown_and_shows_the_model():
    kind = _device_kind(_device(model="zzz-unknown-thing"))
    assert kind.startswith("Unknown")
    assert "zzz-unknown-thing" in kind


def test_no_model_and_no_type_is_unknown():
    assert _device_kind(_device()) == "Unknown"


def test_unknown_is_never_guessed_into_a_family():
    """The failure this guards against: filing an unknown device under a
    plausible family because the name looked router-ish."""
    for model in ("gizmo", "foo-123", "PT-99", "xyz"):
        kind = _device_kind(_device(model=model))
        assert kind.startswith("Unknown"), (model, kind)


# ---------------------------------------------------------------------------
# Families that must be distinguishable
# ---------------------------------------------------------------------------


def test_router_and_multilayer_switch_are_distinct():
    assert _device_kind(_device(model="2911")) != _device_kind(_device(model="3560-24PS"))


def test_pc_and_server_are_distinct():
    assert _device_kind(_device(model="PC-PT")) != _device_kind(_device(model="Server-PT"))


def test_firewall_and_router_are_distinct():
    assert _device_kind(_device(model="ASA-5505")) != _device_kind(_device(model="2911"))
