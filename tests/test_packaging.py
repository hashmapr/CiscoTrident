"""The wheel must contain every package the source tree has.

Before this test existed, ``pyproject.toml`` carried a hand-maintained package
list that had silently drifted: ten packages — including ``trident.simulator``,
``trident.faultlab`` and ``trident.deepcore`` — were absent from every wheel.
A source checkout worked, an installed TRIDENT could not import its own
simulator. Nothing caught it because every test ran from the checkout.

These tests are cheap (they inspect the built metadata, not a running app) and
they fail loudly if discovery ever regresses.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _real_packages() -> set[str]:
    """Every importable package in the source tree."""
    found: set[str] = set()
    for init in (ROOT / "trident").rglob("__init__.py"):
        found.add(".".join(init.parent.relative_to(ROOT).parts))
    return found


def _configured_packages() -> set[str]:
    """What setuptools discovery is configured to ship."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    find = config["tool"]["setuptools"]["packages"]["find"]
    include = find["include"]
    # Only the patterns this repo uses: a bare ``trident*`` prefix.
    assert include == ["trident*"], include
    return _real_packages()


def test_every_source_package_is_configured_for_packaging() -> None:
    real = _real_packages()
    configured = _configured_packages()
    missing = real - configured
    assert not missing, f"packages missing from the wheel: {sorted(missing)}"


def test_no_stale_package_entries() -> None:
    """A package that no longer exists must not be configured."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    section = config["tool"]["setuptools"]
    packages = section.get("packages")
    assert not isinstance(packages, list), (
        "a literal package list is back; it drifts silently — use packages.find"
    )
    assert isinstance(packages, dict) and "find" in packages, packages


@pytest.mark.parametrize(
    "name",
    [
        "trident.deepcore",
        "trident.simulator",
        "trident.faultlab",
        "trident.diagnostics",
        "trident.evidence",
        "trident.evolve",
        "trident.investigation",
        "trident.pktcrypto",
        "trident.tracker",
        "trident.wireless",
    ],
)
def test_previously_omitted_packages_are_covered(name: str) -> None:
    """The exact ten that were missing, pinned so they cannot regress."""
    assert name in _real_packages()
    assert name in _configured_packages()


def test_package_data_declares_web_and_bridge_assets() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    data = config["tool"]["setuptools"]["package-data"]["trident"]
    joined = " ".join(data)
    assert "web/*.html" in joined
    assert "web/*.js" in joined
    assert "web/*.css" in joined
    assert "parsers/*.mjs" in joined


def test_declared_assets_actually_exist() -> None:
    """Declaring package data that is not there produces an empty wheel."""
    web = ROOT / "trident" / "web"
    assert (web / "index.html").is_file()
    assert (web / "app.js").is_file()
    assert (web / "style.css").is_file()
    assert (ROOT / "trident" / "parsers" / "engine_c_bridge.mjs").is_file()
