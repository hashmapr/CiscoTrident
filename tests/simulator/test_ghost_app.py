"""Background-agent ("ghost") Packet Tracer copy.

The stock bundle registers a Dock icon and takes focus when it opens a file.
Unattended operation needs neither, so a separate copy is built with
``LSUIElement`` set. These tests check the copy is well-formed and that the
original installation is never touched.
"""

from __future__ import annotations

import plistlib

import pytest

from trident.simulator.backends import find_ghost_app, find_packet_tracer, ghost_preferred
from trident.simulator.ghost import GhostError, build, remove


def test_refuses_a_non_bundle(tmp_path):
    with pytest.raises(GhostError, match="not a usable Packet Tracer bundle"):
        build(tmp_path / "nothing", tmp_path / "ghost")


def test_refuses_to_overwrite_an_unrelated_directory(tmp_path):
    fake_source = tmp_path / "src" / "Cisco Packet Tracer 9.0.1.app"
    (fake_source / "Contents" / "MacOS").mkdir(parents=True)
    (fake_source / "Contents" / "MacOS" / "PacketTracer").write_text("#!/bin/sh\n")
    ghost_dir = tmp_path / "ghost"
    (ghost_dir / "PTGhost.app").mkdir(parents=True)
    with pytest.raises(GhostError, match="pass force=True"):
        build(fake_source, ghost_dir)


@pytest.mark.skipif(
    __import__("trident.simulator.backends", fromlist=["find_packet_tracer"]).find_packet_tracer()
    is None,
    reason="Packet Tracer is not installed",
)
def test_build_creates_a_background_agent(tmp_path):
    source = find_packet_tracer()
    if source is None or "PTGhost" in str(source):
        pytest.skip("no stock installation to copy")
    ghost = build(source, tmp_path)
    assert ghost.executable.is_file()
    with open(ghost.path / "Contents" / "Info.plist", "rb") as handle:
        assert plistlib.load(handle).get("LSUIElement") is True
    assert ghost.version != ""


@pytest.mark.skipif(
    __import__("trident.simulator.backends", fromlist=["find_packet_tracer"]).find_packet_tracer()
    is None,
    reason="Packet Tracer is not installed",
)
def test_build_never_modifies_the_source(tmp_path):
    """The installation is read-only for this feature."""
    source = find_packet_tracer()
    if source is None or "PTGhost" in str(source):
        pytest.skip("no stock installation to copy")
    plist = source / "Contents" / "Info.plist"
    before = plist.read_bytes()
    build(source, tmp_path)
    assert plist.read_bytes() == before


def test_remove_is_idempotent(tmp_path):
    assert remove(tmp_path) == "ALREADY_GONE"
    assert remove(tmp_path) == "ALREADY_GONE"


def test_ghost_is_opt_in(monkeypatch):
    monkeypatch.delenv("TRIDENT_USE_GHOST_APP", raising=False)
    assert ghost_preferred() is False


@pytest.mark.parametrize("value", ["1", "true", "yes"])
def test_ghost_can_be_preferred(monkeypatch, value):
    monkeypatch.setenv("TRIDENT_USE_GHOST_APP", value)
    assert ghost_preferred() is True


def test_find_ghost_app_ignores_a_copy_without_the_flag(tmp_path, monkeypatch):
    import trident.simulator.ghost as ghost_module

    bundle = tmp_path / "PTGhost.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)
    (bundle / "Contents" / "MacOS" / "PacketTracer").write_text("#!/bin/sh\n")
    with open(bundle / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump({"CFBundleIdentifier": "x"}, handle)
    monkeypatch.setattr(ghost_module, "DEFAULT_GHOST_DIR", tmp_path)
    assert find_ghost_app() is None


def test_find_ghost_app_accepts_a_proper_agent(tmp_path, monkeypatch):
    import trident.simulator.ghost as ghost_module

    bundle = tmp_path / "PTGhost.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)
    (bundle / "Contents" / "MacOS" / "PacketTracer").write_text("#!/bin/sh\n")
    with open(bundle / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump({"LSUIElement": True}, handle)
    monkeypatch.setattr(ghost_module, "DEFAULT_GHOST_DIR", tmp_path)
    assert find_ghost_app() == bundle
