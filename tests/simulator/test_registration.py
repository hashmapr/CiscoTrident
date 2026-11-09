"""Registration helper tests.

The helper automates everything except the one click that Packet Tracer exposes
no programmatic way to perform. These tests check the automation half and, just
as importantly, that the helper refuses to do anything that would amount to an
authentication bypass.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest


def test_manifest_contains_every_required_element():
    from trident.simulator.registration import render_manifest

    xml = render_manifest("dev.trident.ipc", "abc123def456ghi789")
    for element in (
        "<PT_VERSION>",
        "<IPC_VERSION>",
        "<NAME>",
        "<VERSION>",
        "<ID>dev.trident.ipc</ID>",
        "<KEY>abc123def456ghi789</KEY>",
        "<SECURITY_SETTINGS>",
        "<LOADING>ON_DEMAND</LOADING>",
        "<SAVING>NEVER</SAVING>",
        "<INSTANCES>1</INSTANCES>",
    ):
        assert element in xml


def test_manifest_grants_the_documented_privilege_set():
    from trident.simulator.registration import PRIVILEGES, render_manifest

    xml = render_manifest("dev.trident.ipc", "abc123def456ghi789")
    assert xml.count("<PRIVILEGE>") == len(PRIVILEGES)
    assert "IPC" in PRIVILEGES


def test_secret_is_generated_not_hardcoded():
    from trident.simulator.registration import generate_secret

    first = generate_secret()
    second = generate_secret()
    assert first != second
    assert len(first) == 32
    assert first.isalnum()


@pytest.mark.parametrize(
    "bad_id",
    ["", "ab", "has space", "quote'", "../../etc", "<script>"],
)
def test_invalid_app_ids_are_rejected(bad_id):
    from trident.simulator.registration import RegistrationError, prepare

    with pytest.raises(RegistrationError):
        prepare(output_dir=Path("/tmp/trident-reg-test"), app_id=bad_id)


def test_short_secret_is_rejected(tmp_path):
    from trident.simulator.registration import RegistrationError, prepare

    with pytest.raises(RegistrationError, match="secret"):
        prepare(output_dir=tmp_path, secret="short")


@pytest.mark.skipif(
    __import__("trident.simulator.backends", fromlist=["find_packet_tracer"]).find_packet_tracer()
    is None,
    reason="Packet Tracer is not installed",
)
def test_helper_produces_a_pta_and_leaves_no_plaintext_secret(tmp_path):
    from trident.simulator.registration import MANIFEST_NAME, prepare

    result = prepare(output_dir=tmp_path, app_id="dev.trident.test")
    assert result.pta_path.is_file()
    assert result.pta_path.stat().st_size > 0
    # The plaintext manifest carries the secret and must not survive.
    assert not (tmp_path / MANIFEST_NAME).exists()
    # The .pta is encrypted, so the secret must not appear in it verbatim.
    assert result.secret.encode() not in result.pta_path.read_bytes()


@pytest.mark.skipif(
    __import__("trident.simulator.backends", fromlist=["find_packet_tracer"]).find_packet_tracer()
    is None,
    reason="Packet Tracer is not installed",
)
def test_helper_reports_the_manual_step(tmp_path):
    from trident.simulator.registration import prepare

    result = prepare(output_dir=tmp_path, app_id="dev.trident.test")
    steps = result.steps()
    assert any("Extensions" in step for step in steps)
    assert any("Quit" in step for step in steps), (
        "the clean-quit requirement is what persists the registration"
    )


@pytest.mark.skipif(
    __import__("trident.simulator.backends", fromlist=["find_packet_tracer"]).find_packet_tracer()
    is None,
    reason="Packet Tracer is not installed",
)
def test_output_files_are_private(tmp_path):
    from trident.simulator.registration import prepare

    prepare(output_dir=tmp_path, app_id="dev.trident.test")
    mode = stat.S_IMODE(os.stat(tmp_path).st_mode)
    assert mode & 0o077 == 0, "the registration directory must not be group/world accessible"


def test_helper_never_touches_packet_tracer_state(tmp_path):
    """It must not edit PT.conf or anything inside the app bundle."""
    from trident.simulator.backends import find_packet_tracer
    from trident.simulator.registration import prepare

    bundle = find_packet_tracer()
    if bundle is None:
        pytest.skip("Packet Tracer is not installed")
    pt_conf = Path.home() / "Cisco Packet Tracer 9.0.1" / "PT.conf"
    before = pt_conf.stat().st_mtime if pt_conf.exists() else None
    prepare(output_dir=tmp_path, app_id="dev.trident.test")
    after = pt_conf.stat().st_mtime if pt_conf.exists() else None
    assert before == after, "the helper must not modify Packet Tracer configuration"


def test_cli_reports_a_clean_failure_without_a_bundle(monkeypatch, capsys):
    from trident.simulator import registration

    monkeypatch.setattr(registration, "find_packet_tracer", lambda: None)
    assert registration.main(["--output-dir", "/tmp/trident-reg-cli"]) == 2
    output = capsys.readouterr().out
    assert "registration not prepared" in output
