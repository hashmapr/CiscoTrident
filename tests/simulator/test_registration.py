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
def test_invalid_app_ids_are_rejected(bad_id, tmp_path):
    from trident.simulator.registration import RegistrationError, prepare

    with pytest.raises(RegistrationError):
        prepare(output_dir=tmp_path, app_id=bad_id, force_new=True)


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
def test_helper_reports_the_no_gui_path_first(tmp_path):
    """The primary instruction must be the one that needs no GUI click.

    An earlier version led with Extensions > Configure Apps > Add, which is the
    optional route. The working route is installing the .pta where Packet
    Tracer scans for it.
    """
    from trident.simulator.registration import prepare

    result = prepare(output_dir=tmp_path, app_id="dev.trident.test")
    steps = result.steps()
    assert any("--install" in step for step in steps)
    assert any("--verify" in step for step in steps)
    # The GUI route is still documented, but as the optional alternative.
    rendered = " ".join(steps)
    assert "Configure Apps" in rendered
    assert "Optional" in rendered


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


# ---------------------------------------------------------------------------
# Re-running must not invalidate an existing install
# ---------------------------------------------------------------------------


def test_rerun_reuses_the_existing_secret(tmp_path):
    """A second run must not mint a new secret.

    The secret is baked into the installed .pta. Regenerating it silently
    invalidates a working registration, which is exactly what happened when the
    helper was run twice in a row.
    """
    from trident.simulator.backends import find_packet_tracer
    from trident.simulator.registration import prepare

    if find_packet_tracer() is None:
        pytest.skip("Packet Tracer is not installed")

    first = prepare(output_dir=tmp_path, app_id="dev.trident.test")
    second = prepare(output_dir=tmp_path, app_id="dev.trident.test")
    assert first.secret == second.secret
    assert first.app_id == second.app_id
    assert second.pta_path.is_file()


def test_force_new_changes_the_secret(tmp_path):
    from trident.simulator.backends import find_packet_tracer
    from trident.simulator.registration import prepare

    if find_packet_tracer() is None:
        pytest.skip("Packet Tracer is not installed")

    first = prepare(output_dir=tmp_path, app_id="dev.trident.test")
    second = prepare(output_dir=tmp_path, app_id="dev.trident.test", force_new=True)
    assert first.secret != second.secret


def test_existing_credentials_file_is_read(tmp_path):
    from trident.simulator.backends import find_packet_tracer
    from trident.simulator.registration import prepare

    if find_packet_tracer() is None:
        pytest.skip("Packet Tracer is not installed")

    prepared = prepare(output_dir=tmp_path, app_id="dev.trident.persist")
    credentials = tmp_path / "credentials.env"
    assert credentials.is_file()
    text = credentials.read_text()
    assert "TRIDENT_PT_APP_ID=dev.trident.persist" in text
    assert prepared.secret in text
    # mode 0600: the secret grants full control of Packet Tracer.
    assert stat.S_IMODE(os.stat(credentials).st_mode) & 0o077 == 0


# ---------------------------------------------------------------------------
# Credential resolution and mismatch reporting
# ---------------------------------------------------------------------------


def test_installed_registration_wins_over_a_stale_export(monkeypatch, tmp_path):
    """The install must win, because it is the pair Packet Tracer holds.

    An earlier version let the environment win, so a shell that had exported a
    secret before the helper was re-run overrode a correct install and produced
    an authentication failure for a working setup.
    """
    from trident.simulator import backends

    credentials = tmp_path / "credentials.env"
    credentials.write_text(
        "TRIDENT_PT_APP_ID=dev.trident.installed\nTRIDENT_PT_SECRET=installedSecret123\n"
    )
    monkeypatch.setattr(backends, "CREDENTIALS_FILE", credentials)
    monkeypatch.setenv("TRIDENT_PT_APP_ID", "dev.trident.stale")
    monkeypatch.setenv("TRIDENT_PT_SECRET", "staleSecret123456")
    monkeypatch.delenv("TRIDENT_PT_FORCE_ENV", raising=False)

    assert backends.credentials_from_env() == (
        "dev.trident.installed",
        "installedSecret123",
    )


def test_environment_used_when_no_file_exists(monkeypatch, tmp_path):
    from trident.simulator import backends

    monkeypatch.setattr(backends, "CREDENTIALS_FILE", tmp_path / "absent.env")
    monkeypatch.setenv("TRIDENT_PT_APP_ID", "dev.trident.env")
    monkeypatch.setenv("TRIDENT_PT_SECRET", "envSecret123456")
    assert backends.credentials_from_env() == ("dev.trident.env", "envSecret123456")


def test_force_env_prefers_the_shell(monkeypatch, tmp_path):
    """A deliberate escape hatch for testing a not-yet-installed registration."""
    from trident.simulator import backends

    credentials = tmp_path / "credentials.env"
    credentials.write_text(
        "TRIDENT_PT_APP_ID=dev.trident.installed\nTRIDENT_PT_SECRET=installedSecret123\n"
    )
    monkeypatch.setattr(backends, "CREDENTIALS_FILE", credentials)
    monkeypatch.setenv("TRIDENT_PT_APP_ID", "dev.trident.env")
    monkeypatch.setenv("TRIDENT_PT_SECRET", "envSecret123456")
    monkeypatch.setenv("TRIDENT_PT_FORCE_ENV", "1")
    assert backends.credentials_from_env() == ("dev.trident.env", "envSecret123456")


def test_mismatch_between_shell_and_file_is_explained(monkeypatch, tmp_path):
    """The most likely cause of an auth rejection must be named, not implied."""
    from trident.simulator import backends

    credentials = tmp_path / "credentials.env"
    credentials.write_text(
        "TRIDENT_PT_APP_ID=dev.trident.ipc\nTRIDENT_PT_SECRET=installedSecret123\n"
    )
    monkeypatch.setattr(backends, "CREDENTIALS_FILE", credentials)
    monkeypatch.setenv("TRIDENT_PT_APP_ID", "dev.trident.ipc")
    monkeypatch.setenv("TRIDENT_PT_SECRET", "staleSecret123456")

    hint = backends.credentials_disagreement()
    assert hint is not None
    assert "differ from the registration installed" in hint
    assert "unset TRIDENT_PT_APP_ID" in hint


def test_no_mismatch_reported_when_values_agree(monkeypatch, tmp_path):
    from trident.simulator import backends

    credentials = tmp_path / "credentials.env"
    credentials.write_text(
        "TRIDENT_PT_APP_ID=dev.trident.ipc\nTRIDENT_PT_SECRET=secret1234567890\n"
    )
    monkeypatch.setattr(backends, "CREDENTIALS_FILE", credentials)
    monkeypatch.setenv("TRIDENT_PT_APP_ID", "dev.trident.ipc")
    monkeypatch.setenv("TRIDENT_PT_SECRET", "secret1234567890")
    assert backends.credentials_disagreement() is None


@pytest.mark.live_simulator
@pytest.mark.skipif(
    __import__("trident.simulator.backends", fromlist=["find_packet_tracer"]).find_packet_tracer()
    is None,
    reason="Packet Tracer is not installed",
)
def test_verify_reports_ok_when_the_install_is_valid(monkeypatch):
    """--verify launches Packet Tracer, so this is a live test, not a unit test.

    `verify()` starts the simulator and opens the sample lab to prove the
    registration authenticates. Without the `live_simulator` mark it ran during a
    plain `pytest`, which is exactly what the suite promises never happens, and
    it failed with a `fileOpen` timeout when the simulator had not settled.
    """
    """--verify must actually authenticate, not just check that files exist."""
    from trident.simulator.backends import credentials_from_env
    from trident.simulator.registration import verify

    if credentials_from_env() is None:
        pytest.skip("no registration is installed on this machine")
    ok, message = verify()
    assert ok, message
    assert "authenticated" in message


def test_verify_fails_cleanly_without_an_installed_meta_file(monkeypatch):
    from trident.simulator import registration

    monkeypatch.setattr(registration, "PTA_NAME", "definitely-not-installed.pta")
    ok, message = registration.verify()
    assert ok is False
    assert "run --install" in message or "not found" in message
