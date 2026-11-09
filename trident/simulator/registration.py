"""ExApp registration bootstrap.

Packet Tracer accepts PTMP connections only from registered external
applications, and registration is a one-time interactive step that Packet Tracer
exposes no IPC call for. This module does everything that *can* be automated and
stops at the one click that cannot:

1. render the app manifest XML with a generated app id and secret,
2. run Cisco's own ``meta`` utility, unchanged, to encrypt it into a ``.pta``,
3. report the exact remaining steps and the exact commands to verify them.

It never drives the Packet Tracer GUI, never edits ``PT.conf``, and never
patches a binary. Those would be authentication bypasses, and they are out of
scope by design.

Usage::

    python -m trident.simulator.registration

    # or programmatically
    from trident.simulator.registration import prepare
    result = prepare(output_dir=Path("~/.config/trident"))
    print(result.export_commands())
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import string
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .backends import find_packet_tracer

DEFAULT_APP_ID = "dev.trident.ipc"
DEFAULT_OUTPUT_DIR = Path.home() / ".config" / "trident"
MANIFEST_NAME = "trident-exapp.xml"
PTA_NAME = "trident.pta"
INTEGRITY_NAME = "trident-exapp"

#: Every privilege in the shipped framework's SecurityPrivilege enum. The
#: runtime refuses mutations regardless, so granting them does not widen what
#: this project will do; it only avoids a second registration later.
PRIVILEGES = (
    "GET_NETWORK_INFO",
    "CHANGE_NETWORK_INFO",
    "SIMULATION_MODE",
    "MISC_GUI",
    "FILE",
    "CHANGE_PREFERENCES",
    "CHANGE_GUI",
    "ACTIVITY_WIZARD",
    "MULTIUSER",
    "IPC",
    "APPLICATION",
)

_MANIFEST = """<?xml version="1.0" encoding = "iso-8859-1"?>
<!DOCTYPE PT_APP_META>
<PT_APP_META>
    <PT_VERSION>9.0.0</PT_VERSION>
    <IPC_VERSION>1.0</IPC_VERSION>
    <NAME>trident</NAME>
    <VERSION>1.0.0</VERSION>
    <ID>{app_id}</ID>
    <DESCRIPTION>TRIDENT headless investigation runtime</DESCRIPTION>
    <AUTHOR>TRIDENT</AUTHOR>
    <CONTACT>trident</CONTACT>
    <EXECUTABLE_PATH>trident</EXECUTABLE_PATH>
    <KEY>{secret}</KEY>
    <SECURITY_SETTINGS>
{privileges}
    </SECURITY_SETTINGS>
    <LOADING>ON_DEMAND</LOADING>
    <SAVING>NEVER</SAVING>
    <INSTANCES>1</INSTANCES>
</PT_APP_META>
"""


class RegistrationError(RuntimeError):
    """A required input or tool was missing."""


@dataclass(frozen=True)
class RegistrationResult:
    app_id: str
    secret: str
    pta_path: Path
    meta_tool: Path
    bundle: Path

    def export_commands(self) -> str:
        """Shell lines the operator runs after registering the .pta."""
        return (
            f'export TRIDENT_PT_APP_ID="{self.app_id}"\n'
            f'export TRIDENT_PT_SECRET="{self.secret}"\n'
            f'export TRIDENT_PT_HOME="{self.bundle}"'
        )

    def steps(self) -> list[str]:
        return [
            (
                "Install the meta file into Packet Tracer's own extensions folder. "
                "This is the location it scans, and no GUI step is needed:"
            ),
            "    python -m trident.simulator.registration --install",
            "Prove it works:",
            "    python -m trident.simulator.registration --verify",
            "Run the live tests:",
            "    pytest tests/simulator/test_live_integration.py -v",
            (
                "Optional alternative: Extensions > IPC > Configure Apps > Add, "
                "select the .pta, then quit Packet Tracer normally. That route "
                "persists the registration in Packet Tracer's own configuration."
            ),
        ]

    def as_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "pta_path": str(self.pta_path),
            "meta_tool": str(self.meta_tool),
            "bundle": str(self.bundle),
            "steps": self.steps(),
            "export_commands": self.export_commands(),
            "secret_redacted": True,
        }


def _validate_app_id(app_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,80}", app_id or ""):
        raise RegistrationError(
            "app id may only contain letters, digits, dots, dashes and underscores"
        )
    return app_id


def generate_secret(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def render_manifest(app_id: str, secret: str) -> str:
    privileges = "\n".join(f"        <PRIVILEGE>{name}</PRIVILEGE>" for name in PRIVILEGES)
    return _MANIFEST.format(app_id=app_id, secret=secret, privileges=privileges)


def _write_private(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o600)


def _read_existing_credentials(target: Path) -> tuple[str | None, str | None]:
    """Read a previously generated app id and secret, if present.

    Re-running the helper must not mint a new secret: the secret is baked into
    the installed ``.pta``, so a fresh one silently invalidates a working
    registration. Earlier versions regenerated unconditionally, which produced
    exactly that failure when the helper was run twice.
    """
    path = target / "credentials.env"
    if not path.is_file():
        return None, None
    values: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return None, None
    return values.get("TRIDENT_PT_APP_ID"), values.get("TRIDENT_PT_SECRET")


def prepare(
    output_dir: Path | None = None,
    app_id: str | None = None,
    secret: str | None = None,
    persist: bool = True,
    force_new: bool = False,
) -> RegistrationResult:
    """Build the ``.pta`` and return what the operator must do next.

    Raises :class:`RegistrationError` when Packet Tracer or its ``meta`` tool is
    missing, so the caller can report a real reason rather than a generic failure.
    """
    bundle = find_packet_tracer()
    if bundle is None:
        raise RegistrationError(
            "Packet Tracer was not found in a searchable location; set "
            "TRIDENT_PT_HOME to the installation folder"
        )
    meta_tool = bundle / "Contents" / "extensions" / "meta"
    if not meta_tool.is_file():
        raise RegistrationError(f"Packet Tracer's meta tool is missing at {meta_tool}")
    if os.access(meta_tool, os.X_OK) is False:
        raise RegistrationError(f"{meta_tool} is not executable")

    target = Path(output_dir).expanduser() if output_dir else DEFAULT_OUTPUT_DIR
    target.mkdir(parents=True, exist_ok=True)
    os.chmod(target, 0o700)

    existing_id, existing_secret = _read_existing_credentials(target)
    if not force_new:
        app_id = app_id or existing_id or DEFAULT_APP_ID
        secret = secret or existing_secret
    app_id = _validate_app_id(app_id)
    secret = secret or generate_secret()
    if not re.fullmatch(r"[A-Za-z0-9]{16,128}", secret):
        raise RegistrationError("secret must be 16-128 alphanumeric characters")

    manifest_path = target / MANIFEST_NAME
    pta_path = target / PTA_NAME
    integrity_path = target / INTEGRITY_NAME
    _write_private(manifest_path, render_manifest(app_id, secret))
    integrity_path.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(integrity_path, 0o755)

    # ``meta`` resolves its arguments relative to the working directory and
    # refuses absolute paths for the integrity file, so it must run inside the
    # output directory with bare filenames.
    completed = subprocess.run(
        [
            str(meta_tool),
            PTA_NAME,
            MANIFEST_NAME,
            "-i",
            INTEGRITY_NAME,
        ],
        cwd=target,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    # The plaintext secret must not linger once it is inside the encrypted .pta.
    manifest_path.unlink(missing_ok=True)

    if completed.returncode != 0 or not pta_path.is_file():
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RegistrationError(f"meta tool did not produce {pta_path}: {detail}")

    if persist:
        credentials_path = target / "credentials.env"
        _write_private(
            credentials_path,
            f"TRIDENT_PT_APP_ID={app_id}\nTRIDENT_PT_SECRET={secret}\n",
        )

    return RegistrationResult(
        app_id=app_id,
        secret=secret,
        pta_path=pta_path,
        meta_tool=meta_tool,
        bundle=bundle,
    )


def verify(use_environment: bool = False) -> tuple[bool, str]:
    """Prove the *installed* registration authenticates.

    Reads the credentials written next to the ``.pta`` rather than the
    environment, because the question this answers is "is the install good?".
    A stale export in the calling shell made an earlier version report a failure
    for a perfectly working install, which is the opposite of useful.

    Pass ``use_environment=True`` to test the shell's credentials instead.
    """
    from .backends import (
        CREDENTIALS_FILE,
        ProcessSupervisor,
        credentials_from_env,
        find_packet_tracer,
    )
    from .isolation import Workspace
    from .ptmp import PtmpClient

    bundle = find_packet_tracer()
    if bundle is None:
        return False, "Packet Tracer not found; set TRIDENT_PT_HOME"
    installed = bundle / "Contents" / "extensions" / PTA_NAME
    if not installed.is_file():
        return False, f"no installed meta file at {installed}; run --install"

    if use_environment:
        credentials = credentials_from_env()
    else:
        stored_id, stored_secret = _read_existing_credentials(CREDENTIALS_FILE.parent)
        credentials = (
            (stored_id, stored_secret) if stored_id and stored_secret else None
        )
    cred_source = "the environment" if use_environment else str(CREDENTIALS_FILE)
    if credentials is None:
        return False, f"no credentials at {cred_source}; run the helper with --install"

    workspace = Workspace()
    directory = workspace.new_session_dir("verify")
    supervisor = ProcessSupervisor(bundle, 0)
    client = None
    try:
        port = supervisor.start(directory)
        client = PtmpClient(*credentials, port=port)
        handshake = client.connect()
        version = handshake.server_version or "unknown"

        details = f"authenticated against Packet Tracer {version} (credentials from {cred_source})"
        sample = Path(__file__).parents[2] / "tests" / "fixtures" / "sample_lab.pkt"
        if sample.is_file():
            reply = client.call(
                ["appWindow", ("fileOpen", [(9, str(sample))])], timeout=60.0
            )
            status = reply[0] if reply else ""
            if status not in {"0", "4", "OK", ""}:
                return False, f"authenticated, but fileOpen returned {status!r}"
            count = client.call(["network", "getDeviceCount"])
            details += f", loaded {sample.name}, {count[0] if count else '?'} devices visible"

        if not use_environment:
            note = _shell_mismatch_note()
            if note:
                details += f"\nNOTE: {note}"
        return True, details
    except Exception as exc:  # noqa: BLE001 - returned as a diagnostic
        from .backends import _auth_hint

        if type(exc).__name__ == "PtmpAuthRejected":
            return False, _auth_hint(exc)
        return False, str(exc)
    finally:
        if client is not None:
            client.close()
        supervisor.stop()
        workspace.cleanup(directory)


def _shell_mismatch_note() -> str | None:
    """A warning, not an error, when the shell disagrees with the install."""
    from .backends import credentials_disagreement

    hint = credentials_disagreement()
    if not hint:
        return None
    return (
        "this shell still exports stale credentials. The installed registration "
        "is used regardless, so nothing is broken; run "
        "`unset TRIDENT_PT_APP_ID TRIDENT_PT_SECRET` to clean up the environment."
    )


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="trident.simulator.registration",
        description=(
            "Prepare the Packet Tracer ExApp registration file and print the "
            "remaining manual steps. Never drives the GUI."
        ),
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--app-id", default=None)
    parser.add_argument(
        "--force-new",
        action="store_true",
        help=(
            "generate a new secret even if one exists. This invalidates any "
            "previously installed .pta and requires reinstalling it."
        ),
    )
    parser.add_argument(
        "--show-credentials",
        action="store_true",
        help="include the secret in the output (it grants full control of Packet Tracer)",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="do not write credentials.env; use TRIDENT_PT_APP_ID/SECRET instead",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="prove the installed registration authenticates, then exit",
    )
    parser.add_argument(
        "--verify-env",
        action="store_true",
        help="verify using TRIDENT_PT_APP_ID/TRIDENT_PT_SECRET from the environment",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help=(
            "copy the .pta into Packet Tracer's own extensions directory, which is "
            "the location it scans for ExApps"
        ),
    )
    args = parser.parse_args(argv)

    if args.verify or args.verify_env:
        ok, message = verify(use_environment=args.verify_env)
        print(("OK: " if ok else "FAILED: ") + message)
        return 0 if ok else 3

    try:
        result = prepare(
            Path(args.output_dir) if args.output_dir else None,
            args.app_id,
            persist=not args.no_persist,
            force_new=args.force_new,
        )
    except RegistrationError as exc:
        print(f"registration not prepared: {exc}")
        return 2

    if args.install:
        target = result.bundle / "Contents" / "extensions" / PTA_NAME
        shutil.copyfile(result.pta_path, target)
        os.chmod(target, 0o644)
        print(f"Installed {target}")

    print(f"Prepared {result.pta_path}")
    print("\nRemaining steps (manual, one time):")
    for index, step in enumerate(result.steps(), start=1):
        print(f"  {index}. {step}")
    print("\nAfter registering, export:")
    print(result.export_commands())
    if args.show_credentials:
        print("\nFull result:")
        print(json.dumps({**result.as_dict(), "secret": result.secret}, indent=2))
    else:
        print("\n(the secret is printed by --show-credentials; it is not shown above)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
