"""Shared browser fixtures, imported explicitly by each browser test module.

This cannot be a ``conftest.py``: a conftest in this directory shadows the
top-level ``tests/conftest.py`` for the entire test tree, because pytest imports
a bare ``conftest`` module by name. That collision silently broke collection for
five unrelated modules. Importing explicitly avoids it entirely.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "sample_lab.pkt"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_server(extra_env: dict[str, str] | None = None) -> tuple[subprocess.Popen, str]:
    """Start the real application and return (process, base_url)."""
    port = free_port()
    env = dict(os.environ)
    env["TRIDENT_PORT"] = str(port)
    env["TRIDENT_HOST"] = "127.0.0.1"
    env.pop("TRIDENT_ALLOW_LIVE_SIMULATOR", None)
    if extra_env:
        env.update(extra_env)
    process = subprocess.Popen(
        [sys.executable, "-m", "trident"],
        cwd=REPO,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("server exited before becoming ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return process, f"http://127.0.0.1:{port}"
        except OSError:
            time.sleep(0.25)
    process.terminate()
    raise RuntimeError("server did not start within 45s")


def stop_server(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def _lab_file(tmp_path) -> Path:
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    target = tmp_path / "lab.pkt"
    target.write_bytes(FIXTURE.read_bytes())
    return target


#: Import as a fixture in each browser test module:  from .browser_fixtures import lab_file
lab_file = pytest.fixture(name="lab_file")(_lab_file)
