"""Browser test fixtures: a real server plus a real Chromium.

These tests drive the actual application in a real browser. They are slower than
unit tests, so they are marked ``browser`` and excluded from the default run
unless explicitly selected.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("playwright", reason="playwright is not installed")

from playwright.sync_api import sync_playwright

REPO = Path(__file__).parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "sample_lab.pkt"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def server():
    """Run the real application and yield its base URL."""
    port = _free_port()
    env = dict(os.environ)
    env["TRIDENT_PORT"] = str(port)
    env["TRIDENT_HOST"] = "127.0.0.1"
    # Never start a simulator from a browser test.
    env.pop("TRIDENT_ALLOW_LIVE_SIMULATOR", None)
    process = subprocess.Popen(
        [sys.executable, "-m", "trident"],
        cwd=REPO,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read().decode(errors="replace") if process.stdout else ""
            raise RuntimeError(f"server exited early:\n{output[-2000:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                break
        except OSError:
            time.sleep(0.25)
    else:
        process.terminate()
        raise RuntimeError("server did not start within 45s")

    yield base

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


@pytest.fixture(scope="session")
def chromium():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        yield browser
        browser.close()


@pytest.fixture()
def page(chromium, server):
    context = chromium.new_context()
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.errors = errors  # type: ignore[attr-defined]
    page.goto(server, wait_until="domcontentloaded")
    page.wait_for_selector("#analyze", timeout=15000)
    yield page
    context.close()


@pytest.fixture()
def lab_file(tmp_path) -> Path:
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    target = tmp_path / "lab.pkt"
    target.write_bytes(FIXTURE.read_bytes())
    return target
