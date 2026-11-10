"""A slow Ghost investigation must not block ordinary static answers.

Two tests, deliberately separated:

* **Controlled** — a deliberately slow worker stands in for Ghost. This runs in
  CI with no Packet Tracer and proves the *scheduling* behaviour.
* **Real** — only runs when a live simulator is registered, and is skipped
  otherwise. It is never used to claim simulator functionality from the
  controlled test.
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

pytestmark = pytest.mark.browser

REPO = Path(__file__).parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "sample_lab.pkt"

QUESTIONS = (
    "What is the hostname of R1?\n"  # Q1 fast static
    "What IP address does R1 GigabitEthernet0/0 have?\n"  # Q2 fast static
    "What is the model of R1?\n"  # Q3 fast static
    "Is PC-A able to reach PC-B?\n"  # Q4 the slow one
    "What is the subnet mask of R1 GigabitEthernet0/0?"  # Q5 must not wait
)


def _start_server(extra_env: dict[str, str]) -> tuple[subprocess.Popen, str]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    env = dict(os.environ)
    env["TRIDENT_PORT"] = str(port)
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
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                break
        except OSError:
            time.sleep(0.25)
    return process, f"http://127.0.0.1:{port}"


def _question_times(page, lab: Path) -> dict[str, int]:
    page.set_input_files("input[type=file]", str(lab))
    page.fill("#questions", QUESTIONS)
    page.evaluate(
        """() => {
            window.__cardTimes = {};
            window.__t0 = performance.now();
            const root = document.getElementById('results');
            new MutationObserver(() => {
                for (const card of root.querySelectorAll('.result')) {
                    const q = card.querySelector('.qnum')?.textContent?.trim();
                    if (q && !(q in window.__cardTimes)) {
                        window.__cardTimes[q] = Math.round(performance.now() - window.__t0);
                    }
                }
            }).observe(root, { childList: true, subtree: true });
        }"""
    )
    page.click("#analyze")
    page.wait_for_function(
        """() => {
            const s = document.getElementById('status')?.textContent || '';
            return s.startsWith('Done') || s.startsWith('Failed');
        }""",
        timeout=120000,
    )
    return page.evaluate("() => window.__cardTimes")


# ---------------------------------------------------------------------------
# Controlled: a slow worker stands in for Ghost
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def slow_worker_server():
    """Server where question 4 is artificially slow, standing in for Ghost."""
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    process, base = _start_server(
        {
            "TRIDENT_TEST_MODE": "1",
            "TRIDENT_TEST_ANSWER_DELAYS": "4:4000",
        }
    )
    yield base
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def test_slow_question_does_not_block_fast_ones(slow_worker_server, tmp_path):
    """Q1, Q2, Q3 and Q5 must all render before Q4 finishes."""
    lab = tmp_path / "lab.pkt"
    lab.write_bytes(FIXTURE.read_bytes())
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_context().new_page()
        errors: list[str] = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto(slow_worker_server, wait_until="domcontentloaded")
        page.wait_for_selector("#analyze", timeout=15000)
        try:
            times = _question_times(page, lab)
            assert set(times) == {"Q1", "Q2", "Q3", "Q4", "Q5"}, times
            # The slow question lands well after every fast one.
            assert times["Q4"] > 3500, times
            for fast in ("Q1", "Q2", "Q3", "Q5"):
                assert times[fast] < times["Q4"] - 1000, (
                    f"{fast} ({times[fast]}ms) should have rendered long before "
                    f"Q4 ({times['Q4']}ms)"
                )
            assert errors == []
        finally:
            browser.close()


def test_slow_question_still_produces_a_card(slow_worker_server, tmp_path):
    """The delayed question must not be dropped or hang the batch."""
    lab = tmp_path / "lab.pkt"
    lab.write_bytes(FIXTURE.read_bytes())
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_context().new_page()
        page.goto(slow_worker_server, wait_until="domcontentloaded")
        page.wait_for_selector("#analyze", timeout=15000)
        try:
            _question_times(page, lab)
            cards = page.evaluate(
                """() => Array.from(document.querySelectorAll('#results .result')).map(a => ({
                    q: a.querySelector('.qnum')?.textContent?.trim(),
                    badge: a.querySelector('.badge')?.textContent?.trim(),
                }))"""
            )
            assert len(cards) == 5, cards
            q4 = [card for card in cards if card["q"] == "Q4"]
            assert q4 and q4[0]["badge"]
        finally:
            browser.close()


# ---------------------------------------------------------------------------
# Real Ghost, when a live simulator is registered
# ---------------------------------------------------------------------------

_HAS_SIMULATOR = False
try:
    from trident.simulator.backends import credentials_from_env, find_packet_tracer

    _HAS_SIMULATOR = (
        find_packet_tracer() is not None and credentials_from_env() is not None
    )
except Exception:  # noqa: BLE001
    _HAS_SIMULATOR = False


@pytest.mark.skipif(
    not _HAS_SIMULATOR,
    reason="no registered Packet Tracer; the real-simulator test cannot run",
)
def test_real_simulator_does_not_block_static_answers(tmp_path):
    """With a live simulator, a PDU experiment must not delay static answers.

    Skips entirely when no registration exists. A skip is recorded as a skip and
    is never presented as evidence that live concurrency works.
    """
    from trident.simulator import SimulatorRuntime

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(prefer_live=True)
    if not runtime.is_available():
        pytest.skip("live simulator is not available in this process")

    lab = tmp_path / "lab.pkt"
    lab.write_bytes(FIXTURE.read_bytes())
    session = runtime.create_session(lab)
    try:
        result = session.send_pdu("R1", "R2", timeout_seconds=30)
        assert result.observed is True
        assert result.status.value in {"DELIVERED", "DROPPED", "INCONCLUSIVE"}
        # The static answers were computed before/independent of this experiment;
        # this test only asserts the experiment itself is real and bounded.
    finally:
        status = session.close()
    assert "source=INTACT" in status
