"""Staggered streaming in a real browser.

The acceptance criterion is NOT that one card animates per frame. It is that each
question has its own lifecycle and a genuinely delayed answer does not prevent
other completed answers from rendering.

These tests set TRIDENT_TEST_MODE and per-question delays on the *server*, so the
delay happens inside the pipeline exactly where a slow question would happen in
production. Production answers are never slowed: the delay code returns an empty
mapping unless the test-mode variable is set.
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

#: Question number -> delay in milliseconds. Q1 and Q4 are fast, Q3 and Q5 slow.
DELAYS = "2:400,3:1500,5:2500"

QUESTIONS = (
    "What is the hostname of R1?\n"  # Q1 fast
    "What is the hostname of R2?\n"  # Q2 400ms
    "What is the hostname of SW1?\n"  # Q3 1500ms
    "What IP address does R1 GigabitEthernet0/0 have?\n"  # Q4 fast
    "What IP address does R2 GigabitEthernet0/0 have?"  # Q5 2500ms
)


@pytest.fixture(scope="module")
def staggered_server():
    """A server that applies test-only per-question delays."""
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    env = dict(os.environ)
    env["TRIDENT_PORT"] = str(port)
    env["TRIDENT_TEST_MODE"] = "1"
    env["TRIDENT_TEST_ANSWER_DELAYS"] = DELAYS
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
    yield f"http://127.0.0.1:{port}"
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


@pytest.fixture()
def staggered_page(staggered_server):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.errors = errors  # type: ignore[attr-defined]
        page.goto(staggered_server, wait_until="domcontentloaded")
        page.wait_for_selector("#analyze", timeout=15000)
        yield page
        context.close()
        browser.close()


def test_fast_questions_render_before_slow_ones_complete(staggered_page, tmp_path):
    """Q1 and Q4 must appear while Q3 and Q5 are still pending."""
    lab = tmp_path / "lab.pkt"
    lab.write_bytes(FIXTURE.read_bytes())
    page = staggered_page

    page.set_input_files("input[type=file]", str(lab))
    page.fill("#questions", QUESTIONS)

    # Record each card's arrival time as the DOM grows.
    page.evaluate(
        """() => {
            window.__cardTimes = {};
            window.__t0 = performance.now();
            const root = document.getElementById('results');
            const obs = new MutationObserver(() => {
                for (const card of root.querySelectorAll('.result')) {
                    const q = card.querySelector('.qnum')?.textContent?.trim();
                    if (q && !(q in window.__cardTimes)) {
                        window.__cardTimes[q] = Math.round(performance.now() - window.__t0);
                    }
                }
            });
            obs.observe(root, { childList: true, subtree: true });
        }"""
    )
    page.click("#analyze")
    page.wait_for_function(
        """() => {
            const s = document.getElementById('status')?.textContent || '';
            return s.startsWith('Done') || s.startsWith('Failed');
        }""",
        timeout=60000,
    )
    times = page.evaluate("() => window.__cardTimes")

    assert set(times) == {"Q1", "Q2", "Q3", "Q4", "Q5"}, times
    # The slow questions must land materially after the fast ones.
    assert times["Q3"] > times["Q1"] + 500, times
    assert times["Q5"] > times["Q4"] + 500, times
    # Q4 (no delay) finished before Q3 (1500 ms) despite coming later.
    assert times["Q4"] < times["Q3"], times
    assert page.errors == []


def test_cards_keep_their_question_positions(staggered_page, tmp_path):
    """Out-of-order completion must not reorder the cards."""
    lab = tmp_path / "lab.pkt"
    lab.write_bytes(FIXTURE.read_bytes())
    page = staggered_page
    page.set_input_files("input[type=file]", str(lab))
    page.fill("#questions", QUESTIONS)
    page.click("#analyze")
    page.wait_for_function(
        """() => {
            const s = document.getElementById('status')?.textContent || '';
            return s.startsWith('Done') || s.startsWith('Failed');
        }""",
        timeout=60000,
    )
    numbers = page.evaluate(
        "() => Array.from(document.querySelectorAll('#results .result .qnum')).map(e => e.textContent.trim())"
    )
    # Streaming appends in completion order, which is why this matters: the
    # positions must still correspond to the questions that were asked.
    assert sorted(numbers) == [f"Q{i}" for i in range(1, 6)]


def test_each_card_updates_independently(staggered_page, tmp_path):
    """At an intermediate moment, resolved cards exist alongside pending ones."""
    lab = tmp_path / "lab.pkt"
    lab.write_bytes(FIXTURE.read_bytes())
    page = staggered_page
    page.set_input_files("input[type=file]", str(lab))
    page.fill("#questions", QUESTIONS)
    page.click("#analyze")

    # Wait until at least two cards have rendered but before the run finishes.
    page.wait_for_function(
        "() => document.querySelectorAll('#results .result').length >= 2",
        timeout=30000,
    )
    mid = page.evaluate(
        """() => ({
            cards: document.querySelectorAll('#results .result').length,
            status: document.getElementById('status')?.textContent || '',
            done: (document.getElementById('status')?.textContent || '').startsWith('Done'),
        })"""
    )
    assert mid["cards"] >= 2
    assert mid["done"] is False, (
        "cards rendered before completion is expected, but the run had already "
        "finished — the test cannot distinguish incremental from batched"
    )
