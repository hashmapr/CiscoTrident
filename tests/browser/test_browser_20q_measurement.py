"""Twenty-question workload with recorded measurements.

The acceptance criterion is NOT that cards animate one per frame. It is that each
question has its own scheduled lifecycle and that a delayed answer does not
prevent completed answers from rendering. The timings here document what the
application actually does on this machine.
"""

from __future__ import annotations

import json
import pathlib
import time

import pytest
from browser_fixtures import lab_file, start_server, stop_server

pytestmark = pytest.mark.browser

__all__ = ["lab_file"]


@pytest.fixture(scope="module")
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


@pytest.fixture(scope="module")
def trident_server():
    process, base = start_server()
    yield base
    stop_server(process)


@pytest.fixture()
def page(browser, trident_server):
    context = browser.new_context()
    pg = context.new_page()
    errors: list[str] = []
    pg.on("pageerror", lambda exc: errors.append(str(exc)))
    pg.errors = errors  # type: ignore[attr-defined]
    pg.goto(trident_server, wait_until="domcontentloaded")
    pg.wait_for_selector("#analyze", timeout=15000)
    yield pg
    context.close()

REPO = pathlib.Path(__file__).parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "sample_lab.pkt"

QUESTIONS = (
    "What is the hostname of R1?\n"
    "What is the hostname of R2?\n"
    "What is the hostname of SW1?\n"
    "What IP address does R1 GigabitEthernet0/0 have?\n"
    "What IP address does R1 GigabitEthernet0/1 have?\n"
    "What IP address does R2 GigabitEthernet0/0 have?\n"
    "What IP address does R2 GigabitEthernet0/1 have?\n"
    "Which device is directly connected to R1 GigabitEthernet0/0?\n"
    "Which device is directly connected to R1 GigabitEthernet0/1?\n"
    "Which device is directly connected to R2 GigabitEthernet0/0?\n"
    "What subnet does R1 GigabitEthernet0/0 belong to?\n"
    "What subnet does R1 GigabitEthernet0/1 belong to?\n"
    "What subnet does R2 GigabitEthernet0/0 belong to?\n"
    "What is the subnet mask of R1 GigabitEthernet0/0?\n"
    "What is the subnet mask of R1 GigabitEthernet0/1?\n"
    "How many VLANs are configured?\n"
    "What is the model of R1?\n"
    "What is the model of SW1?\n"
    "Is PC-A able to reach PC-B?\n"
    "What is the design intent of this lab?"
)

ARTIFACTS = REPO / "docs" / "stream_verify" / "artifacts"


def test_twenty_questions_with_measurements(page, lab_file):
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    page.set_input_files("input[type=file]", str(lab_file))
    page.fill("#questions", QUESTIONS)

    page.evaluate(
        """() => {
            window.__marks = { firstEvent: null, stageTimes: {}, cardTimes: {} };
            window.__t0 = performance.now();
            const root = document.getElementById('results');
            new MutationObserver(() => {
                for (const card of root.querySelectorAll('.result')) {
                    const q = card.querySelector('.qnum')?.textContent?.trim();
                    if (q && !(q in window.__marks.cardTimes)) {
                        window.__marks.cardTimes[q] = Math.round(performance.now() - window.__t0);
                    }
                }
            }).observe(root, { childList: true, subtree: true });
        }"""
    )

    started = time.monotonic()
    page.click("#analyze")
    page.wait_for_function(
        """() => {
            const s = document.getElementById('status')?.textContent || '';
            return s.startsWith('Done') || s.startsWith('Failed');
        }""",
        timeout=180000,
    )
    elapsed = time.monotonic() - started

    marks = page.evaluate("() => window.__marks")
    cards = page.evaluate(
        """() => Array.from(document.querySelectorAll('#results .result')).map(a => ({
            q: a.querySelector('.qnum')?.textContent?.trim(),
            badge: a.querySelector('.badge')?.textContent?.trim(),
            answer: a.querySelector('.answer')?.textContent?.trim() || null,
            explain: a.querySelector('.explain')?.textContent?.trim() || null,
        }))"""
    )

    card_times = marks["cardTimes"]
    times = sorted(card_times.values()) if card_times else []
    measurements = {
        "total_session_seconds": round(elapsed, 2),
        "card_count": len(cards),
        "first_card_ms": times[0] if times else None,
        "median_card_ms": times[len(times) // 2] if times else None,
        "slowest_card_ms": times[-1] if times else None,
        "distinct_arrival_times": len(set(times)),
        "status_counts": _counts(cards),
        "errors": page.errors,
    }
    (ARTIFACTS / "twenty_question_measurements.json").write_text(
        json.dumps({"measurements": measurements, "cards": cards}, indent=2)
    )
    page.screenshot(path=str(ARTIFACTS / "twenty_questions.png"), full_page=True)

    assert len(cards) == 20, measurements
    assert measurements["errors"] == []
    assert measurements["first_card_ms"] is not None
    # Every card must be terminal.
    for card in cards:
        assert card["badge"], card
        assert card["answer"] or card["explain"], card


def _counts(cards: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for card in cards:
        counts[card["badge"]] = counts.get(card["badge"], 0) + 1
    return counts
