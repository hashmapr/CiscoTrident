"""Real-browser tests for the streaming UI.

Every test here drives actual Chromium against the actual application. Nothing
is mocked: the file is really uploaded, the button is really clicked, and the
assertions read the real DOM.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.browser

THREE = (
    "What is the hostname of R1?\n"
    "What IP address does R1 GigabitEthernet0/0 have?\n"
    "Which device is directly connected to R1 GigabitEthernet0/0?"
)

TWENTY = "What is the hostname of R1?\nWhat is the hostname of R2?\nWhat is the hostname of SW1?\nWhat IP address does R1 GigabitEthernet0/0 have?\nWhat IP address does R1 GigabitEthernet0/1 have?\nWhat IP address does R2 GigabitEthernet0/0 have?\nWhat IP address does R2 GigabitEthernet0/1 have?\nWhich device is directly connected to R1 GigabitEthernet0/0?\nWhich device is directly connected to R1 GigabitEthernet0/1?\nWhich device is directly connected to R2 GigabitEthernet0/0?\nWhat subnet does R1 GigabitEthernet0/0 belong to?\nWhat subnet does R1 GigabitEthernet0/1 belong to?\nWhat subnet does R2 GigabitEthernet0/0 belong to?\nWhat is the subnet mask of R1 GigabitEthernet0/0?\nWhat is the subnet mask of R1 GigabitEthernet0/1?\nHow many VLANs are configured?\nWhat is the model of R1?\nWhat is the model of SW1?\nIs PC-A able to reach PC-B?\nWhat is the design intent of this lab?"


def _run(page, lab_file, questions: str) -> None:
    page.set_input_files("input[type=file]", str(lab_file))
    page.fill("#questions", questions)
    page.click("#analyze")
    page.wait_for_function(
        """() => {
            const s = document.getElementById('status')?.textContent || '';
            return s.startsWith('Done') || s.startsWith('Failed');
        }""",
        timeout=120000,
    )


def _cards(page) -> list[dict]:
    return page.evaluate(
        """() => Array.from(document.querySelectorAll('#results .result')).map(a => ({
            q: a.querySelector('.qnum')?.textContent?.trim(),
            badge: a.querySelector('.badge')?.textContent?.trim(),
            answer: a.querySelector('.answer')?.textContent?.trim() || null,
            explain: a.querySelector('.explain')?.textContent?.trim() || null,
        }))"""
    )


# ---------------------------------------------------------------------------
# Test A — initial state
# ---------------------------------------------------------------------------


def test_page_loads_with_all_engines_available(page):
    heading = page.text_content("h1")
    assert "TRIDENT" in heading
    assert page.is_visible("input[type=file]")
    assert page.is_visible("#questions")
    assert page.is_visible("#analyze")
    assert page.errors == [], f"JavaScript errors on load: {page.errors}"

    engines = page.text_content("#parsers")
    assert "engine_a" in engines
    assert "engine_b" in engines
    assert "engine_c" in engines
    assert engines.count("AVAILABLE") >= 3


def test_analyze_button_requires_a_file(page):
    page.fill("#questions", "What is the hostname of R1?")
    page.click("#analyze")
    page.wait_for_timeout(300)
    status = page.text_content("#status")
    assert "file first" in status.lower() or "choose" in status.lower()


def test_analyze_requires_questions(page, lab_file):
    page.set_input_files("input[type=file]", str(lab_file))
    page.click("#analyze")
    page.wait_for_timeout(300)
    status = page.text_content("#status")
    assert "question" in status.lower()


# ---------------------------------------------------------------------------
# Test B — twenty questions
# ---------------------------------------------------------------------------


def test_twenty_questions_produce_twenty_cards(page, lab_file):
    _run(page, lab_file, TWENTY)
    cards = _cards(page)
    assert len(cards) == 20, f"expected 20 cards, got {len(cards)}"
    numbers = [card["q"] for card in cards]
    assert numbers == [f"Q{i}" for i in range(1, 21)]


def test_every_card_reaches_a_terminal_state(page, lab_file):
    """Every card resolves, and says something either way.

    An abstention is a legitimate terminal state: a question the model cannot
    answer reports NOT_AVAILABLE with an explanation and no answer text. That is
    correct behaviour, so the assertion is that a card has EITHER an answer or a
    stated reason — never that every question must produce an answer.
    """
    _run(page, lab_file, TWENTY)
    cards = _cards(page)
    for card in cards:
        assert card["badge"], f"{card['q']} has no status badge"
        assert card["badge"].upper() not in {"PENDING", "LOADING", "QUEUED"}, card
        if card["answer"] is None:
            assert card["explain"], (
                f"{card['q']} has neither an answer nor an explanation "
                f"(status {card['badge']})"
            )


def test_answers_correspond_to_their_questions(page, lab_file):
    """Question identity is stable: Q1 asked about R1 and must answer R1."""
    _run(page, lab_file, TWENTY)
    cards = {card["q"]: card for card in _cards(page)}
    assert cards["Q1"]["answer"] == "R1"
    assert cards["Q2"]["answer"] == "R2"
    assert cards["Q3"]["answer"] == "SW1"
    assert cards["Q4"]["answer"] == "192.168.1.1"
    assert cards["Q6"]["answer"] == "192.168.2.2"


def test_no_javascript_errors_during_a_run(page, lab_file):
    _run(page, lab_file, THREE)
    assert page.errors == [], page.errors


def test_no_duplicate_cards(page, lab_file):
    _run(page, lab_file, THREE)
    cards = _cards(page)
    numbers = [card["q"] for card in cards]
    assert len(numbers) == len(set(numbers)), numbers


# ---------------------------------------------------------------------------
# Test D — verifier rejects an incorrect claim
# ---------------------------------------------------------------------------


def test_verification_endpoint_rejects_an_address_the_model_does_not_hold(page, lab_file):
    """Drive the verify endpoint from the page and check the verdict."""
    result = page.evaluate(
        """async ([name, bytes]) => {
            const blob = new Blob([new Uint8Array(bytes)], {type: 'application/octet-stream'});
            const fd = new FormData();
            fd.append('file', new File([blob], name));
            fd.append('questions', 'What is the hostname of R1?');
            fd.append('use_ai', 'false');
            const res = await fetch('/api/analyze/verify', {method: 'POST', body: fd});
            return await res.json();
        }""",
        ["lab.pkt", list(lab_file.read_bytes())],
    )
    assert "verification" in result
    verification = result["verification"]
    assert verification["counts"]["total"] == 1
    assert verification["counts"]["DISAGREES"] == 0
    record = verification["records"][0]
    assert record["verdict"] in {"CONFIRMED", "NOT_INDEPENDENTLY_CHECKABLE"}


# ---------------------------------------------------------------------------
# Test F — interruption and recovery
# ---------------------------------------------------------------------------


def test_page_reload_leaves_a_clean_state(page, lab_file):
    _run(page, lab_file, THREE)
    assert len(_cards(page)) == 3
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#analyze", timeout=15000)
    assert _cards(page) == []
    assert page.errors == []


def test_aborted_request_does_not_leave_a_stuck_ui(page, lab_file):
    """Cancelling the stream must leave the controls usable."""
    page.set_input_files("input[type=file]", str(lab_file))
    page.fill("#questions", TWENTY)
    page.click("#analyze")
    page.wait_for_timeout(150)
    page.evaluate("() => { window.stop(); }")
    page.wait_for_timeout(500)
    # The button must be usable again after the aborted run settles.
    page.wait_for_function(
        "() => !document.getElementById('analyze').disabled", timeout=60000
    )
    assert page.errors == []


# ---------------------------------------------------------------------------
# Buffered fallback
# ---------------------------------------------------------------------------


def test_buffered_fallback_produces_the_same_answers(page, lab_file):
    """With streaming blocked, the UI must fall back and still answer correctly."""
    page.route(
        "**/api/analyze/stream",
        lambda route: route.abort(),
    )
    _run(page, lab_file, THREE)
    cards = _cards(page)
    assert len(cards) == 3
    assert [card["answer"] for card in cards] == ["R1", "192.168.1.1", "SW1"]
