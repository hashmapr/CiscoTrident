"""Analyze Mode in a real browser: one button, no questions.

The user experience this validates: upload a file, press Analyze Network, and get
an overview plus a section for every device, with honest status markers.
"""

from __future__ import annotations

import pytest
from browser_fixtures import start_server, stop_server

pytestmark = pytest.mark.browser

__all__: list[str] = []


@pytest.fixture(scope="module")
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        instance = pw.chromium.launch()
        yield instance
        instance.close()


@pytest.fixture(scope="module")
def server():
    process, base = start_server()
    yield base
    stop_server(process)


@pytest.fixture()
def page(browser, server, tmp_path):
    from pathlib import Path

    fixture = Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not fixture.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    lab = tmp_path / "lab.pkt"
    lab.write_bytes(fixture.read_bytes())

    context = browser.new_context()
    pg = context.new_page()
    errors: list[str] = []
    pg.on("pageerror", lambda exc: errors.append(str(exc)))
    pg.errors = errors  # type: ignore[attr-defined]
    pg.goto(server, wait_until="domcontentloaded")
    pg.wait_for_selector("#analyze-network", timeout=15000)
    pg.lab = lab  # type: ignore[attr-defined]
    yield pg
    context.close()


def test_analyze_network_button_exists_and_needs_no_questions(page):
    assert page.is_visible("#analyze-network")
    # The questions box may be empty; the button must still be present and usable.
    assert page.input_value("#questions") == ""


def test_analyze_without_questions_produces_a_full_report(page):
    page.set_input_files("input[type=file]", str(page.lab))
    page.click("#analyze-network")
    page.wait_for_function(
        """() => {
            const s = document.getElementById('status')?.textContent || '';
            return s.startsWith('Analyzed') || s.startsWith('Failed');
        }""",
        timeout=60000,
    )
    status = page.text_content("#status")
    assert status.startswith("Analyzed"), status

    sections = page.evaluate(
        "() => document.querySelectorAll('#device-sections .device-section').length"
    )
    assert sections == 7, f"expected 7 device sections, got {sections}"
    assert page.errors == []


def test_overview_shows_device_and_link_counts(page):
    page.set_input_files("input[type=file]", str(page.lab))
    page.click("#analyze-network")
    page.wait_for_function(
        "() => document.querySelectorAll('#device-sections .device-section').length > 0",
        timeout=60000,
    )
    overview = page.text_content("#network-overview")
    assert "Network overview" in overview
    assert "Devices" in overview
    assert "Physical links" in overview


def test_every_device_heading_is_present(page):
    page.set_input_files("input[type=file]", str(page.lab))
    page.click("#analyze-network")
    page.wait_for_function(
        "() => document.querySelectorAll('#device-sections .device-section').length > 0",
        timeout=60000,
    )
    headings = page.evaluate(
        "() => Array.from(document.querySelectorAll('#device-sections .device-section h2')).map(h => h.textContent.trim())"
    )
    assert any("R1" in h for h in headings)
    assert any("SW1" in h for h in headings)
    assert any("PC-A" in h for h in headings)
    for heading in headings:
        assert " — " in heading, heading


def test_common_questions_section_is_rendered(page):
    page.set_input_files("input[type=file]", str(page.lab))
    page.click("#analyze-network")
    page.wait_for_function(
        "() => document.querySelectorAll('#device-sections .device-section details.questions').length > 0",
        timeout=60000,
    )
    count = page.evaluate(
        "() => document.querySelectorAll('#device-sections details.questions').length"
    )
    assert count >= 7


def test_unsupported_checks_are_listed_honestly(page):
    page.set_input_files("input[type=file]", str(page.lab))
    page.click("#analyze-network")
    page.wait_for_function(
        "() => document.querySelectorAll('#device-sections .device-section').length > 0",
        timeout=60000,
    )
    coverage = page.text_content("#network-coverage")
    assert "What was not checked" in coverage
    assert "not proof that the network is correct" in coverage


def test_export_produces_markdown_text(page):
    page.set_input_files("input[type=file]", str(page.lab))
    page.select_option("#analyze-export", "markdown")
    page.click("#analyze-network")
    page.wait_for_function(
        """() => {
            const s = document.getElementById('status')?.textContent || '';
            return s.startsWith('Report exported') || s.startsWith('Failed');
        }""",
        timeout=60000,
    )
    body = page.text_content(".export-body")
    assert body.startswith("# TRIDENT Network Analysis")
    assert "## Router — R1" in body
    assert page.errors == []
