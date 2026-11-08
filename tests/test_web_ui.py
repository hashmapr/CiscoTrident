"""Static-asset tests for the TRIDENT web UI (no browser required).

These assert the security and feature contract of the served static files:
escaping of server data, no data-built script tags, the evidence panel, the
shared-decoder caveat, and the six verification status badges.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from trident.server import app

WEB_DIR = Path(__file__).resolve().parents[1] / "trident" / "web"
APP_JS = WEB_DIR / "app.js"
INDEX_HTML = WEB_DIR / "index.html"
STYLE_CSS = WEB_DIR / "style.css"

STATUSES = [
    "VERIFIED",
    "VERIFIED_DERIVED",
    "INCOMPLETE",
    "CONFLICT",
    "NOT_AVAILABLE",
    "ERROR",
]


@pytest.fixture(scope="module")
def app_js() -> str:
    return APP_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def index_html() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def style_css() -> str:
    return STYLE_CSS.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# XSS safety
# ---------------------------------------------------------------------------


def test_app_js_has_escape_helper(app_js: str) -> None:
    assert re.search(r"function\s+escapeHtml\s*\(", app_js), "escapeHtml helper is missing"
    # All five dangerous characters must be handled.
    for ch in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert ch in app_js, f"escapeHtml does not map {ch}"


def _inner_html_assignments(js: str) -> list[str]:
    """Return the right-hand sides of every `innerHTML = ...` assignment."""
    return re.findall(r"\.innerHTML\s*=\s*(.+?);", js, flags=re.DOTALL)


def test_no_unescaped_innerhtml(app_js: str) -> None:
    assignments = _inner_html_assignments(app_js)
    for rhs in assignments:
        stripped = rhs.strip()
        is_static_template = bool(re.fullmatch(r"``|`[^`$]*`|\"\"|''", stripped))
        uses_escape = "escapeHtml(" in stripped
        assert is_static_template or uses_escape, (
            "innerHTML assigned non-escaped data: " + stripped[:200]
        )


def test_results_renderer_avoids_innerhtml(app_js: str) -> None:
    """The per-answer renderer must build nodes, never inject HTML strings."""
    start = app_js.find("function renderResult(")
    assert start != -1, "renderResult is missing"
    end = app_js.find("/* ---------- exports ---------- */", start)
    assert end > start
    renderer = app_js[start:end]
    assert "innerHTML" not in renderer, "renderResult/renderEvidence must not use innerHTML"
    for helper in ("renderEvidence", "renderEvidenceItem"):
        assert helper in renderer, f"{helper} should render the evidence panel"


def test_no_script_tags_built_from_data(app_js: str) -> None:
    assert not re.search(r"createElement\(\s*[\"']script[\"']\s*\)", app_js), (
        "app.js must not create <script> elements"
    )
    assert "<script" not in app_js.lower(), "app.js must not construct script markup"
    for dangerous in ("insertAdjacentHTML", "outerHTML", "document.write"):
        assert dangerous not in app_js, f"app.js must not use {dangerous}"


def test_text_nodes_used_for_server_values(app_js: str) -> None:
    # Server-derived values are set through textContent / createTextNode.
    assert "textContent" in app_js
    assert "createTextNode" in app_js


# ---------------------------------------------------------------------------
# Structure / features in index.html
# ---------------------------------------------------------------------------


def test_index_has_evidence_panel(index_html: str) -> None:
    assert re.search(r'id="evidence-panel"', index_html), "evidence panel container missing"
    assert re.search(r'id="results"', index_html), "results container missing"


def test_index_has_decoder_caveat(index_html: str) -> None:
    assert re.search(r'id="decoder-caveat"', index_html), "decoder caveat element missing"
    assert re.search(r'id="results-header"', index_html), "results header missing"
    assert "Twofish-EAX" in index_html, "decoder caveat copy missing"
    assert "extraction-level" in index_html


def test_caveat_is_gated_on_crypto_shared(app_js: str) -> None:
    assert "crypto_shared" in app_js, "caveat must be conditional on crypto_shared"
    assert "decoder-caveat" in app_js, "renderer must toggle the decoder caveat element"


def test_existing_controls_preserved(index_html: str) -> None:
    for element_id in ("file", "questions", "useai", "fileinfo", "analyze", "copy"):
        assert re.search(rf'id="{element_id}"', index_html), f"#{element_id} was removed"


def test_evidence_details_are_collapsed(app_js: str) -> None:
    # <details> without an `open` attribute renders collapsed by default.
    assert 'el("details"' in app_js, "evidence should use a <details> element"
    assert "open:" not in app_js, "evidence details must not force-open"
    assert ".open = true" not in app_js, "evidence details must not force-open"


# ---------------------------------------------------------------------------
# Status badges / card fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", STATUSES)
def test_badge_style_for_each_status(style_css: str, status: str) -> None:
    assert f".badge.{status}" in style_css, f"missing badge colour for {status}"
    assert f".result.{status}" in style_css, f"missing result border colour for {status}"


def test_all_six_statuses_declared(app_js: str) -> None:
    match = re.search(r"const\s+STATUS_BADGES\s*=\s*\[(.*?)\]", app_js, flags=re.DOTALL)
    assert match, "STATUS_BADGES list missing"
    block = match.group(1)
    for status in STATUSES:
        assert f'"{status}"' in block, f"{status} missing from STATUS_BADGES"


def test_card_shows_families_and_snapshot(app_js: str) -> None:
    assert "families" in app_js, "answer card must show agreeing families"
    assert "/${required} families" in app_js or "families`" in app_js
    assert "snapshot" in app_js, "answer card must show the snapshot id"
    assert "meta.snapshot_id" in app_js


def test_evidence_item_renders_fields(app_js: str) -> None:
    start = app_js.find("function renderEvidenceItem(")
    assert start != -1
    chunk = app_js[start:]
    for token in ("e.device", "e.interface", "e.field", "e.value", "raw_evidence"):
        assert token in chunk, f"evidence renderer missing {token}"
    assert "extraction_paths" in chunk, "evidence renderer must show extraction paths"
    assert "family" in chunk, "extraction family name should be surfaced"


def test_hardware_model_structural_path(app_js: str) -> None:
    assert "hardware_model" in app_js
    assert "DEVICE/ENGINE/TYPE/@model" in app_js, "structural source path for hardware questions"


def test_conflicts_and_missing_distinct(app_js: str, style_css: str) -> None:
    assert "conflict-list" in app_js and "missing-list" in app_js
    assert ".conflict-list" in style_css and ".missing-list" in style_css
    assert "Conflicts" in app_js and "Missing evidence" in app_js


# ---------------------------------------------------------------------------
# Served routes
# ---------------------------------------------------------------------------


def test_static_assets_served() -> None:
    client = TestClient(app)
    assert client.get("/").status_code == 200
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "escapeHtml" in js.text
    css = client.get("/static/style.css")
    assert css.status_code == 200
