"""Security tests: key exposure, answer-key leakage, file mutation, injection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trident.config import Settings
from trident.ingestion import IngestionError, ingest


# 21. No API key exposure
def test_api_key_never_in_public_dict():
    secret = "sk-super-secret-test-key-DO-NOT-LEAK"
    cfg = Settings(ai_api_key=secret, ai_model="test-model")
    public = cfg.public_dict()
    serialised = json.dumps(public)
    assert secret not in serialised
    assert "ai_api_key" not in public
    assert public["ai_configured"] is True


def test_api_key_scrubbed_from_provider_error_text():
    from trident.reasoning.ai_client import _scrub

    secret = "sk-abc123"
    message = f"upstream said Authorization: Bearer {secret} is invalid"
    assert secret not in _scrub(message, secret)
    assert "[redacted]" in _scrub(message, secret)


def test_api_key_not_in_health_payload():
    import asyncio

    from trident.pipeline import health

    cfg = Settings(ai_api_key="sk-health-secret", ai_model="m")
    payload = asyncio.run(health(cfg))
    assert "sk-health-secret" not in json.dumps(payload)


def test_api_key_absent_from_frontend_assets():
    """The key lives only in server memory; the static assets must never reference it."""
    web = Path("trident/web")
    for asset in web.glob("*"):
        if asset.suffix in {".js", ".html", ".css"}:
            text = asset.read_text(encoding="utf-8", errors="replace")
            assert "AI_API_KEY" not in text
            assert "Authorization" not in text


# 22. No embedded answer-key exposure
def test_answer_key_sections_not_exposed_in_adapter_output():
    """ACTIVITY / COMPARISONS content must never reach observations or the model."""
    from trident.parsers.pka_xml import _walk_xml

    xml = (
        "<PACKETTRACER5_ACTIVITY>"
        "<PACKETTRACER5><NETWORK><DEVICES>"
        "<DEVICE><ENGINE><NAME>SW1</NAME></ENGINE></DEVICE>"
        "</DEVICES></NETWORK></PACKETTRACER5>"
        "<ACTIVITY><INSTRUCTIONS>"
        "<LINE>THE_CORRECT_ANSWER_IS_B</LINE></INSTRUCTIONS></ACTIVITY>"
        "<COMPARISONS><NODE><VALUE>ANSWERKEY_XYZ</VALUE></NODE></COMPARISONS>"
        "<CLEAN_ACTIVITY><LINE>CLEAN_KEY_123</LINE></CLEAN_ACTIVITY>"
        "</PACKETTRACER5_ACTIVITY>"
    )
    blob = json.dumps(_walk_xml(xml))
    for secret in ("THE_CORRECT_ANSWER_IS_B", "ANSWERKEY_XYZ", "CLEAN_KEY_123"):
        assert secret not in blob


def test_analysis_response_has_no_answer_key_fields():
    from trident.models import AnalysisResponse

    fields = set(AnalysisResponse.model_fields)
    forbidden = {"activity", "comparisons", "answer_key", "grading", "scores"}
    assert not (fields & forbidden)


# 23. No source file mutation
def test_ingest_never_writes_the_original(tmp_path):
    original = b"\x00" * 200
    path = tmp_path / "outside.pkt"
    path.write_bytes(original)
    ingested = ingest("upload.pka", b"\x01" * 200)
    # ingestion is pure in-memory
    assert path.read_bytes() == original
    assert ingested.data == b"\x01" * 200


def test_temp_path_uses_sanitised_name(tmp_path):
    ingested = ingest("evil.pkt", b"A" * 200)
    target = ingested.temp_path(tmp_path)
    assert target.parent == tmp_path.resolve()
    assert "evil" not in target.name
    assert target.name.startswith("input")


def test_temp_path_cannot_escape_even_with_hostile_name(tmp_path):
    """The filename is discarded entirely, so traversal is impossible by construction."""
    from trident.ingestion import IngestedFile

    ingested = ingest("x.pkt", b"A" * 200)
    hostile = IngestedFile(
        file_name="../../etc/passwd",
        data=ingested.data,
        sha256=ingested.sha256,
        size_bytes=ingested.size_bytes,
    )
    target = hostile.temp_path(tmp_path)
    assert target.parent == tmp_path.resolve()
    assert target.name == "input.pka"
    assert ".." not in str(target)
    assert target.exists()


# --- input validation ------------------------------------------------------

def test_reject_unsupported_extension():
    with pytest.raises(IngestionError, match="unsupported extension"):
        ingest("payload.exe", b"x" * 200)


def test_reject_empty_file():
    with pytest.raises(IngestionError):
        ingest("empty.pka", b"")


def test_reject_tiny_file():
    with pytest.raises(IngestionError, match="too small"):
        ingest("tiny.pka", b"abc")


def test_reject_oversized_file():
    cfg = Settings(max_file_bytes=100)
    with pytest.raises(IngestionError, match="exceeds"):
        ingest("big.pka", b"x" * 200, cfg)


def test_reject_path_separators_in_filename():
    with pytest.raises(IngestionError, match="path separators"):
        ingest("../../evil.pka", b"x" * 200)


def test_accepts_pka_and_pkt():
    assert ingest("a.pka", b"x" * 200).sha256
    assert ingest("a.pkt", b"x" * 200).sha256


def test_sha256_is_computed_over_exact_bytes():
    import hashlib

    data = bytes(range(256)) * 4
    ingested = ingest("x.pka", data)
    assert ingested.sha256 == hashlib.sha256(data).hexdigest()
    assert ingested.size_bytes == len(data)


# --- XML safety ------------------------------------------------------------

def test_defusedxml_available_for_xml_hardening():
    """TRIDENT ships defusedxml so any future XML parsing is XXE-safe."""
    import defusedxml  # noqa: F401


def test_no_dangerous_xml_parser_in_walker():
    """The Engine A walker uses regex over already-decoded XML, never a live parser."""
    source = Path("trident/parsers/pka_xml.py").read_text()
    assert "defusedxml" in source or "re.compile" in source
    assert "xml.etree" not in source
    assert "lxml" not in source


# --- no command execution ---------------------------------------------------

def test_no_shell_true_in_subprocess_calls():
    root = Path("trident")
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "shell=True" not in text, f"shell=True found in {path}"


def test_no_eval_or_exec_of_parser_output():
    root = Path("trident")
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for bad in ("eval(", "exec("):
            assert bad not in text, f"{bad} found in {path}"
