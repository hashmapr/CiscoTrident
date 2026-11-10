"""TRIDENT configuration.

All settings come from environment variables (loaded from ``.env`` at the repo
root by python-dotenv). Secrets are never logged and never serialised into a
response payload.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv is a declared dependency
    def load_dotenv(*_a, **_k):  # type: ignore
        return False

REPO_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(REPO_ROOT / ".env")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


#: The three strict-consensus policy modes.
#: ``strict``      -> 3/3 distinct extraction families required for VERIFIED.
#: ``two_engine``  -> 2/2 agreement (only when exactly 2 engines are available).
#: ``deterministic`` -> derived values from a single verified input are VERIFIED_DERIVED.
CONSENSUS_POLICIES = ("strict", "two_engine", "deterministic")


@dataclass(frozen=True)
class Settings:
    """Runtime settings. Frozen so it cannot be mutated after import."""

    host: str = field(default_factory=lambda: os.environ.get("TRIDENT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("TRIDENT_PORT", 8000))

    # --- AI provider (OpenAI-compatible) ---
    ai_api_key: str = field(default_factory=lambda: os.environ.get("AI_API_KEY", "").strip())
    ai_base_url: str = field(
        default_factory=lambda: os.environ.get("AI_BASE_URL", "https://api.openai.com/v1").strip()
    )
    ai_model: str = field(default_factory=lambda: os.environ.get("AI_MODEL", "").strip())
    ai_temperature: float = field(default_factory=lambda: _env_float("AI_TEMPERATURE", 0.0))
    ai_timeout: float = field(default_factory=lambda: _env_float("AI_TIMEOUT", 60.0))
    ai_max_tokens: int = field(default_factory=lambda: _env_int("AI_MAX_TOKENS", 1200))
    #: Questions per AI request. Bounded so a 65-100 question batch cannot be
    #: truncated mid-JSON; larger batches are chunked automatically.
    ai_batch_size: int = field(default_factory=lambda: _env_int("AI_BATCH_SIZE", 12))

    # --- ingestion limits ---
    max_file_bytes: int = field(default_factory=lambda: _env_int("TRIDENT_MAX_FILE_BYTES", 64 * 1024 * 1024))
    max_xml_bytes: int = field(default_factory=lambda: _env_int("TRIDENT_MAX_XML_BYTES", 256 * 1024 * 1024))
    #: Reject decoded payloads that inflate more than this multiple of the input.
    max_decompression_ratio: int = field(
        default_factory=lambda: _env_int("TRIDENT_MAX_DECOMPRESSION_RATIO", 200)
    )
    max_questions: int = field(default_factory=lambda: _env_int("TRIDENT_MAX_QUESTIONS", 500))
    #: Answers resolved concurrently. Bounded so a large paste cannot spawn one
    #: task per question and exhaust memory; four keeps the event loop
    #: responsive on a 16 GB machine while letting fast questions finish early.
    max_concurrency: int = field(default_factory=lambda: _env_int("TRIDENT_MAX_CONCURRENCY", 4))
    max_question_chars: int = field(default_factory=lambda: _env_int("TRIDENT_MAX_QUESTION_CHARS", 8_000))

    # --- parser execution ---
    parser_timeout: float = field(default_factory=lambda: _env_float("TRIDENT_PARSER_TIMEOUT", 90.0))
    consensus_policy: str = field(
        default_factory=lambda: os.environ.get("TRIDENT_CONSENSUS_POLICY", "strict").strip().lower()
    )

    # --- engine C (pt-convert) external integration ---
    pt_convert_dir: str = field(
        default_factory=lambda: os.environ.get("TRIDENT_PT_CONVERT_DIR", "").strip()
    )
    node_binary: str = field(default_factory=lambda: os.environ.get("TRIDENT_NODE", "node").strip() or "node")

    # --- engine A native library ---
    libtwofish: str = field(default_factory=lambda: os.environ.get("LIBTWOFISH", "").strip())

    # --- local test corpus (read-only; never uploaded) ---
    test_corpus_dir: str = field(
        default_factory=lambda: os.environ.get("TRIDENT_TEST_CORPUS_DIR", "").strip()
    )

    def __post_init__(self) -> None:
        if self.consensus_policy not in CONSENSUS_POLICIES:
            object.__setattr__(self, "consensus_policy", "strict")

    @property
    def ai_configured(self) -> bool:
        return bool(self.ai_api_key and self.ai_model)

    def public_dict(self) -> dict:
        """Safe-to-expose settings. Never includes the API key."""
        return {
            "host": self.host,
            "port": self.port,
            "ai_configured": self.ai_configured,
            "ai_model": self.ai_model or None,
            "ai_base_url": self.ai_base_url or None,
            "ai_temperature": self.ai_temperature,
            "ai_batch_size": self.ai_batch_size,
            "consensus_policy": self.consensus_policy,
            "max_file_bytes": self.max_file_bytes,
            "max_questions": self.max_questions,
            "max_concurrency": self.max_concurrency,
            "parser_timeout": self.parser_timeout,
            "pt_convert_configured": bool(self.pt_convert_dir),
            "test_corpus_configured": bool(self.test_corpus_dir),
        }


settings = Settings()
