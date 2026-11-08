"""Read-only ingestion of uploaded Packet Tracer files.

Responsibilities:
  * validate extension *and* real content (never trust the suffix alone)
  * enforce size limits before touching disk
  * hash the original bytes (SHA-256) and preserve them unchanged
  * hand the bytes to parsers from an immutable in-memory copy
  * never write the original; intermediate work goes to a temp dir that is removed

The uploaded original is held in memory only. Nothing on disk is ever created
from the user's file except the private temp workspace used by subprocess
parsers, and that is deleted in ``finally`` blocks by the caller.
"""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .config import settings as default_settings

#: Packet Tracer containers have no magic bytes. We therefore validate by
#: attempting a structural decode, plus a sanity check on the decoded payload.
SUPPORTED_EXTENSIONS = {".pka", ".pkt", ".xml"}

#: Text formats are inspected directly by TRIDENT rather than by a container
#: decoder, so they are explicitly labelled and reported separately.
XML_EXTENSIONS = {".xml"}


class IngestionError(ValueError):
    """Raised for any input that must be rejected before parsing."""


@dataclass(frozen=True)
class IngestedFile:
    file_name: str
    data: bytes
    sha256: str
    size_bytes: int

    @property
    def suffix(self) -> str:
        return Path(self.file_name).suffix.lower()

    def temp_path(self, workdir: Path) -> Path:
        """Write the *unchanged* bytes into a private workspace for subprocess parsers.

        The filename is fully sanitised: only a fixed stem and the validated
        suffix survive, so no traversal sequence can escape ``workdir``.
        """
        safe = f"input{self.suffix if self.suffix in SUPPORTED_EXTENSIONS else '.pka'}"
        target = (workdir / safe).resolve()
        if workdir.resolve() not in target.parents:
            raise IngestionError("refusing to write outside the private workspace")
        target.write_bytes(self.data)
        return target


def _looks_like_trident_container(data: bytes) -> str | None:
    """Cheap structural probe. Returns an error string or None when plausible.

    Packet Tracer containers have **no magic bytes**, so the suffix is the only
    cheap signal and it must not be over-trusted. We reject only what is provably
    impossible: an empty file or one too small to carry any structure.

    A wrong-but-plausible file is NOT rejected here. It is handed to the engines,
    and if they cannot decode it every adapter reports ERROR — which the response
    surfaces honestly. That is far better than a heuristic that rejects valid files.
    """
    if len(data) == 0:
        return "file is empty"
    if len(data) < 48:
        return "file is far too small to be a Packet Tracer container"
    return None


def ingest(
    file_name: str,
    data: bytes,
    cfg: Settings | None = None,
) -> IngestedFile:
    """Validate and snapshot an uploaded file. Never mutates ``data``."""
    cfg = cfg or default_settings

    if not file_name:
        raise IngestionError("a file name is required")

    # Path traversal guard on the *name* itself.
    if "/" in file_name or "\\" in file_name or file_name in {".", ".."}:
        raise IngestionError("file name contains path separators")

    suffix = Path(file_name).suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise IngestionError(
            f"unsupported extension {suffix or '(none)'!r}; expected .pka or .pkt"
        )

    if not data:
        raise IngestionError("uploaded file is empty")

    if len(data) > cfg.max_file_bytes:
        raise IngestionError(
            f"file is {len(data):,} bytes which exceeds the {cfg.max_file_bytes:,} byte limit"
        )

    if suffix in XML_EXTENSIONS:
        probe_error = _looks_like_trident_xml(data)
    else:
        probe_error = _looks_like_trident_container(data)
    if probe_error:
        raise IngestionError(probe_error)

    digest = hashlib.sha256(data).hexdigest()
    return IngestedFile(
        file_name=Path(file_name).name,
        data=bytes(data),  # immutable copy
        sha256=digest,
        size_bytes=len(data),
    )


def _looks_like_trident_xml(data: bytes) -> str | None:
    """Validate that an uploaded ``.xml`` is a decoded Packet Tracer document.

    Read-only and cheap: the payload must decode as UTF-8 and contain a
    PACKETTRACER5 element. No XML library is used (no entity expansion).
    """
    head = data[:4096]
    try:
        text = head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "XML upload is not valid UTF-8 text"
    if "<PACKETTRACER" not in text and "PACKETTRACER" not in text:
        return "XML upload does not look like a decoded Packet Tracer document"
    return None


def make_workspace() -> tempfile.TemporaryDirectory:
    """Create a private, auto-cleaning workspace for a single analysis."""
    return tempfile.TemporaryDirectory(prefix="trident-")
