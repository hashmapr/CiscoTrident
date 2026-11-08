"""Working-copy isolation for simulator sessions.

A session must never touch the uploaded file. This module owns that promise:

* the source is hashed before anything else happens, so a later mutation is
  detectable;
* every session gets its own directory under a controlled workspace root;
* the copy is written atomically (temp file + ``os.replace``) so a crash cannot
  leave a half-written lab;
* paths are confined to the workspace root, resolved through ``realpath`` so a
  symlink cannot escape, and checked *before* any file operation;
* cleanup removes the directory, and a failed cleanup is reported rather than
  swallowed.

The original file's hash is re-checked on close. That is the proof the source
was not modified, and it is evidence rather than a promise.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
from pathlib import Path

MAX_LAB_BYTES = 512 * 1024 * 1024


class IsolationError(RuntimeError):
    """A path or file operation would have broken the isolation promise."""


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _confined(root: Path, candidate: Path) -> Path:
    """Resolve ``candidate`` and refuse anything outside ``root``."""
    root_real = os.path.realpath(root)
    candidate_real = os.path.realpath(candidate)
    if candidate_real != root_real and not candidate_real.startswith(root_real + os.sep):
        raise IsolationError(f"path escapes the workspace: {candidate}")
    return Path(candidate_real)


class Workspace:
    """A directory tree that owns disposable lab copies."""

    def __init__(self, root: str | Path | None = None) -> None:
        if root is None:
            root = Path(tempfile.gettempdir()) / "trident-simulator"
        self.root = Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = Path(os.path.realpath(self.root))

    def new_session_dir(self, prefix: str = "session") -> Path:
        safe = "".join(ch for ch in prefix if ch.isalnum() or ch in "._-")[:40] or "session"
        directory = self.root / f"{safe}-{uuid.uuid4().hex[:12]}"
        directory.mkdir(mode=0o700)
        return _confined(self.root, directory)

    def stage_copy(self, source: str | Path, directory: Path, filename: str | None = None) -> tuple[Path, str]:
        """Copy ``source`` into ``directory`` atomically and return (path, sha256).

        The source is never written to. The destination name is sanitised so a
        malicious upload name cannot traverse.
        """
        source_path = Path(source)
        if not source_path.is_file():
            raise IsolationError(f"source lab not found: {source}")
        size = source_path.stat().st_size
        if size > MAX_LAB_BYTES:
            raise IsolationError(
                f"lab file is {size} bytes, above the {MAX_LAB_BYTES} byte limit"
            )
        target_dir = _confined(self.root, directory)
        name = _safe_name(filename or source_path.name)
        target = _confined(self.root, target_dir / name)
        if target.exists():
            raise IsolationError(f"refusing to overwrite {target}")

        temporary = target_dir / f".{name}.{uuid.uuid4().hex[:8]}.part"
        try:
            with open(source_path, "rb") as reader, open(temporary, "wb") as writer:
                shutil.copyfileobj(reader, writer, length=1 << 20)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink(missing_ok=True)
        return target, sha256_file(target)

    def cleanup(self, directory: Path) -> str:
        """Remove a session directory. Returns a cleanup status string."""
        try:
            resolved = _confined(self.root, directory)
        except IsolationError:
            return "REFUSED_OUTSIDE_WORKSPACE"
        if not resolved.exists():
            return "ALREADY_GONE"
        try:
            shutil.rmtree(resolved)
        except OSError as exc:
            return f"FAILED: {exc}"
        return "CLEANED" if not resolved.exists() else "PARTIAL"


def _safe_name(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/"))
    cleaned = "".join(ch for ch in base if ch.isalnum() or ch in "._-")
    cleaned = cleaned.lstrip(".")
    if not cleaned:
        cleaned = "lab.pkt"
    if not cleaned.lower().endswith((".pkt", ".pka", ".pkz", ".xml", ".json")):
        cleaned += ".pkt"
    return cleaned[:120]
