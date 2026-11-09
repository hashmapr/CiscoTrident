"""Independent Packet Tracer container codec.

A ``.pkt``/``.pka`` file, outside in:

1. **layer A** — byte reversal combined with a positional XOR
2. **AEAD** — Twofish/Serpent/CAST-256 in Crypto++'s EAX variant, fixed key/IV
3. **layer B** — XOR each byte with ``(len - i)``
4. **qCompress** — 4-byte big-endian length prefix, then zlib
5. **UTF-8 XML**

There is no magic header: the first bytes are noise, so a container is
identified by trying each candidate key schedule and accepting it only when the
EAX tag verifies. That is a cryptographic oracle with a 2^-128 false-positive
rate, so detection is both necessary and conclusive.

Why this exists alongside ``pkt-core``: that library is GPL-3.0. Having TRIDENT's
own decoder means the application does not inherit copyleft obligations merely by
reading its own input files, and it removes an external dependency from the hot
path. Both implementations are kept in the tree and cross-checked against each
other in tests, which is a stronger correctness argument than either alone.

The formats and key bytes below are published in Packet Tracer interoperability
documentation. No code is copied from another implementation.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .eax import TagMismatch, eax_open, eax_seal
from .twofish import Twofish

#: Key schedules per container flavour. ``key_byte`` and ``iv_byte`` are repeated
#: sixteen times; the fixed pair is what makes the keystream file-independent.
FORMATS: Final[dict[str, tuple[str, int, int, str]]] = {
    "pkt": ("twofish", 0x89, 0x10, ".pkt and .pka save files"),
    "log": ("twofish", 0xBA, 0xBE, "internal log files"),
    "pkc": ("serpent128", 0xAB, 0x23, "PKC saves"),
    "pta": ("serpent128", 0xAB, 0xCD, "activity files"),
    "sm": ("cast256", 0x12, 0xFE, "saved simulations"),
    "userapp": ("cast256", 0xF1, 0x1F, "user applications"),
}

#: Detection order. The two Twofish flavours are tried first because they are by
#: far the most common; each candidate is confirmed by its tag, not by its order.
DETECT_ORDER: Final[tuple[str, ...]] = ("pkt", "log", "pkc", "pta", "sm", "userapp")

TAG_SIZE: Final[int] = 16
BLOCK_SIZE: Final[int] = 16
MAX_PLAUSIBLE_XML: Final[int] = 1 << 31


class ContainerError(ValueError):
    """The bytes are not a container this module can open."""


class IntegrityError(ContainerError):
    """A candidate format's authentication tag did not verify."""


def layer_a(data: bytes) -> bytes:
    """Outer scramble, file bytes to AEAD input.

    ``C[i] = F[n-1-i] ^ ((n * (1-i)) & 0xFF)``. This is **not** an involution:
    the reversal makes the inverse a separate formula, which is
    :func:`layer_a_inverse`. Using the forward function on the write path
    produces a file that decrypts to the right length and the wrong content.
    """
    n = len(data)
    return bytes(data[n - 1 - i] ^ ((n * (1 - i)) & 0xFF) for i in range(n))


def layer_a_inverse(data: bytes) -> bytes:
    """AEAD input back to file bytes: ``F[j] = C[n-1-j] ^ ((n*(1-(n-1-j))) & 0xFF)``."""
    n = len(data)
    return bytes(
        data[n - 1 - j] ^ ((n * (1 - (n - 1 - j))) & 0xFF) for j in range(n)
    )


def layer_b(data: bytes) -> bytes:
    """Inner obfuscation: ``XOR byte i with (len - i)``. Self-inverse."""
    n = len(data)
    return bytes(value ^ ((n - i) & 0xFF) for i, value in enumerate(data))


def quncompress(payload: bytes) -> bytes:
    """Undo Qt's ``qCompress``: 4-byte big-endian size, then a zlib stream."""
    if len(payload) < 4:
        raise ContainerError("qCompress payload is shorter than its length prefix")
    declared = struct.unpack(">I", payload[:4])[0]
    if declared > MAX_PLAUSIBLE_XML:
        raise ContainerError(f"implausible uncompressed length {declared}")
    try:
        inflated = zlib.decompress(payload[4:])
    except zlib.error as exc:
        raise ContainerError(f"zlib stream is corrupt: {exc}") from exc
    if len(inflated) != declared:
        # Qt rejects this too; it is a cheap corruption check.
        raise ContainerError(
            f"length mismatch: prefix says {declared}, inflated to {len(inflated)}"
        )
    return inflated


#: Qt's qCompress uses zlib's default level (6), not maximum. Using 9 produces a
#: smaller file that is *not* byte-identical to what Packet Tracer writes, which
#: breaks round-trip equality even though the content is the same.
QCOMPRESS_LEVEL: Final[int] = 6


def qcompress(xml: bytes) -> bytes:
    """Apply Qt's ``qCompress`` framing."""
    return struct.pack(">I", len(xml)) + zlib.compress(xml, QCOMPRESS_LEVEL)


def _cipher_for(name: str):
    """Construct the block cipher for a format.

    Only Twofish is implemented here. Serpent and CAST-256 flavours are declared
    so detection reports an honest ``UNSUPPORTED`` instead of a confusing tag
    failure, and so adding them later needs no interface change.
    """
    cipher_name = FORMATS[name][0]
    if cipher_name == "twofish":
        return Twofish
    raise ContainerError(
        f"{name} uses {cipher_name}, which this decoder does not implement yet"
    )


@dataclass(frozen=True)
class Container:
    """A decoded container."""

    xml: bytes
    format_name: str
    raw: bytes

    @property
    def root_tag(self) -> str:
        head = self.xml[:400].decode("utf-8", "replace")
        start, end = head.find("<"), head.find(">")
        if start < 0 or end <= start:
            return "?"
        return head[start + 1 : end].split()[0].rstrip("/")

    @property
    def is_activity(self) -> bool:
        return self.root_tag.upper().endswith("_ACTIVITY")


def decode_bytes(raw: bytes, format_name: str | None = None) -> Container:
    """Decode a container, or raise :class:`ContainerError`.

    With ``format_name=None`` every candidate is tried and the first whose tag
    verifies wins. A tag mismatch on a *specified* format is an integrity error,
    not a fallthrough: if the caller says which format a file is, a failure to
    authenticate that format must be reported, never silently retried as another.
    """
    if len(raw) <= TAG_SIZE:
        raise ContainerError(f"file is {len(raw)} bytes; too short to be a container")

    candidates = (format_name,) if format_name else DETECT_ORDER
    unsupported: list[str] = []
    authenticated_attempts = 0
    for name in candidates:
        if name not in FORMATS:
            raise ContainerError(f"unknown container format {name!r}")
        try:
            cipher_class = _cipher_for(name)
        except ContainerError as exc:
            unsupported.append(str(exc))
            if format_name:
                raise
            continue

        key = bytes([FORMATS[name][1]]) * BLOCK_SIZE
        iv = bytes([FORMATS[name][2]]) * BLOCK_SIZE
        scrambled = layer_a(raw)
        body, tag = scrambled[:-TAG_SIZE], scrambled[-TAG_SIZE:]
        try:
            plaintext = eax_open(cipher_class(key), iv, body, tag)
        except TagMismatch:
            authenticated_attempts += 1
            if format_name:
                raise IntegrityError(
                    f"{name} authentication failed: the file is corrupt or is not a "
                    f"{name} container"
                ) from None
            continue
        xml = quncompress(layer_b(plaintext))
        return Container(xml=xml, format_name=name, raw=raw)

    # Every supported (Twofish) candidate was tried and its tag failed. The file
    # is corrupt or not a container. Reporting "unsupported flavour" here would
    # be misleading: the flavours were supported, the bytes were not valid. The
    # unimplemented Serpent/CAST flavours are still mentioned, because a caller
    # with such a file deserves to know it cannot be checked yet.
    if authenticated_attempts:
        note = (
            f"; {len(unsupported)} other flavour(s) are not implemented yet"
            if unsupported
            else ""
        )
        raise IntegrityError(
            "no supported container format authenticated these bytes; the file is "
            f"corrupt, truncated, or not a Packet Tracer save{note}"
        )
    detail = f" ({'; '.join(unsupported)})" if unsupported else ""
    raise ContainerError(f"not a Packet Tracer container, or an unsupported flavour{detail}")


def decode(path: str | Path, format_name: str | None = None) -> Container:
    return decode_bytes(Path(path).read_bytes(), format_name)


def encode_bytes(xml: bytes, format_name: str = "pkt") -> bytes:
    """Seal XML back into a container. Used by round-trip tests."""
    if format_name not in FORMATS:
        raise ContainerError(f"unknown container format {format_name!r}")
    cipher_class = _cipher_for(format_name)
    key = bytes([FORMATS[format_name][1]]) * BLOCK_SIZE
    iv = bytes([FORMATS[format_name][2]]) * BLOCK_SIZE
    payload = layer_b(qcompress(xml))
    ciphertext, tag = eax_seal(cipher_class(key), iv, payload)
    # The write path needs the inverse of the read scramble, not the scramble.
    return layer_a_inverse(ciphertext + tag)


def is_container(path: str | Path) -> bool:
    """Cheap check: does this file open as a container at all?"""
    try:
        decode(path)
    except (ContainerError, OSError):
        return False
    return True


__all__ = [
    "BLOCK_SIZE",
    "DETECT_ORDER",
    "FORMATS",
    "TAG_SIZE",
    "Container",
    "ContainerError",
    "IntegrityError",
    "decode",
    "decode_bytes",
    "encode_bytes",
    "is_container",
    "layer_a",
    "layer_a_inverse",
    "layer_b",
    "qcompress",
    "quncompress",
]
