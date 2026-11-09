"""Independent Packet Tracer container decoding.

Implements Twofish, Crypto++ EAX and the ``.pkt``/``.pka`` container format from
published specifications, so TRIDENT can read its own input files without a
GPL-3.0 dependency.

Public surface:

* :func:`decode` / :func:`decode_bytes` — open a container to its XML.
* :func:`encode_bytes` — seal XML back, for round-trip verification.
* :class:`Container` — the decoded document plus which format produced it.

Correctness is established two ways: official cipher test vectors, and
byte-for-byte agreement with ``pkt-core`` on real lab files. Both are checked in
``tests/test_pktcrypto.py``.
"""

from .container import (
    Container,
    ContainerError,
    IntegrityError,
    decode,
    decode_bytes,
    encode_bytes,
    is_container,
)
from .eax import TagMismatch
from .twofish import Twofish

__all__ = [
    "Container",
    "ContainerError",
    "IntegrityError",
    "TagMismatch",
    "Twofish",
    "decode",
    "decode_bytes",
    "encode_bytes",
    "is_container",
]
