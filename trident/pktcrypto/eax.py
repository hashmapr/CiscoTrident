"""EAX authenticated encryption, matching Crypto++'s variant.

Packet Tracer seals containers with ``CryptoPP::EAX_Final``. Crypto++'s EAX
differs from the textbook presentation in one important place, and getting it
wrong produces files that look plausible and fail the tag check:

* the nonce is ``CMAC_K(0^128 || IV)`` — a zero block **concatenated** with the
  IV, not ``CMAC_K(IV)``;
* the keystream is CTR with a big-endian full-width counter starting at that
  nonce value;
* the tag is ``N ^ CMAC_K(0x02-block || ciphertext) ^ CMAC_K(0x01-block)``.

This implementation is written from that description plus RFC 4493 (CMAC) and
the EAX paper (Bellare, Rogaway, Wagner 2004). Only the forward cipher is used,
which is why :mod:`trident.pktcrypto.twofish` needs no decryption routine.

Correctness is checked against the reference implementation over real container
files in ``tests/test_pktcrypto.py``.
"""

from __future__ import annotations

from typing import Final, Protocol

BLOCK_SIZE: Final[int] = 16
_RB: Final[int] = 0x87
_FULL_MASK: Final[int] = (1 << 128) - 1


class BlockCipher(Protocol):
    """A 128-bit block cipher exposing forward encryption only."""

    def encrypt_block(self, block: bytes) -> bytes: ...


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _dbl(block: bytes) -> bytes:
    """Multiply by x in GF(2^128) with the EAX reduction polynomial."""
    value = int.from_bytes(block, "big")
    carry = value >> 127
    value = ((value << 1) & _FULL_MASK) ^ (_RB if carry else 0)
    return value.to_bytes(BLOCK_SIZE, "big")


def cmac(cipher: BlockCipher, message: bytes) -> bytes:
    """CMAC per RFC 4493."""
    zero = bytes(BLOCK_SIZE)
    k1 = _dbl(cipher.encrypt_block(zero))
    k2 = _dbl(k1)

    if message and len(message) % BLOCK_SIZE == 0:
        blocks = [message[i : i + BLOCK_SIZE] for i in range(0, len(message), BLOCK_SIZE)]
        padded = _xor(blocks[-1], k1)
        body = blocks[:-1]
    else:
        remainder = message[len(message) - len(message) % BLOCK_SIZE :]
        padded_input = remainder + b"\x80" + bytes(BLOCK_SIZE - len(remainder) - 1)
        padded = _xor(padded_input, k2)
        body = [
            message[i : i + BLOCK_SIZE]
            for i in range(0, len(message) - len(remainder), BLOCK_SIZE)
        ]

    state = zero
    for block in body:
        state = cipher.encrypt_block(_xor(state, block))
    return cipher.encrypt_block(_xor(state, padded))


def ctr_crypt(cipher: BlockCipher, nonce: bytes, data: bytes) -> bytes:
    """CTR mode with a big-endian full-width counter beginning at ``nonce``."""
    counter = int.from_bytes(nonce, "big")
    out = bytearray(len(data))
    offset = 0
    while offset < len(data):
        stream = cipher.encrypt_block(counter.to_bytes(BLOCK_SIZE, "big"))
        chunk = data[offset : offset + BLOCK_SIZE]
        out[offset : offset + len(chunk)] = _xor(chunk, stream[: len(chunk)])
        offset += BLOCK_SIZE
        counter = (counter + 1) & _FULL_MASK
    return bytes(out)


def _domain_block(value: int) -> bytes:
    """A 16-byte block whose final byte is a domain separator."""
    return bytes(BLOCK_SIZE - 1) + bytes([value])


def eax_nonce(cipher: BlockCipher, iv: bytes) -> bytes:
    """Crypto++'s nonce derivation: ``CMAC(0^128 || IV)``."""
    return cmac(cipher, bytes(BLOCK_SIZE) + iv)


def eax_seal(cipher: BlockCipher, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt and authenticate. Returns ``(ciphertext, tag)``."""
    nonce = eax_nonce(cipher, iv)
    ciphertext = ctr_crypt(cipher, nonce, plaintext)
    tag = _xor(
        _xor(nonce, cmac(cipher, _domain_block(2) + ciphertext)),
        cmac(cipher, _domain_block(1)),
    )
    return ciphertext, tag


def eax_open(cipher: BlockCipher, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Authenticate and decrypt. Raises :class:`TagMismatch` on a bad tag.

    The tag is verified **before** any plaintext is returned, so a corrupted or
    wrong-format file can never yield partial output that looks valid.
    """
    if len(tag) != BLOCK_SIZE:
        raise TagMismatch(f"tag must be {BLOCK_SIZE} bytes, got {len(tag)}")
    nonce = eax_nonce(cipher, iv)
    expected = _xor(
        _xor(nonce, cmac(cipher, _domain_block(2) + ciphertext)),
        cmac(cipher, _domain_block(1)),
    )
    if expected != tag:
        raise TagMismatch("EAX tag mismatch: the file is corrupt or a different format")
    return ctr_crypt(cipher, nonce, ciphertext)


class TagMismatch(ValueError):
    """The authentication tag did not verify."""


__all__ = [
    "BLOCK_SIZE",
    "BlockCipher",
    "TagMismatch",
    "cmac",
    "ctr_crypt",
    "eax_nonce",
    "eax_open",
    "eax_seal",
]
