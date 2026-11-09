"""Twofish block cipher, implemented from the published specification.

Twofish is the cipher Packet Tracer uses for ``.pkt``/``.pka`` containers. This
is an independent implementation written from Schneier, Kelsey, Whiting, Wagner,
Hall and Ferguson, *The Twofish Encryption Algorithm: A 128-Bit Block Cipher*
(1998), sections 4.2 (MDS matrix) and 4.3 (key schedule, h and g functions).
No code is copied from another implementation; it is derived from the paper so
TRIDENT can decode its own files without a GPL dependency.

Only encryption is needed: the container uses EAX, which builds CTR mode and
CMAC from the forward cipher alone.

Correctness is checked against the official Twofish test vectors in
``tests/test_pktcrypto.py``.
"""

from __future__ import annotations

from typing import Final

MASK32: Final[int] = 0xFFFFFFFF

#: Reed-Solomon matrix over GF(2^8) with polynomial 0x169 (Twofish section 4.2).
_MDS: Final[tuple[tuple[int, ...], ...]] = (
    (0x01, 0xEF, 0x5B, 0x5B),
    (0x5B, 0xEF, 0xEF, 0x01),
    (0xEF, 0x5B, 0x01, 0xEF),
    (0xEF, 0x01, 0xEF, 0x5B),
)

#: The single 8x8 MDS used inside the h function's q permutations.
_RS: Final[tuple[tuple[int, ...], ...]] = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
    (0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03, 0xA4),
    (0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03, 0xA4, 0x55),
    (0x5A, 0x58, 0xDB, 0x9E, 0x03, 0xA4, 0x55, 0x87),
    (0x58, 0xDB, 0x9E, 0x03, 0xA4, 0x55, 0x87, 0x5A),
)


def _build_q(t0, t1, t2, t3) -> tuple[int, ...]:
    """Expand four 4-bit permutations into one 8-bit q permutation.

    Twofish section 4.3.1 defines q as two rounds of nibble substitution, each
    preceded by a keyed nibble mixing step. The mixing step is:

        a' = a XOR b
        b' = a XOR ROR4(b, 1) XOR (8 * a mod 16)

    ``ROR4(b, 1)`` is the 4-bit rotate. The 4-bit tables t0..t3 are the published
    constants from the paper's appendix; the composition is the part that has to
    be right.
    """

    def mix(a: int, b: int) -> tuple[int, int]:
        b_rot = ((b >> 1) | ((b & 1) << 3)) & 0x0F
        return (a ^ b) & 0x0F, (a ^ b_rot ^ ((8 * a) & 0x0F)) & 0x0F

    table = [0] * 256
    for value in range(256):
        a0, b0 = (value >> 4) & 0x0F, value & 0x0F
        a1, b1 = mix(a0, b0)
        a2, b2 = t0[a1], t1[b1]
        a3, b3 = mix(a2, b2)
        a4, b4 = t2[a3], t3[b3]
        table[value] = ((b4 << 4) | a4) & 0xFF
    return tuple(table)


#: The eight 4-bit permutations published with the cipher (paper appendix).
_Q0_T = (
    (0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4),
    (0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD),
    (0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1),
    (0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA),
)
_Q1_T = (
    (0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5),
    (0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8),
    (0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF),
    (0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA),
)


def _q_permutations() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """The two 8-bit q permutations used by the h function."""
    return _build_q(*_Q0_T), _build_q(*_Q1_T)


_Q0, _Q1 = _q_permutations()

#: Multiplication tables for the h function's GF(2^8) operations.
_MUL = {}
for _m in (0x01, 0x5B, 0xEF):
    row = []
    for _v in range(256):
        _acc = 0
        _x, _y = _v, _m
        while _y:
            if _y & 1:
                _acc ^= _x
            _x <<= 1
            if _x & 0x100:
                _x ^= 0x169
            _y >>= 1
        row.append(_acc & 0xFF)
    _MUL[_m] = tuple(row)


#: Which q permutation to apply at each depth, per key length and byte
#: position. Table 4 of the paper: the chains alternate q0/q1 differently for
#: even and odd byte positions and depend on the number of key words.
_Q_CHAINS: Final[dict[tuple[int, int], tuple[int, ...]]] = {
    (2, 0): (0, 0, 1),
    (2, 1): (1, 0, 0),
    (2, 2): (0, 1, 1),
    (2, 3): (1, 1, 0),
    (3, 0): (1, 0, 0, 1),
    (3, 1): (1, 1, 0, 0),
    (3, 2): (0, 0, 1, 1),
    (3, 3): (0, 1, 1, 0),
    (4, 0): (1, 1, 0, 0, 1),
    (4, 1): (0, 1, 1, 0, 0),
    (4, 2): (0, 0, 0, 1, 1),
    (4, 3): (1, 0, 1, 1, 0),
}

_Q_TABLES: Final[tuple[tuple[int, ...], ...]] = (_Q0, _Q1)

#: Reed-Solomon polynomial and matrix used to derive S-box key material.
#: Twofish section 4.3.2: the key is RS-encoded so that the S-boxes depend on
#: every key byte, not just the ones aligned to each position. Omitting this
#: step leaves the zero-key vectors passing while every non-zero key is wrong.
_RS_POLY: Final[int] = 0x14D
_RS_MATRIX: Final[tuple[tuple[int, ...], ...]] = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
)


def _rs_encode(key: bytes) -> tuple[int, ...]:
    """RS-encode the key into the S-box key bytes.

    Each 8-byte chunk of the key multiplies one column of the RS matrix over
    GF(2^8) with polynomial 0x14D, producing four bytes per chunk in row order.
    """
    out = [0] * 16
    for index, byte in enumerate(key):
        # Each key byte scales one RS column; the four products land in the
        # output lanes of that key chunk.
        column = index % 8
        offset = 4 * (index // 8)
        for lane in range(4):
            coefficient = _RS_MATRIX[lane][column]
            out[offset + lane] ^= _gf_mul(coefficient, byte, _RS_POLY)
    return tuple(out)


#: GF(2^8) multiply, polynomial 0x169 (Twofish MDS).
def _gf_mul(a: int, b: int, poly: int = 0x169) -> int:
    result = 0
    x, y = a & 0xFF, b & 0xFF
    while y:
        if y & 1:
            result ^= x
        x <<= 1
        if x & 0x100:
            x ^= poly
        y >>= 1
    return result & 0xFF


#: MDS columns expanded to 32-bit contributions per input byte value.
def _build_mds() -> tuple[tuple[int, ...], ...]:
    columns = []
    for position in range(4):
        column = []
        for value in range(256):
            word = 0
            for row in range(4):
                word |= _gf_mul(_MDS[row][position], value) << (8 * row)
            column.append(word)
        columns.append(tuple(column))
    return tuple(columns)


_MDS_COLUMNS: Final[tuple[tuple[int, ...], ...]] = _build_mds()


def _h(x: int, key: tuple[int, ...]) -> int:
    """The h function for a full 32-bit word and a list of key words.

    Section 4.3.2: the word is split into four bytes, each byte position runs a
    q chain (differing by position and key length), key words are XORed in at
    each depth, and the four results are combined through the MDS matrix.
    """
    k = len(key)
    out = 0
    for position in range(4):
        chain = _Q_CHAINS[(k, position)]
        value = (x >> (8 * (3 - position))) & 0xFF
        mixed = _Q_TABLES[chain[0]][value]
        for depth in range(k):
            key_byte = _byte(key[k - 1 - depth], position)
            mixed = _Q_TABLES[chain[depth + 1]][mixed ^ key_byte]
        out ^= _MDS_COLUMNS[position][mixed]
    return out


def _byte(word: int, index: int) -> int:
    """Little-endian byte ``index`` of a key word."""
    return (word >> (8 * index)) & 0xFF


def _rol(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & MASK32


def _ror(value: int, count: int) -> int:
    count &= 31
    return ((value >> count) | (value << (32 - count))) & MASK32


class Twofish:
    """Twofish-128/192/256 with the standard 16-round structure."""

    block_size = 16
    key_sizes = (16, 24, 32)

    def __init__(self, key: bytes) -> None:
        if len(key) not in self.key_sizes:
            raise ValueError(f"Twofish key must be 16, 24 or 32 bytes, got {len(key)}")
        self._key_bytes = tuple(key)
        words = [
            int.from_bytes(key[i : i + 4], "little") for i in range(0, len(key), 4)
        ]
        k = len(words) // 2
        self._k = k

        # Round subkeys. The paper splits the key into even and odd word groups;
        # subkey i is derived from the group whose parity matches i. Getting the
        # group wrong produces a cipher that is internally consistent and
        # completely wrong, which no amount of self-consistency testing reveals.
        subkeys: list[int] = []
        for i in range(20):
            a = self._h_word(2 * i, 0)
            b = _rol(self._h_word(2 * i + 1, 4), 8)
            subkeys.append((a + b) & MASK32)
            subkeys.append(_rol(((b + ((a + b) & MASK32)) & MASK32), 9))
        self._subkeys = subkeys

        # Key-dependent S-box tables, one per byte position, with the MDS
        # column pre-applied so the round loop is four lookups and three XORs.
        s_bytes = _rs_encode(key)
        self._s = s_bytes
        tables: list[tuple[int, ...]] = []
        for position in range(4):
            chain = _Q_CHAINS[(k, position)]
            column = _MDS_COLUMNS[position]
            table = [0] * 256
            for value in range(256):
                mixed = _Q_TABLES[chain[0]][value]
                for depth in range(k):
                    mixed = _Q_TABLES[chain[depth + 1]][mixed ^ s_bytes[4 * depth + position]]
                table[value] = column[mixed]
            tables.append(tuple(table))
        self._sb = tuple(tables)

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block.

        Sixteen rounds as eight double-rounds. Each half-round applies g() to one
        word, mixes the pair through the PHT (``x + y``, ``y + x + y``), adds the
        round subkeys and the two whitening words, and folds the result into the
        opposite pair with a 1-bit rotation.
        """
        if len(block) != 16:
            raise ValueError("Twofish block must be 16 bytes")
        a, b, c, d = (
            int.from_bytes(block[0:4], "little"),
            int.from_bytes(block[4:8], "little"),
            int.from_bytes(block[8:12], "little"),
            int.from_bytes(block[12:16], "little"),
        )
        sb0, sb1, sb2, sb3 = self._sb
        rk = self._subkeys

        a ^= rk[0]
        b ^= rk[1]
        c ^= rk[2]
        d ^= rk[3]

        for base in range(8, 40, 4):
            x = sb0[a & 0xFF] ^ sb1[(a >> 8) & 0xFF] ^ sb2[(a >> 16) & 0xFF] ^ sb3[(a >> 24) & 0xFF]
            y = sb1[b & 0xFF] ^ sb2[(b >> 8) & 0xFF] ^ sb3[(b >> 16) & 0xFF] ^ sb0[(b >> 24) & 0xFF]
            x = (x + y) & MASK32
            y = (y + x) & MASK32
            x = (x + rk[base]) & MASK32
            y = (y + rk[base + 1]) & MASK32
            # ror(v, 1) == rol(v, 31). Inlined: this is the hottest loop in the
            # decoder and a call per rotation costs more than the arithmetic.
            v = (c ^ x) & MASK32
            c = ((v >> 1) | (v << 31)) & MASK32
            v = d & MASK32
            d = (((v << 1) | (v >> 31)) & MASK32) ^ y

            x = sb0[c & 0xFF] ^ sb1[(c >> 8) & 0xFF] ^ sb2[(c >> 16) & 0xFF] ^ sb3[(c >> 24) & 0xFF]
            y = sb1[d & 0xFF] ^ sb2[(d >> 8) & 0xFF] ^ sb3[(d >> 16) & 0xFF] ^ sb0[(d >> 24) & 0xFF]
            x = (x + y) & MASK32
            y = (y + x) & MASK32
            x = (x + rk[base + 2]) & MASK32
            y = (y + rk[base + 3]) & MASK32
            v = (a ^ x) & MASK32
            a = ((v >> 1) | (v << 31)) & MASK32
            v = b & MASK32
            b = (((v << 1) | (v >> 31)) & MASK32) ^ y

        c ^= rk[4]
        d ^= rk[5]
        a ^= rk[6]
        b ^= rk[7]

        return (
            c.to_bytes(4, "little")
            + d.to_bytes(4, "little")
            + a.to_bytes(4, "little")
            + b.to_bytes(4, "little")
        )

    def _h_word(self, value: int, group: int) -> int:
        """h() for a subkey index.

        ``value`` selects the key stream position; ``group`` is 0 for even
        subkeys and 4 for odd ones, addressing opposite 32-bit halves of the key
        (the M_e / M_o split).
        """
        out = 0
        key_bytes = self._key_bytes
        k = self._k
        for position in range(4):
            chain = _Q_CHAINS[(k, position)]
            mixed = _Q_TABLES[chain[0]][value]
            for depth in range(k):
                index = 8 * (k - 1 - depth) + group + position
                mixed = _Q_TABLES[chain[depth + 1]][mixed ^ key_bytes[index]]
            out ^= _MDS_COLUMNS[position][mixed]
        return out




__all__ = ["Twofish"]
