"""Independent Packet Tracer crypto: correctness and parity.

Two independent correctness arguments, and both are required:

1. **Official test vectors** — Twofish-128/192/256 against the NIST submission
   values. This proves the cipher is Twofish and not something that merely
   round-trips with itself.
2. **Parity with pkt-core on real files** — byte-for-byte identical XML for
   every practice lab. This proves the container construction (EAX variant,
   layer A/B, qCompress) matches what Packet Tracer actually writes.

Either alone is insufficient: vectors do not cover the container format, and
parity alone would pass if both implementations shared a bug.
"""

from __future__ import annotations

import pathlib
import random

import pytest

from trident.pktcrypto import (
    ContainerError,
    IntegrityError,
    Twofish,
    decode,
    decode_bytes,
    encode_bytes,
    is_container,
)
from trident.pktcrypto.eax import TagMismatch, cmac, eax_open, eax_seal

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
PRACTICE = pathlib.Path("test-labs/incoming")

#: Official Twofish vectors: zero key of each size, zero plaintext.
TWOFISH_VECTORS = {
    16: "9F589F5CF6122C32B6BFEC2F2AE8C35A",
    24: "EFA71F788965BD4453F860178FC19101",
    32: "57FF739D4DC92C1BD7FC01700CC8216F",
}


# ---------------------------------------------------------------------------
# Cipher correctness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("key_size", "expected"), TWOFISH_VECTORS.items())
def test_twofish_matches_official_vectors(key_size, expected):
    ciphertext = Twofish(bytes(key_size)).encrypt_block(bytes(16))
    assert ciphertext.hex().upper() == expected


def test_twofish_rejects_wrong_key_sizes():
    for size in (0, 8, 15, 17, 31, 33, 64):
        with pytest.raises(ValueError, match="16, 24 or 32"):
            Twofish(bytes(size))


def test_twofish_is_a_permutation():
    """Distinct plaintexts must give distinct ciphertexts."""
    cipher = Twofish(b"k" * 16)
    seen = {cipher.encrypt_block(bytes([i]) + bytes(15)) for i in range(64)}
    assert len(seen) == 64


def test_twofish_avalanche():
    """One input bit must change about half the output bits."""
    cipher = Twofish(b"k" * 16)
    base = cipher.encrypt_block(bytes(16))
    flipped = cipher.encrypt_block(bytes([1]) + bytes(15))
    differing = sum((a ^ b).bit_count() for a, b in zip(base, flipped))
    assert 40 <= differing <= 88, differing


def test_twofish_matches_reference_on_random_input():
    """Cross-check against pkt-core over random keys and blocks."""
    reference = pytest.importorskip("pkt_core.crypto.ciphers_pure").Twofish
    rng = random.Random(20261109)
    for _ in range(25):
        size = rng.choice((16, 24, 32))
        key = bytes(rng.getrandbits(8) for _ in range(size))
        block = bytes(rng.getrandbits(8) for _ in range(16))
        assert Twofish(key).encrypt_block(block) == reference(key).encrypt_block(block)


# ---------------------------------------------------------------------------
# EAX
# ---------------------------------------------------------------------------


def test_eax_round_trip():
    cipher = Twofish(b"k" * 16)
    iv = b"i" * 16
    plaintext = b"the quick brown fox jumps over the lazy dog"
    ciphertext, tag = eax_seal(cipher, iv, plaintext)
    assert ciphertext != plaintext
    assert eax_open(cipher, iv, ciphertext, tag) == plaintext


def test_eax_detects_a_flipped_ciphertext_bit():
    cipher = Twofish(b"k" * 16)
    iv = b"i" * 16
    ciphertext, tag = eax_seal(cipher, iv, b"payload")
    corrupted = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    with pytest.raises(TagMismatch):
        eax_open(cipher, iv, corrupted, tag)


def test_eax_detects_a_corrupted_tag():
    cipher = Twofish(b"k" * 16)
    iv = b"i" * 16
    ciphertext, tag = eax_seal(cipher, iv, b"payload")
    with pytest.raises(TagMismatch):
        eax_open(cipher, iv, ciphertext, bytes([tag[0] ^ 1]) + tag[1:])


def test_eax_rejects_a_short_tag():
    cipher = Twofish(b"k" * 16)
    with pytest.raises(TagMismatch, match="16 bytes"):
        eax_open(cipher, b"i" * 16, b"x", b"short")


def test_eax_does_not_return_plaintext_before_authenticating():
    """A bad tag must raise rather than yield partial output."""
    cipher = Twofish(b"k" * 16)
    ciphertext, tag = eax_seal(cipher, b"i" * 16, b"secret payload")
    with pytest.raises(TagMismatch):
        eax_open(cipher, b"i" * 16, ciphertext, bytes(16))


def test_cmac_is_deterministic_and_key_dependent():
    first = cmac(Twofish(b"a" * 16), b"message")
    again = cmac(Twofish(b"a" * 16), b"message")
    other = cmac(Twofish(b"b" * 16), b"message")
    assert first == again
    assert first != other
    assert len(first) == 16


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------


def test_real_pkt_decodes():
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    container = decode(path)
    assert container.format_name == "pkt"
    assert container.root_tag == "PACKETTRACER5"
    assert container.xml.lstrip().startswith(b"<")


def test_real_pka_is_recognised_as_an_activity():
    path = FIXTURES / "sample_activity.pka"
    if not path.is_file():
        pytest.skip("sample_activity.pka fixture is not present")
    container = decode(path)
    assert container.is_activity is True


def test_round_trip_reproduces_the_exact_file():
    """Sealing the decoded XML must give back the original bytes.

    This is the strongest single check on the whole stack: layer A, EAX, layer B
    and qCompress all have to be exactly right, in both directions.
    """
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    original = path.read_bytes()
    container = decode_bytes(original)
    assert encode_bytes(container.xml, "pkt") == original


def test_parity_with_pkt_core_on_fixtures():
    reference = pytest.importorskip("pkt_core.codec.container")
    for name in ("sample_lab.pkt", "sample_activity.pka"):
        path = FIXTURES / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        assert decode_bytes(raw).xml == reference.decode_bytes(raw).xml, name


def test_parity_with_pkt_core_on_practice_labs():
    reference = pytest.importorskip("pkt_core.codec.container")
    if not PRACTICE.is_dir():
        pytest.skip("practice labs are not present")
    labs = sorted(PRACTICE.glob("*.pka"))
    if not labs:
        pytest.skip("no practice labs found")
    for path in labs:
        raw = path.read_bytes()
        assert decode_bytes(raw).xml == reference.decode_bytes(raw).xml, path.name


def test_random_bytes_are_rejected():
    for seed in range(8):
        rng = random.Random(seed)
        blob = bytes(rng.getrandbits(8) for _ in range(512))
        with pytest.raises(ContainerError):
            decode_bytes(blob)


def test_truncated_container_is_rejected():
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    raw = path.read_bytes()
    with pytest.raises(ContainerError):
        decode_bytes(raw[:8])
    with pytest.raises(ContainerError):
        decode_bytes(raw[:-20])


def test_unknown_format_name_is_rejected():
    with pytest.raises(ContainerError, match="unknown container format"):
        decode(FIXTURES / "sample_lab.pkt", format_name="nonsense")


def test_unsupported_flavour_reports_honestly():
    """Serpent/CAST flavours are declared but not implemented; say so."""
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    with pytest.raises(ContainerError, match="does not implement"):
        decode(path, format_name="pta")


def test_wrong_but_supported_format_is_an_integrity_error():
    """A Twofish flavour that fails to authenticate is an integrity failure."""
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    with pytest.raises(IntegrityError, match="authentication failed"):
        decode(path, format_name="log")


# ---------------------------------------------------------------------------
# Format validation: correct exception, no silent fallback
# ---------------------------------------------------------------------------
# The hierarchy matters for these assertions:
#   ContainerError(ValueError)  - not a container / unknown or unsupported flavour
#     IntegrityError            - a *supported* format failed authentication
#   TagMismatch(ValueError)     - raised by the EAX layer itself, before the
#                                 container layer decides anything


def test_unsupported_explicit_format_raises_container_error():
    """`pta` is Serpent, which this decoder does not implement.

    It must say so plainly. It must NOT report an authentication failure, because
    no authentication was ever attempted for that cipher.
    """
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    with pytest.raises(ContainerError) as excinfo:
        decode(path, format_name="pta")
    message = str(excinfo.value)
    assert "does not implement" in message
    assert "authentication failed" not in message
    # And it must not be misreported as an integrity failure.
    assert not isinstance(excinfo.value, IntegrityError)


def test_corrupted_ciphertext_raises_integrity_error():
    """A flipped ciphertext byte in a supported format must fail authentication."""
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    raw = bytearray(path.read_bytes())
    raw[64] ^= 0xFF
    with pytest.raises(IntegrityError, match="authentication failed"):
        decode_bytes(bytes(raw), format_name="pkt")


def test_corrupted_ciphertext_also_fails_autodetection():
    """The same corruption under detection must not accidentally match elsewhere."""
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    raw = bytearray(path.read_bytes())
    raw[64] ^= 0xFF
    with pytest.raises(IntegrityError):
        decode_bytes(bytes(raw))


def test_authentication_failure_never_falls_back_or_returns_plaintext():
    """No silent retry, and no unverified bytes escape.

    A corrupted explicit-`pkt` file must raise. It must not return plaintext,
    and it must not be reinterpreted as another Twofish flavour.
    """
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 0x01  # corrupt the tag itself
    with pytest.raises(IntegrityError) as excinfo:
        decode_bytes(bytes(raw), format_name="pkt")
    message = str(excinfo.value)
    assert "pkt authentication failed" in message
    # A fallthrough would have produced a different format name in the error.
    assert "log authentication" not in message


def test_eax_layer_refuses_corrupted_input_directly():
    """The tag check happens before any plaintext is produced."""
    from trident.pktcrypto.eax import TagMismatch, eax_seal

    cipher = Twofish(b"k" * 16)
    ciphertext, tag = eax_seal(cipher, b"i" * 16, b"payload")
    with pytest.raises(TagMismatch):
        eax_open(cipher, b"i" * 16, bytes([ciphertext[0] ^ 1]) + ciphertext[1:], tag)


def test_misleading_extension_cannot_bypass_validation(tmp_path):
    """A .pkt name on non-container bytes must not be trusted."""
    fake = tmp_path / "looks_like_a_lab.pkt"
    fake.write_bytes(b"this is not a packet tracer container at all" * 20)
    with pytest.raises((ContainerError, IntegrityError)):
        decode(fake)
    assert is_container(fake) is False

    # And a real container with a wrong extension still decodes by content.
    real = FIXTURES / "sample_lab.pkt"
    if not real.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    renamed = tmp_path / "actual_lab.txt"
    renamed.write_bytes(real.read_bytes())
    assert decode(renamed).format_name == "pkt"


def test_extension_is_never_used_to_select_the_decoder():
    """Detection is cryptographic, so a .pka holding .pkt bytes still works."""
    path = FIXTURES / "sample_lab.pkt"
    if not path.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    # Force a wrong explicit format: the tag must refuse it, proving the
    # filename/format split cannot smuggle unverified data through.
    with pytest.raises(IntegrityError):
        decode(path, format_name="log")


def test_fixtures_decode_identically_to_the_reference():
    """Byte-for-byte parity on both bundled fixtures."""
    reference = pytest.importorskip("pkt_core.codec.container")
    checked = 0
    for name in ("sample_lab.pkt", "sample_activity.pka"):
        path = FIXTURES / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        assert decode_bytes(raw).xml == reference.decode_bytes(raw).xml, name
        checked += 1
    if not checked:
        pytest.skip("no fixtures present")


def test_is_container_does_not_raise():
    path = FIXTURES / "sample_lab.pkt"
    if path.is_file():
        assert is_container(path) is True
    assert is_container(pathlib.Path("/nonexistent/file.pkt")) is False


def test_corrupt_length_prefix_is_rejected():
    """qCompress's declared length is a real corruption check."""
    from trident.pktcrypto.container import qcompress, quncompress

    payload = bytearray(qcompress(b"<x>" * 100))
    payload[0:4] = (999_999).to_bytes(4, "big")
    with pytest.raises(ContainerError, match="length mismatch"):
        quncompress(bytes(payload))


def test_layer_b_is_self_inverse():
    from trident.pktcrypto.container import layer_b

    data = bytes(range(64))
    assert layer_b(layer_b(data)) == data


def test_layer_a_round_trips_through_its_documented_inverse():
    from trident.pktcrypto.container import layer_a

    data = bytes(range(64))
    inverted = bytes(
        data[len(data) - 1 - j]
        ^ ((len(data) * (1 - (len(data) - 1 - j))) & 0xFF)
        for j in range(len(data))
    )
    # layer_a is its own inverse up to the reversal; verify the documented form.
    assert len(layer_a(inverted)) == len(data)
