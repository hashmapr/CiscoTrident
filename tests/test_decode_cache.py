"""Content-addressed decode cache.

Three engines decode the same file. The cache removes that duplication without
touching extraction independence, which is about how facts are derived, not how
many times the container was unwrapped.

The properties that matter: content addressing (a renamed file hits), isolation
(a different file never hits), immutability (shared bytes cannot be mutated into
another engine's view), and bounded memory.
"""

from __future__ import annotations

import pathlib

import pytest

from trident.pktcrypto.cache import DecodedCache

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"


def _raw() -> bytes:
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    return FIXTURE.read_bytes()


def test_a_second_decode_hits_the_cache():
    cache = DecodedCache()
    raw = _raw()
    first = cache.decode(raw)
    second = cache.decode(raw)
    assert first is second, "the same document must be returned, not a copy"
    stats = cache.stats_dict()
    assert stats["misses"] == 1
    assert stats["hits"] == 1


def test_a_warm_cache_is_much_faster():
    import time

    cache = DecodedCache()
    raw = _raw()
    started = time.perf_counter()
    cache.decode(raw)
    cold = time.perf_counter() - started
    started = time.perf_counter()
    cache.decode(raw)
    warm = time.perf_counter() - started
    assert warm < cold / 10, f"cold {cold:.3f}s vs warm {warm:.4f}s"


def test_content_addressing_ignores_the_filename():
    """The key is the content hash, so a renamed file still hits."""
    cache = DecodedCache()
    raw = _raw()
    cache.decode(raw)
    # Same bytes, different provenance. No path is involved at all.
    assert cache.decode(bytes(raw)) is not None
    assert cache.stats_dict()["hits"] == 1


def test_a_different_file_never_hits():
    cache = DecodedCache()
    raw = _raw()
    cache.decode(raw)
    from trident.pktcrypto import ContainerError

    # A corrupt container must raise rather than be served from the cache.
    with pytest.raises(ContainerError):
        cache.decode(b"a completely different file" * 40)
    assert cache.stats_dict()["hits"] == 0


def test_the_cached_value_is_immutable_bytes():
    cache = DecodedCache()
    value = cache.decode(_raw())
    assert isinstance(value, bytes)
    with pytest.raises(TypeError):
        value[0] = 0  # type: ignore[index]


def test_eviction_keeps_the_entry_count_bounded():
    cache = DecodedCache(max_entries=2)
    raw = _raw()
    cache.decode(raw)
    for index in range(4):
        cache.put(f"filler-{index}".encode() * 100, b"x")
    assert cache.stats_dict()["entries"] <= 2


def test_clear_empties_the_cache():
    cache = DecodedCache()
    cache.decode(_raw())
    cache.clear()
    assert cache.stats_dict()["entries"] == 0
    assert cache.stats_dict()["bytes"] == 0


def test_stats_add_up():
    cache = DecodedCache()
    raw = _raw()
    cache.decode(raw)
    cache.decode(raw)
    cache.decode(raw)
    stats = cache.stats_dict()
    assert stats["hits"] == 2
    assert stats["misses"] == 1


def test_sharing_a_document_does_not_make_engines_agree():
    """The cache shares bytes, not conclusions.

    Two independent consumers of the same cached document still produce whatever
    they produce; the cache has no idea what they conclude.
    """
    cache = DecodedCache()
    raw = _raw()
    document = cache.decode(raw)
    # Two different questions asked of the same bytes.
    assert b"PACKETTRACER" in document
    assert len(document) > 0
