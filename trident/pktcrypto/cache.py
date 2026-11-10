"""Content-addressed cache for decoded containers.

Three extraction engines each need the same decoded XML. They run concurrently,
so the decode happens three times in parallel — 390 ms each on the practice lab,
more than a second of wasted CPU and three times the peak memory for the same
bytes.

This caches the decoded document keyed by the SHA-256 of the *input file*, so:

* the key is content-addressed, not path-addressed, so a renamed file hits;
* a different file never hits, so there is no staleness to reason about;
* the value is immutable ``bytes``, so sharing it between engines cannot leak
  state.

Sharing the decoded document does **not** compromise extraction independence.
Independence is about how facts are *derived* from the document, not about how
many times the container was unwrapped. Each engine still parses the bytes itself
and reaches its own conclusions; they simply stop paying for the same
cryptographic work three times.

The cache is bounded and holds plaintext, so it is process-local and in-memory
only: nothing is written to disk, and it disappears when the process exits.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from dataclasses import dataclass

from ..pktcrypto import ContainerError, decode_bytes as decode_container


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0

    @property
    def total(self) -> int:
        return self.hits + self.misses


class DecodedCache:
    """A small, thread-safe LRU of decoded containers.

    Thread-safe because the engines run in a thread pool and all three may ask
    for the same file at the same moment on a cold cache.
    """

    def __init__(self, max_entries: int = 4, max_bytes: int = 512 * 1024 * 1024) -> None:
        self.max_entries = max(1, max_entries)
        self.max_bytes = max(1, max_bytes)
        self._entries: OrderedDict[str, bytes] = OrderedDict()
        self._bytes = 0
        self._lock = threading.Lock()
        self.stats = CacheStats()

    def _key(self, raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    def get(self, raw: bytes) -> bytes | None:
        key = self._key(raw)
        with self._lock:
            value = self._entries.get(key)
            if value is None:
                self.stats.misses += 1
                return None
            self._entries.move_to_end(key)
            self.stats.hits += 1
            return value

    def put(self, raw: bytes, xml: bytes) -> None:
        key = self._key(raw)
        with self._lock:
            if key in self._entries:
                return
            self._entries[key] = xml
            self._bytes += len(xml)
            # Evict oldest until both bounds hold. A single document larger than
            # max_bytes is not cached at all rather than flushing the whole cache.
            while self._entries and (
                len(self._entries) > self.max_entries or self._bytes > self.max_bytes
            ):
                _, evicted = self._entries.popitem(last=False)
                self._bytes -= len(evicted)
                self.stats.evictions += 1

    def decode(self, raw: bytes) -> bytes:
        """Return the decoded XML for ``raw``, decoding at most once.

        The decode itself happens *outside* the lock, so a slow 30 MB file does
        not block other threads. Two threads racing on a cold entry may both
        decode; the second result is discarded. That is cheaper than serialising
        every decode behind one lock, and it cannot produce a wrong answer because
        both derive the same bytes from the same content.
        """
        cached = self.get(raw)
        if cached is not None:
            return cached
        xml = decode_container(raw).xml
        self.put(raw, xml)
        return xml

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._bytes = 0

    def stats_dict(self) -> dict:
        return {
            "hits": self.stats.hits,
            "misses": self.stats.misses,
            "evictions": self.stats.evictions,
            "entries": len(self._entries),
            "bytes": self._bytes,
        }


#: The cache the engines share within one process.
SHARED = DecodedCache()


__all__ = ["CacheStats", "DecodedCache", "SHARED"]
