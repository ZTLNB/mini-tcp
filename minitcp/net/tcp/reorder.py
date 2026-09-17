"""Holding area for out-of-order segments.

IP delivery does not preserve order, so a segment can arrive before the one
that precedes it.  Throwing it away would be correct but wasteful -- the peer
would have to retransmit data that already crossed the network successfully,
which on a lossy path can spiral into a retransmission storm.

Instead the segment is parked here keyed by its sequence number.  When the gap
fills, the caller walks forward through the queue taking whatever is now
contiguous.  The capacity limit matters: without one, a peer could pin arbitrary
memory by sending segments with ever-increasing sequence numbers and never
filling the hole.
"""

from __future__ import annotations

from .seqno import seq_lt

__all__ = ["ReorderQueue"]


class ReorderQueue:
    """Buffers segments that arrived ahead of their turn."""

    def __init__(self, capacity: int = 1 << 16) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._data: dict[int, bytes] = {}
        self._capacity = capacity
        self.bytes_buffered = 0
        self.duplicates = 0
        self.overflows = 0

    def insert(self, seq: int, payload: bytes) -> bool:
        """Park *payload* for later.  Returns whether it was accepted."""
        if not payload:
            return True
        if seq in self._data:
            self.duplicates += 1
            return False
        if self.bytes_buffered + len(payload) > self._capacity:
            self.overflows += 1
            return False
        self._data[seq] = payload
        self.bytes_buffered += len(payload)
        return True

    def take(self, seq: int) -> bytes | None:
        """Remove and return the payload whose sequence number is exactly *seq*."""
        data = self._data.pop(seq, None)
        if data is not None:
            self.bytes_buffered -= len(data)
        return data

    def peek(self, seq: int) -> bytes | None:
        return self._data.get(seq)

    def discard_before(self, seq: int) -> int:
        """Drop everything that starts before *seq*, i.e. already delivered."""
        stale = [s for s in self._data if seq_lt(s, seq)]
        for key in stale:
            self.bytes_buffered -= len(self._data.pop(key))
        return len(stale)

    def clear(self) -> None:
        self._data.clear()
        self.bytes_buffered = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def free(self) -> int:
        return max(self._capacity - self.bytes_buffered, 0)

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, seq: int) -> bool:
        return seq in self._data

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<ReorderQueue held=%d bytes=%d>" % (len(self._data), self.bytes_buffered)
