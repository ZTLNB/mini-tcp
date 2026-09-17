"""Send and receive byte streams.

TCP presents a byte stream, but the network carries discrete segments.  These
two classes bridge that gap.

:class:`SendQueue` keeps bytes until they are acknowledged.  ``una`` is the
oldest byte not yet acknowledged, ``nxt`` the next one to transmit, and the gap
between them is exactly what is in flight.  Bytes may not be discarded on
transmission, only on acknowledgement, because a retransmission may need them
again.

:class:`ReceiveQueue` keeps bytes until the application reads them, which is
what lets the receive window advertise how much room is actually free.  If this
buffer fills, the advertised window shrinks toward zero and the peer stops
sending -- that is flow control, and it is the only thing standing between a
slow reader and unbounded memory growth.
"""

from __future__ import annotations

from .reorder import ReorderQueue
from .seqno import seq_add, seq_diff, seq_gt, seq_lt

__all__ = ["SendQueue", "ReceiveQueue"]


class SendQueue:
    """Outbound bytes awaiting acknowledgement."""

    def __init__(self, iss: int, capacity: int = 1 << 20) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        #: Oldest unacknowledged sequence number.
        self.una = iss
        #: Next sequence number to transmit.
        self.nxt = iss
        self._buf = bytearray()  # _buf[0] sits at sequence number ``una``
        self._capacity = capacity
        self.bytes_written = 0

    def write(self, data: bytes) -> int:
        """Append bytes, returning how many were accepted."""
        room = self._capacity - len(self._buf)
        if room <= 0:
            return 0
        chunk = data[:room]
        self._buf.extend(chunk)
        self.bytes_written += len(chunk)
        return len(chunk)

    def peek(self, seq: int, length: int) -> bytes:
        """Read buffered bytes starting at *seq*, without consuming them."""
        offset = seq_diff(seq, self.una)
        if offset < 0 or length <= 0:
            return b""
        return bytes(self._buf[offset: offset + length])

    def acknowledge(self, ack: int) -> int:
        """Advance ``una`` to *ack* and drop the acknowledged prefix."""
        if not seq_gt(ack, self.una):
            return 0
        count = seq_diff(ack, self.una)
        drop = min(count, len(self._buf))
        if drop:
            del self._buf[:drop]
        self.una = ack
        # ``nxt`` must never point at data that has already been acknowledged.
        # Retransmission can leave it behind ``una``, and if it stays there the
        # send path computes a negative in-flight count and stalls forever.
        if seq_lt(self.nxt, ack):
            self.nxt = ack
        return count

    def rewind(self, seq: int) -> None:
        """Move ``nxt`` back so bytes are transmitted again."""
        self.nxt = seq

    @property
    def buffered(self) -> int:
        """Bytes held because they have not been acknowledged."""
        return len(self._buf)

    @property
    def in_flight(self) -> int:
        """Bytes transmitted but not yet acknowledged."""
        return max(seq_diff(self.nxt, self.una), 0)

    @property
    def unsent(self) -> int:
        """Bytes buffered and not yet transmitted."""
        return max(len(self._buf) - self.in_flight, 0)

    @property
    def space(self) -> int:
        """Room left for more bytes from the application."""
        return max(self._capacity - len(self._buf), 0)

    def is_empty(self) -> bool:
        return not self._buf

    def clear(self) -> None:
        self._buf.clear()

    def __len__(self) -> int:
        return len(self._buf)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<SendQueue una=%u nxt=%u held=%d flight=%d>" % (
            self.una,
            self.nxt,
            len(self._buf),
            self.in_flight,
        )


class ReceiveQueue:
    """Inbound bytes: those in order, plus a holding area for those that are not.

    The application reads from the in-order part.  Anything that arrives early
    is parked and pulled in automatically once the gap ahead of it fills.
    """

    def __init__(self, irs: int, capacity: int = 1 << 20) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        #: Sequence number of the next byte we expect.  The peer's SYN consumed
        #: one sequence number, so the first data byte is one past it.
        self.nxt = seq_add(irs, 1)
        self._buf = bytearray()
        self._read_pos = 0
        self._ooo = ReorderQueue(capacity)
        self._capacity = capacity
        self.bytes_received = 0
        self.duplicates = 0

    def insert(self, seq: int, payload: bytes) -> int:
        """Accept a segment payload; returns bytes newly placed in order.

        Handles three cases: the segment is exactly what we expected, it is
        ahead of us (park it), or it overlaps data already held (trim and
        retry).  The third case is why this is not a two-line function --
        retransmissions legitimately overlap.
        """
        if not payload:
            return 0

        if seq == self.nxt:
            return self._accept(payload)

        if seq_gt(seq, self.nxt):
            # Park it, but only within the room we actually have.  The reorder
            # queue has its own limit; bounding by the free window as well is
            # what keeps ``available + held`` from ever exceeding the capacity
            # we advertise.
            room = self.window
            if len(payload) > room:
                payload = payload[:room]
            if payload:
                self._ooo.insert(seq, payload)
            return 0

        # The segment starts behind us.  Trim the part we already have and
        # retry; anything left over is genuinely new.
        overlap = seq_diff(self.nxt, seq)
        if overlap >= len(payload):
            self.duplicates += 1
            return 0
        self.duplicates += 1
        return self.insert(self.nxt, payload[overlap:])

    def _accept(self, payload: bytes) -> int:
        # Never grow past capacity, whatever the peer chooses to send.  A
        # correct peer respects the advertised window, but a buggy or hostile
        # one does not, and an unbounded buffer is precisely the failure that
        # flow control exists to prevent.  A dropped tail costs nothing: those
        # bytes were never acknowledged, so the peer will retransmit them.
        room = self.window
        if room <= 0:
            return 0
        chunk = payload[:room]
        self._buf.extend(chunk)
        self.nxt = seq_add(self.nxt, len(chunk))
        self.bytes_received += len(chunk)
        newly = len(chunk)

        # Pull in whatever the holding area can now supply.  This cannot
        # overflow: every byte moved out of it adds one to ``available``, so
        # ``available + held`` is unchanged by the drain.
        while True:
            data = self._ooo.take(self.nxt)
            if data is None:
                break
            self._buf.extend(data)
            self.nxt = seq_add(self.nxt, len(data))
            self.bytes_received += len(data)
            newly += len(data)

        return newly

    def read(self, max_bytes: int) -> bytes:
        """Consume up to *max_bytes* of in-order data."""
        if max_bytes <= 0:
            return b""
        end = min(self._read_pos + max_bytes, len(self._buf))
        chunk = bytes(self._buf[self._read_pos:end])
        self._read_pos = end
        # Compact once the consumed prefix is worth reclaiming, so repeated
        # small reads do not degrade into quadratic behaviour.
        if self._read_pos > 65536 and self._read_pos * 2 > len(self._buf):
            del self._buf[: self._read_pos]
            self._read_pos = 0
        return chunk

    def discard_before(self, seq: int) -> None:
        """Forget out-of-order data the peer has moved past."""
        self._ooo.discard_before(seq)

    @property
    def available(self) -> int:
        """Bytes the application can read right now."""
        return len(self._buf) - self._read_pos

    @property
    def held_out_of_order(self) -> int:
        return self._ooo.bytes_buffered

    @property
    def window(self) -> int:
        """Bytes we are willing to accept, for the advertised window field."""
        used = self.available + self.held_out_of_order
        return max(self._capacity - used, 0)

    @property
    def capacity(self) -> int:
        return self._capacity

    def clear(self) -> None:
        self._buf.clear()
        self._read_pos = 0
        self._ooo.clear()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<ReceiveQueue nxt=%u avail=%d ooo=%d win=%d>" % (
            self.nxt,
            self.available,
            self.held_out_of_order,
            self.window,
        )
