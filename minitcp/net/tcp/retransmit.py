"""Retransmission timing: the RTO estimator and the outstanding segment queue.

Two pieces of TCP live here, and both exist because the network is allowed to
lose things silently.

**The RTO estimator** (RFC 6298) keeps a smoothed round-trip time and a
variance estimate, and derives the retransmission timeout from them::

    SRTT   <- (1 - 1/8) * SRTT + (1/8) * R
    RTTVAR <- (1 - 1/4) * RTTVAR + (1/4) * |SRTT - R|
    RTO    <- SRTT + 4 * RTTVAR

The variance term is what makes this work.  A connection with a steady 100 ms
RTT and one that alternates between 10 ms and 190 ms have the same average, but
only the second needs a generous timeout.  The estimator alone would treat them
identically.

**Karn's algorithm** lives in the caller: a segment that was retransmitted must
never produce an RTT sample, because the ACK that comes back is ambiguous --
it could acknowledge either the original transmission or the retransmission.
Sampling it would push the RTO down and cause a retransmission storm.

**The outstanding queue** remembers what has been sent and not yet
acknowledged, so a timeout can be answered with the right bytes rather than a
guess.
"""

from __future__ import annotations

from dataclasses import dataclass

from .seqno import seq_le

__all__ = ["RTOEstimator", "OutstandingSegment", "RetransmitQueue"]

#: RFC 6298 suggests an initial RTO of 1 second.  It also permits a lower
#: minimum than its own recommendation of 1 second; 200 ms is what Linux uses
#: and it makes interactive traffic far less sluggish on a LAN.
DEFAULT_INITIAL_RTO = 1.0
DEFAULT_MIN_RTO = 0.2
DEFAULT_MAX_RTO = 60.0


class RTOEstimator:
    """Smoothed RTT and variance, as specified in RFC 6298."""

    def __init__(
        self,
        initial: float = DEFAULT_INITIAL_RTO,
        min_rto: float = DEFAULT_MIN_RTO,
        max_rto: float = DEFAULT_MAX_RTO,
    ) -> None:
        if min_rto <= 0 or max_rto < min_rto:
            raise ValueError("invalid RTO bounds")
        self.srtt: float | None = None
        self.rttvar: float | None = None
        self.min_rto = min_rto
        self.max_rto = max_rto
        self.rto = min(max(initial, min_rto), max_rto)
        self.samples = 0

    def sample(self, rtt: float) -> float:
        """Fold a fresh RTT measurement in and return the new RTO."""
        if rtt <= 0:
            return self.rto

        if self.srtt is None:
            self.srtt = rtt
            self.rttvar = rtt / 2.0
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - rtt)
            self.srtt = 0.875 * self.srtt + 0.125 * rtt

        self.samples += 1
        self.rto = min(max(self.srtt + 4.0 * self.rttvar, self.min_rto), self.max_rto)
        return self.rto

    def backoff(self) -> float:
        """Double the RTO after a timeout, capped at the maximum."""
        self.rto = min(self.rto * 2.0, self.max_rto)
        return self.rto

    def recompute(self) -> float:
        """Recalculate the RTO from the current estimate, undoing any backoff.

        Called when an acknowledgement advances the send window.  Backoff
        exists because a silent network might be a dead network, so it is worth
        being cautious; but an ACK that acknowledges new data proves the path is
        carrying traffic again, and continuing to wait eight seconds between
        retransmissions would turn a brief loss into a stalled connection.
        Linux resets the timer the same way.
        """
        if self.srtt is None:
            self.rto = min(max(DEFAULT_INITIAL_RTO, self.min_rto), self.max_rto)
        else:
            self.rto = min(
                max(self.srtt + 4.0 * self.rttvar, self.min_rto), self.max_rto
            )
        return self.rto

    def reset(self) -> None:
        """Forget all history and start over."""
        self.srtt = None
        self.rttvar = None
        self.rto = min(max(DEFAULT_INITIAL_RTO, self.min_rto), self.max_rto)
        self.samples = 0

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        srtt = "%.4f" % self.srtt if self.srtt is not None else "none"
        return "<RTOEstimator rto=%.4f srtt=%s samples=%d>" % (
            self.rto,
            srtt,
            self.samples,
        )


@dataclass
class OutstandingSegment:
    """A segment that has been transmitted and not yet acknowledged."""

    seq: int
    flags: int
    payload: bytes
    sent_at: float
    retransmits: int = 0
    #: Set once the segment is retransmitted, which disables RTT sampling for
    #: it (Karn's algorithm).
    rtt_sampled: bool = False

    @property
    def seq_len(self) -> int:
        from .segment import FLAG_FIN, FLAG_SYN

        return (
            len(self.payload)
            + (1 if self.flags & FLAG_SYN else 0)
            + (1 if self.flags & FLAG_FIN else 0)
        )

    @property
    def seq_end(self) -> int:
        return (self.seq + self.seq_len) & 0xFFFFFFFF

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Outstanding seq=%u len=%d retx=%d>" % (
            self.seq,
            len(self.payload),
            self.retransmits,
        )


class RetransmitQueue:
    """The list of segments awaiting acknowledgement, oldest first."""

    def __init__(self, capacity: int = 1 << 20) -> None:
        self._segments: list[OutstandingSegment] = []
        self._capacity = capacity

    def add(
        self,
        seq: int,
        flags: int,
        payload: bytes,
        now: float,
    ) -> OutstandingSegment | None:
        """Remember a newly transmitted segment.

        Returns ``None`` if the queue is full, which the caller should treat as
        backpressure rather than as success.
        """
        if self.bytes_outstanding + len(payload) > self._capacity:
            return None
        entry = OutstandingSegment(seq=seq, flags=flags, payload=payload, sent_at=now)
        self._segments.append(entry)
        return entry

    def acknowledge(self, ack: int) -> list[OutstandingSegment]:
        """Drop segments fully covered by *ack*.

        Partially acknowledged segments stay in the queue: their remaining
        bytes may still need retransmitting.
        """
        acked: list[OutstandingSegment] = []
        remaining: list[OutstandingSegment] = []
        for entry in self._segments:
            if seq_le(entry.seq_end, ack):
                acked.append(entry)
            else:
                remaining.append(entry)
        self._segments = remaining
        return acked

    def oldest(self) -> OutstandingSegment | None:
        return self._segments[0] if self._segments else None

    def mark_retransmitted(self, entry: OutstandingSegment, now: float) -> None:
        entry.retransmits += 1
        entry.sent_at = now
        entry.rtt_sampled = True

    def purge_before(self, seq: int) -> int:
        """Forcibly discard segments older than *seq*.

        Used when the peer acknowledges data we no longer hold, which means our
        own bookkeeping is stale and holding on to it would only cause a
        spurious retransmission.
        """
        before = len(self._segments)
        self._segments = [e for e in self._segments if not seq_le(e.seq_end, seq)]
        return before - len(self._segments)

    def clear(self) -> None:
        self._segments.clear()

    @property
    def bytes_outstanding(self) -> int:
        return sum(len(entry.payload) for entry in self._segments)

    def __len__(self) -> int:
        return len(self._segments)

    def __iter__(self):
        return iter(self._segments)
