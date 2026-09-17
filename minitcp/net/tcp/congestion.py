"""TCP Reno congestion control.

Congestion control answers a question flow control cannot: *how fast should I
send, given that the network in between may be overloaded?*  The receiver's
advertised window says how much the peer can absorb; ``cwnd`` says how much the
path can carry.  The sender may only have ``min(cwnd, rwnd)`` bytes in flight.

Reno has three modes:

**Slow start.**  ``cwnd`` grows by the number of bytes acknowledged, so it
doubles every round trip.  Exponential, but starting from one segment, hence
the name.

**Congestion avoidance.**  ``cwnd`` grows by roughly one segment per round
trip, which is additive and therefore cautious.  The transition happens once
``cwnd`` reaches ``ssthresh``.

**Fast recovery.**  Three duplicate ACKs mean a single segment was lost while
the rest of the window got through.  Waiting for a timeout would idle the
connection, so the missing segment is retransmitted immediately and ``cwnd`` is
halved rather than collapsed to one segment.

A timeout, by contrast, is treated as serious: ``cwnd`` drops all the way to
one segment and slow start begins again.  That asymmetry is deliberate.  A
timeout means the network was congested enough that *nothing* got through.
"""

from __future__ import annotations

from .seqno import seq_ge

__all__ = [
    "SLOW_START",
    "CONGESTION_AVOIDANCE",
    "FAST_RECOVERY",
    "RenoCongestion",
]

SLOW_START = "slow-start"
CONGESTION_AVOIDANCE = "congestion-avoidance"
FAST_RECOVERY = "fast-recovery"

#: RFC 5681 caps the initial window at roughly 4 KiB of segments.
INITIAL_WINDOW_CAP = 14600
MAX_CWND = 1 << 30


class RenoCongestion:
    """The congestion window and the rules that move it."""

    def __init__(
        self,
        mss: int,
        initial_window: int | None = None,
        initial_ssthresh: int | None = None,
    ) -> None:
        if mss <= 0:
            raise ValueError("MSS must be positive")
        self.mss = mss
        self.cwnd = (
            initial_window
            if initial_window is not None
            else min(10 * mss, max(2 * mss, INITIAL_WINDOW_CAP))
        )
        self.ssthresh = initial_ssthresh if initial_ssthresh is not None else MAX_CWND
        self.state = SLOW_START
        self.duplicate_acks = 0
        self.recover = 0
        #: Counters exposed for tests and diagnostics.
        self.timeouts = 0
        self.fast_retransmits = 0

    # -- growth ----------------------------------------------------------

    def on_ack(self, bytes_acked: int, ack_number: int | None = None) -> None:
        """A new acknowledgement covering *bytes_acked* fresh bytes."""
        if bytes_acked <= 0:
            return

        if self.state == FAST_RECOVERY:
            if ack_number is not None and seq_ge(ack_number, self.recover):
                # The retransmission is acknowledged: leave recovery and go
                # back to cautious growth.
                self.cwnd = max(self.ssthresh, self.mss)
                self.state = CONGESTION_AVOIDANCE
                self.duplicate_acks = 0
            else:
                # A partial ACK.  Another segment was lost; retransmit it and
                # stay in recovery.
                self.cwnd = max(self.ssthresh, self.cwnd - bytes_acked) + bytes_acked
            return

        self.duplicate_acks = 0

        if self.state == SLOW_START:
            self.cwnd = min(self.cwnd + bytes_acked, MAX_CWND)
            if self.cwnd >= self.ssthresh:
                self.state = CONGESTION_AVOIDANCE
            return

        # Congestion avoidance: about one extra segment per round trip.
        increment = (self.mss * bytes_acked) // max(self.cwnd, 1)
        self.cwnd = min(self.cwnd + max(increment, 1), MAX_CWND)

    def on_duplicate_ack(self, ack_number: int | None = None) -> bool:
        """Register a duplicate ACK; returns ``True`` when to fast retransmit.

        The third duplicate ACK is the signal: one segment was lost, but the
        ones after it arrived, which means the path is still delivering data.
        """
        if self.state == FAST_RECOVERY:
            # Each further duplicate ACK means another segment left the
            # network, so the window may be inflated by one MSS.
            self.cwnd = min(self.cwnd + self.mss, MAX_CWND)
            return False

        self.duplicate_acks += 1
        if self.duplicate_acks == 3:
            self.ssthresh = max(self.cwnd // 2, 2 * self.mss)
            self.cwnd = self.ssthresh + 3 * self.mss
            self.recover = ack_number if ack_number is not None else 0
            self.state = FAST_RECOVERY
            self.fast_retransmits += 1
            return True
        return False

    def on_timeout(self) -> None:
        """A retransmission timer fired; assume severe congestion."""
        self.ssthresh = max(self.cwnd // 2, 2 * self.mss)
        self.cwnd = self.mss
        self.state = SLOW_START
        self.duplicate_acks = 0
        self.timeouts += 1

    def on_partial_ack(self, ack_number: int) -> None:
        """Recovery exit helper used when the caller tracks ``recover``."""
        if self.state == FAST_RECOVERY and seq_ge(ack_number, self.recover):
            self.cwnd = max(self.ssthresh, self.mss)
            self.state = CONGESTION_AVOIDANCE
            self.duplicate_acks = 0

    # -- inspection ------------------------------------------------------

    @property
    def in_recovery(self) -> bool:
        return self.state == FAST_RECOVERY

    def effective_window(self, receiver_window: int) -> int:
        """Bytes that may be in flight: the smaller of the two windows."""
        return max(min(self.cwnd, receiver_window), self.mss)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Reno cwnd=%d ssthresh=%d state=%s dup=%d>" % (
            self.cwnd,
            self.ssthresh,
            self.state,
            self.duplicate_acks,
        )
