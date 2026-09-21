"""A single TCP connection: the state machine, timers and data path.

This is where everything else comes together.  A connection owns a send queue,
a receive queue, a congestion window, an RTO estimator and a retransmission
queue, and it reacts to two kinds of event:

``on_segment(seg, src_ip, dst_ip)``
    A segment arrived from the network.

``on_tick(now)``
    Time passed.  Retransmission, delayed acknowledgement and TIME-WAIT expiry
    are all driven from here rather than from background threads, which keeps
    the connection deterministic and therefore testable.

The connection never touches a socket.  It calls a ``transmit`` callable and
lets the stack above decide how the bytes reach the wire.  That is what allows
the same connection object to be driven by a simulated wire in a unit test and
by a TUN device in production.

Timers worth knowing about:

*Retransmission* -- armed whenever data is in flight, disarmed when the
retransmission queue drains.  This is the only mechanism that recovers lost
data.

*Delayed acknowledgement* -- holding an ACK briefly gives the application a
chance to send a reply that can be piggybacked, halving the segment count for
interactive traffic.  The delay is bounded so the peer does not stall.

*TIME-WAIT* -- after a graceful close the connection lingers for twice the
maximum segment lifetime.  Two reasons: a lost final ACK can be answered if the
peer retransmits its FIN, and any stray segments from the old connection die
out before the same port pair can be reused.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

from .buffer import ReceiveQueue, SendQueue
from .congestion import RenoCongestion
from .retransmit import RetransmitQueue, RTOEstimator
from .segment import (
    FLAG_ACK,
    FLAG_FIN,
    FLAG_PSH,
    FLAG_RST,
    FLAG_SYN,
    TCPOptions,
    TCPSegment,
)
from .seqno import seq_add, seq_ge, seq_gt, seq_lt
from .state import (
    CLOSE_WAIT,
    CLOSED,
    CLOSING,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    LAST_ACK,
    LISTEN,
    SYN_RECEIVED,
    SYN_SENT,
    TIME_WAIT,
    is_synchronised,
)

__all__ = ["TCPStateError", "TCPConnection", "DEFAULT_MSS", "DEFAULT_WINDOW"]

DEFAULT_MSS = 1460
DEFAULT_WINDOW = 65535
DEFAULT_MSL = 30.0
DEFAULT_DELAYED_ACK = 0.05

#: How many times a segment may be retransmitted before the connection is
#: considered dead.  Linux uses roughly this order of magnitude.
MAX_RETRANSMITS = 15

#: First persist probe delay, and the ceiling its exponential backoff climbs
#: to.  A shut window is usually brief -- an application reading a buffer --
#: so the first probe comes quickly, but a peer that stays shut for minutes
#: should not be probed every second forever.
DEFAULT_PERSIST_DELAY = 0.5
MAX_PERSIST_DELAY = 60.0


class TCPStateError(RuntimeError):
    """Raised when an operation is not valid in the connection's state."""


class TCPConnection:
    """One TCP connection endpoint."""

    def __init__(
        self,
        local_ip: bytes,
        local_port: int,
        remote_ip: bytes,
        remote_port: int,
        transmit: Callable[[TCPSegment], None],
        *,
        mss: int = DEFAULT_MSS,
        receive_capacity: int = DEFAULT_WINDOW,
        send_capacity: int = 1 << 20,
        window_scale: int = 0,
        initial_window: int | None = None,
        clock: Callable[[], float] | None = None,
        iss: int | None = None,
        msl: float = DEFAULT_MSL,
        delayed_ack: bool = False,
        delayed_ack_delay: float = DEFAULT_DELAYED_ACK,
        on_established: Callable[["TCPConnection"], None] | None = None,
        on_data: Callable[["TCPConnection"], None] | None = None,
        on_closed: Callable[["TCPConnection"], None] | None = None,
        on_accept: Callable[["TCPConnection"], None] | None = None,
        on_reset: Callable[["TCPConnection"], None] | None = None,
    ) -> None:
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.transmit = transmit

        self.mss = mss
        self.receive_capacity = receive_capacity
        self.send_capacity = send_capacity
        self.rcv_wscale = window_scale
        self.msl = msl
        self.delayed_ack = delayed_ack
        self.delayed_ack_delay = delayed_ack_delay

        self._clock = clock or time.monotonic
        self._iss_override = iss
        self._rng = random.Random(iss)

        self.on_established = on_established
        self.on_data = on_data
        self.on_closed = on_closed
        self.on_accept = on_accept
        self.on_reset = on_reset

        # -- protocol state ---------------------------------------------
        self.state = CLOSED
        self.iss = 0
        self.irs = 0
        self.peer_mss = 536  # RFC 1122 default when the peer says nothing
        self.snd_wscale = 0
        self.peer_window = DEFAULT_WINDOW

        self.send_queue = SendQueue(0, send_capacity)
        self.recv_queue = ReceiveQueue(0, receive_capacity)
        self.reno = RenoCongestion(mss, initial_window=initial_window)
        self.rto = RTOEstimator()
        self.retx_queue = RetransmitQueue()

        # -- timers ------------------------------------------------------
        self._retransmit_at: float | None = None
        self._delayed_ack_at: float | None = None
        self._time_wait_until: float | None = None
        self._fin_seq: int | None = None
        self._syn_sent_at: float | None = None
        self._last_activity = 0.0
        #: Persist timer: probes a peer whose window has shut, so that a lost
        #: window update cannot deadlock the connection.
        self._persist_at: float | None = None
        self._persist_delay = DEFAULT_PERSIST_DELAY

        # -- statistics --------------------------------------------------
        self.segments_sent = 0
        self.segments_received = 0
        self.retransmissions = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.reset_received = False

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def snd_una(self) -> int:
        return self.send_queue.una

    @property
    def snd_nxt(self) -> int:
        return self.send_queue.nxt

    @property
    def rcv_nxt(self) -> int:
        return self.recv_queue.nxt

    @property
    def is_established(self) -> bool:
        return self.state == ESTABLISHED

    @property
    def is_closed(self) -> bool:
        return self.state == CLOSED

    @property
    def can_send(self) -> bool:
        return self.state in (ESTABLISHED, CLOSE_WAIT)

    @property
    def can_receive(self) -> bool:
        return self.state in (ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2)

    @property
    def peer_closed(self) -> bool:
        """True once the peer has sent its FIN.

        From that point the peer will never send more data, so a read that
        finds nothing buffered has reached end of stream rather than needing
        to wait.

        ``FIN-WAIT-2`` is deliberately absent.  It means *we* have closed our
        direction and been acknowledged -- the peer may still be sending, and
        treating that as end of stream would throw away a response that is
        merely still in flight.
        """
        return self.state in (CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<TCP %d -> %d %s>" % (self.local_port, self.remote_port, self.state)

    # ------------------------------------------------------------------
    # Application-facing operations
    # ------------------------------------------------------------------

    def listen(self) -> None:
        """Move to LISTEN and wait for an inbound SYN."""
        if self.state != CLOSED:
            raise TCPStateError("cannot listen from state %s" % self.state)
        self.state = LISTEN

    def connect(self, now: float | None = None) -> None:
        """Actively open the connection by sending a SYN."""
        if self.state != CLOSED:
            raise TCPStateError("cannot connect from state %s" % self.state)

        now = self._now(now)
        self.iss = self._choose_iss()
        self.send_queue = SendQueue(self.iss, self.send_capacity)
        self.recv_queue = ReceiveQueue(0, self.receive_capacity)
        self.reno = RenoCongestion(self.mss)

        self._transmit(
            seq=self.iss,
            flags=FLAG_SYN,
            payload=b"",
            now=now,
            options=self._syn_options(),
        )
        self.send_queue.nxt = seq_add(self.iss, 1)
        self.state = SYN_SENT
        self._syn_sent_at = now

    def send(self, data: bytes, now: float | None = None) -> int:
        """Queue bytes for transmission; returns how many were accepted."""
        if not self.can_send:
            raise TCPStateError("cannot send in state %s" % self.state)
        if not data:
            return 0

        now = self._now(now)
        written = self.send_queue.write(data)
        if written:
            self._flush(now)
        return written

    def recv(self, max_bytes: int = 65536) -> bytes:
        """Take up to *max_bytes* of received data, or ``b""`` if none is ready."""
        if self.recv_queue.available == 0:
            return b""
        data = self.recv_queue.read(max_bytes)
        # Reading frees window space, so tell the peer about it.
        if data and self.state in (ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2):
            self._send_ack()
        return data

    def close(self, now: float | None = None) -> None:
        """Gracefully shut down this direction of the connection."""
        now = self._now(now)

        if self.state == ESTABLISHED:
            self._send_fin(now)
            self.state = FIN_WAIT_1
        elif self.state == CLOSE_WAIT:
            self._send_fin(now)
            self.state = LAST_ACK
        elif self.state in (SYN_SENT, SYN_RECEIVED):
            # Nothing is established yet, so there is nothing to shut down
            # gracefully.
            self.abort(now)
        elif self.state in (FIN_WAIT_1, FIN_WAIT_2, CLOSING, LAST_ACK, TIME_WAIT):
            # Already closing; closing again is harmless.
            return
        else:
            self.state = CLOSED
            self._notify_closed()

    def abort(self, now: float | None = None) -> None:
        """Send an RST and tear the connection down immediately.

        Used when data would be lost anyway or when the peer has violated the
        protocol.  No handshake: an RST says "forget this connection".
        """
        now = self._now(now)
        if self.state not in (CLOSED, LISTEN):
            self._transmit(
                seq=self.send_queue.nxt,
                flags=FLAG_RST | FLAG_ACK,
                payload=b"",
                now=now,
                ack=self.recv_queue.nxt,
            )
        self._teardown()
        self._notify_closed()

    # ------------------------------------------------------------------
    # Inbound segment handling
    # ------------------------------------------------------------------

    def on_segment(
        self,
        seg: TCPSegment,
        src_ip: bytes | None = None,
        dst_ip: bytes | None = None,
        now: float | None = None,
    ) -> None:
        """Process one segment that arrived from the network."""
        now = self._now(now)
        self.segments_received += 1
        self._last_activity = now

        if self.state == CLOSED:
            # Nothing here remembers this connection; tell the peer so.
            self._reject(seg, now)
            return

        if seg.is_rst:
            self._handle_rst(seg, now)
            return

        if self.state == LISTEN:
            self._handle_segment_in_listen(seg, src_ip, now)
            return

        if seg.is_syn:
            # A SYN+ACK answers our own SYN; a bare SYN means both sides
            # opened at the same moment.  Getting this wrong is subtle: the
            # SYN+ACK carries the SYN bit, so it must not be mistaken for a
            # simultaneous open.
            if self.state == SYN_SENT:
                if seg.is_ack:
                    self._handle_syn_ack(seg, now)
                else:
                    self._handle_simultaneous_open(seg, now)
            elif self.state == SYN_RECEIVED:
                # Our SYN+ACK was probably lost; send it again.
                self._retransmit_oldest(now)
            else:
                self._reject(seg, now)
            return

        if self.state == SYN_SENT:
            # Nothing but a SYN or an RST is meaningful before the handshake
            # completes, so anything else is ignored.
            return

        if self.state == SYN_RECEIVED:
            if seg.is_ack:
                self._handle_final_ack_of_handshake(seg, now)
            return

        # From here on the connection is synchronised.
        if not self._acceptable(seg):
            if not seg.is_rst:
                self._send_ack(now)
            return

        if seg.is_ack:
            self._process_ack(seg, now)

        # An ACK that acknowledges our FIN while we are waiting changes state.
        self._maybe_advance_after_ack(seg, now)

        if seg.payload:
            self._handle_data(seg, now)

        if seg.is_fin:
            self._handle_fin(seg, now)

    # -- handshake -----------------------------------------------------

    def _handle_segment_in_listen(
        self, seg: TCPSegment, src_ip: bytes | None, now: float
    ) -> None:
        if seg.is_rst:
            return
        if not seg.is_syn:
            return

        # A child connection takes over from here; the listener stays in
        # LISTEN so it can accept more.
        child = TCPConnection(
            local_ip=self.local_ip,
            local_port=self.local_port,
            remote_ip=src_ip if src_ip is not None else self.remote_ip,
            remote_port=seg.src_port,
            transmit=self.transmit,
            mss=self.mss,
            receive_capacity=self.receive_capacity,
            send_capacity=self.send_capacity,
            window_scale=self.rcv_wscale,
            clock=self._clock,
            iss=self._iss_override,
            msl=self.msl,
            delayed_ack=self.delayed_ack,
            delayed_ack_delay=self.delayed_ack_delay,
            on_established=self.on_established,
            on_data=self.on_data,
            on_closed=self.on_closed,
            on_accept=self.on_accept,
            on_reset=self.on_reset,
        )
        child._begin_passive_open(seg, now)
        if self.on_accept is not None:
            self.on_accept(child)

    def _begin_passive_open(self, seg: TCPSegment, now: float) -> None:
        self.irs = seg.seq
        self.iss = self._choose_iss()
        self.send_queue = SendQueue(self.iss, self.send_capacity)
        self.recv_queue = ReceiveQueue(self.irs, self.receive_capacity)
        self.reno = RenoCongestion(self.mss)
        self.peer_window = seg.window
        self._apply_peer_options(seg.options)

        self._transmit(
            seq=self.iss,
            flags=FLAG_SYN | FLAG_ACK,
            payload=b"",
            now=now,
            ack=self.recv_queue.nxt,
            options=self._syn_options(),
        )
        self.send_queue.nxt = seq_add(self.iss, 1)
        self.state = SYN_RECEIVED

    def _handle_simultaneous_open(self, seg: TCPSegment, now: float) -> None:
        """Both sides sent a SYN at the same time (RFC 793 section 3.4)."""
        self.irs = seg.seq
        self.recv_queue = ReceiveQueue(self.irs, self.receive_capacity)
        self._apply_peer_options(seg.options)
        self.peer_window = seg.window
        self._transmit(
            seq=self.iss,
            flags=FLAG_SYN | FLAG_ACK,
            payload=b"",
            now=now,
            ack=self.recv_queue.nxt,
            options=self._syn_options(),
        )
        self.state = SYN_RECEIVED

    def _handle_syn_ack(self, seg: TCPSegment, now: float) -> None:
        if not seq_ge(seg.ack, seq_add(self.iss, 1)):
            self._reject(seg, now)
            return

        self.irs = seg.seq
        self.recv_queue = ReceiveQueue(self.irs, self.receive_capacity)
        self._apply_peer_options(seg.options)
        self.peer_window = seg.window << self.snd_wscale

        self._process_ack(seg, now)
        self._send_ack(now)
        self.state = ESTABLISHED
        self._notify_established()

    def _handle_final_ack_of_handshake(self, seg: TCPSegment, now: float) -> None:
        if not seq_ge(seg.ack, seq_add(self.iss, 1)):
            return
        self._process_ack(seg, now)
        self.state = ESTABLISHED
        self._notify_established()

    # -- data path -----------------------------------------------------

    def _handle_data(self, seg: TCPSegment, now: float) -> None:
        newly = self.recv_queue.insert(seg.seq, seg.payload)
        if newly:
            self.bytes_received += newly
            self._notify_data()

        if newly or seg.payload:
            if self.delayed_ack and newly:
                # Hold the ACK briefly so a reply can ride along with it.
                if self._delayed_ack_at is None:
                    self._delayed_ack_at = now + self.delayed_ack_delay
            else:
                self._send_ack(now)

    def _process_ack(self, seg: TCPSegment, now: float) -> None:
        """Handle an acknowledgement, including duplicate and partial ACKs."""
        una = self.send_queue.una

        if not seq_gt(seg.ack, una):
            # Not new.  The window field is still authoritative, though: a
            # pure window update -- the peer re-opening a closed window once
            # its application drained the buffer -- arrives as a duplicate
            # ACK, because acknowledging bytes we already know about does not
            # advance the number.  Ignoring it deadlocks the connection with
            # one side holding data and the other holding room for it.
            reopened = self._update_peer_window(seg)

            # A window update is still a duplicate ACK as far as congestion
            # control is concerned, so it counts toward the fast retransmit
            # threshold rather than being exempt from it.
            fast = False
            if seg.ack == una and self.send_queue.in_flight > 0:
                fast = self.reno.on_duplicate_ack(seg.ack)

            if fast:
                self._retransmit_oldest(now, fast=True)
            elif reopened and self.retx_queue.oldest() is not None:
                # The window has just re-opened.  Anything we probed while it
                # was shut may have been refused rather than buffered, and the
                # ACK number cannot tell us which, so resend from the head of
                # the outstanding queue instead of waiting out the RTO.
                self._retransmit_oldest(now)

            self._flush(now)
            return

        acknowledged = self.send_queue.acknowledge(seg.ack)
        if acknowledged <= 0:
            return

        # RTT sampling, with Karn's algorithm: a segment that was retransmitted
        # must not be sampled, because its ACK is ambiguous.
        for entry in self.retx_queue.acknowledge(seg.ack):
            if entry.retransmits == 0:
                self.rto.sample(max(now - entry.sent_at, 0.0))
                break
        else:
            # Everything acknowledged had been retransmitted at least once, so
            # no RTT sample is available.  Still drop any backoff: an ACK that
            # moves the window forward means the path is working again.
            self.rto.recompute()

        self.reno.on_ack(acknowledged, seg.ack)
        self._update_peer_window(seg)
        self._arm_retransmit_timer(now)
        self._flush(now)

    def _update_peer_window(self, seg: TCPSegment) -> bool:
        """Adopt the receive window the peer advertised.

        Returns whether the window has just re-opened from zero, which the
        caller uses to decide whether the head of the send queue needs
        resending.

        The value is taken at face value, as RFC 793 specifies.  A window that
        shrinks below the amount already in flight strands nothing: those bytes
        are protected by the retransmission timer, not by the window.
        """
        previous = self.peer_window
        self.peer_window = seg.window << self.snd_wscale
        return previous <= 0 < self.peer_window

    def _maybe_advance_after_ack(self, seg: TCPSegment, now: float) -> None:
        """Move through the closing states once our FIN is acknowledged."""
        if self._fin_seq is None or not seg.is_ack:
            return
        fin_acked = seq_ge(seg.ack, seq_add(self._fin_seq, 1))
        if not fin_acked:
            return

        if self.state == FIN_WAIT_1:
            self.state = FIN_WAIT_2
        elif self.state == CLOSING:
            self._enter_time_wait(now)
        elif self.state == LAST_ACK:
            self._teardown()
            self._notify_closed()

    def _handle_fin(self, seg: TCPSegment, now: float) -> None:
        """Handle the peer's FIN, tolerating out-of-order arrival.

        A FIN carries a sequence number like any other segment, so it can
        arrive ahead of the data that precedes it.  Consuming it in that case
        would advance ``rcv_nxt`` past a gap and silently discard the missing
        bytes, so it is acknowledged and ignored until the gap fills.
        """
        fin_seq = seq_add(seg.seq, len(seg.payload))

        if seq_gt(fin_seq, self.recv_queue.nxt):
            # Data before the FIN is still missing.  Re-acknowledge what we
            # have so the peer retransmits the gap.
            self._send_ack(now)
            return

        if seq_lt(fin_seq, self.recv_queue.nxt):
            # Already consumed; acknowledge again without advancing.
            self._send_ack(now)
            return

        self.recv_queue.nxt = seq_add(self.recv_queue.nxt, 1)
        self._send_ack(now)

        if self.state == ESTABLISHED:
            self.state = CLOSE_WAIT
        elif self.state == FIN_WAIT_1:
            if self._fin_seq is not None and seq_ge(
                self.send_queue.una, seq_add(self._fin_seq, 1)
            ):
                self._enter_time_wait(now)
            else:
                self.state = CLOSING
        elif self.state == FIN_WAIT_2:
            self._enter_time_wait(now)
        elif self.state == CLOSING:
            self._enter_time_wait(now)

    def _handle_rst(self, seg: TCPSegment, now: float) -> None:
        self.reset_received = True
        self._teardown()
        if self.on_reset is not None:
            self.on_reset(self)
        self._notify_closed()

    # ------------------------------------------------------------------
    # Outbound transmission
    # ------------------------------------------------------------------

    def _flush(self, now: float) -> None:
        """Send as much buffered data as the two windows allow."""
        if not is_synchronised(self.state):
            return

        if self.peer_window <= 0:
            # The peer has no room.  Sending anyway would consume sequence
            # numbers on bytes the peer is entitled to refuse outright,
            # leaving a hole that only a timeout could repair -- and if the
            # window update that re-opens the peer is lost, nothing would
            # repair it at all.  Probe on the persist timer instead, from the
            # sequence number the peer is actually waiting for.
            self._arm_persist_timer(now)
            return

        self._persist_at = None
        self._persist_delay = DEFAULT_PERSIST_DELAY

        while True:
            window = self.reno.effective_window(self.peer_window)
            in_flight = self.send_queue.in_flight
            if in_flight >= window:
                break

            allowed = min(window - in_flight, self.peer_mss)
            payload = self.send_queue.peek(self.send_queue.nxt, allowed)
            if not payload:
                break

            self._transmit(
                seq=self.send_queue.nxt,
                flags=FLAG_ACK | FLAG_PSH,
                payload=payload,
                now=now,
            )
            self.send_queue.nxt = seq_add(self.send_queue.nxt, len(payload))

            if len(payload) < allowed:
                break

    def _send_fin(self, now: float) -> None:
        self._fin_seq = self.send_queue.nxt
        self._transmit(
            seq=self._fin_seq,
            flags=FLAG_ACK | FLAG_FIN,
            payload=b"",
            now=now,
        )
        self.send_queue.nxt = seq_add(self._fin_seq, 1)

    def _send_ack(self, now: float | None = None) -> None:
        now = self._now(now)
        self._delayed_ack_at = None
        if self.state in (CLOSED, LISTEN):
            return
        self._transmit(
            seq=self.send_queue.nxt,
            flags=FLAG_ACK,
            payload=b"",
            now=now,
            ack=self.recv_queue.nxt,
        )

    def _transmit(
        self,
        seq: int,
        flags: int,
        payload: bytes,
        now: float,
        ack: int | None = None,
        options: TCPOptions | None = None,
        track: bool = True,
    ) -> None:
        """Build a segment, hand it to the stack, and remember it for retransmission.

        ``track=False`` is used when retransmitting: the segment is already in
        the queue, and adding it again would leave two entries sharing a
        sequence number.
        """
        segment = TCPSegment(
            src_port=self.local_port,
            dst_port=self.remote_port,
            seq=seq,
            ack=self.recv_queue.nxt if ack is None else ack,
            flags=flags,
            window=self._advertised_window(),
            payload=payload,
            options=options or TCPOptions(),
        )
        self.segments_sent += 1
        self.bytes_sent += len(payload)
        # The destination address is passed along because a connection created
        # from a listener has a different peer than the listener itself.
        self.transmit(segment, self.remote_ip)

        # Only segments that consume sequence space need tracking; a bare ACK
        # is never retransmitted.
        if track and (flags & (FLAG_SYN | FLAG_FIN) or payload):
            self.retx_queue.add(seq, flags, payload, now)
            self._arm_retransmit_timer(now)

    def _advertised_window(self) -> int:
        """The receive window, right-shifted by the negotiated scale factor."""
        window = self.recv_queue.window
        if self.rcv_wscale:
            window >>= self.rcv_wscale
        return min(window, 0xFFFF)

    def _reject(self, seg: TCPSegment, now: float) -> None:
        """Answer an unexpected segment with an RST, as RFC 793 requires."""
        if seg.is_rst:
            return
        if seg.is_ack:
            self._transmit(
                seq=seg.ack,
                flags=FLAG_RST,
                payload=b"",
                now=now,
            )
        else:
            self._transmit(
                seq=0,
                flags=FLAG_RST | FLAG_ACK,
                payload=b"",
                now=now,
                ack=seq_add(seg.seq, seg.seq_len),
            )

    # ------------------------------------------------------------------
    # Timers
    # ------------------------------------------------------------------

    def on_tick(self, now: float | None = None) -> None:
        """Drive every time-based transition.  Call this regularly."""
        now = self._now(now)

        if self._delayed_ack_at is not None and now >= self._delayed_ack_at:
            self._send_ack(now)

        if self._retransmit_at is not None and now >= self._retransmit_at:
            self._on_retransmit_timeout(now)

        if self._persist_at is not None and now >= self._persist_at:
            self._on_persist_timeout(now)

        if self.state == TIME_WAIT and self._time_wait_until is not None:
            if now >= self._time_wait_until:
                self._teardown()
                self._notify_closed()

        if self.state == SYN_SENT and self._syn_sent_at is not None:
            # The SYN is in the retransmission queue, so this is handled by the
            # retransmit timeout above.  Nothing extra to do.
            pass

    def _arm_persist_timer(self, now: float) -> None:
        """Start (or restart) the persist timer, if there is anything to send."""
        if self.send_queue.unsent <= 0 and self.send_queue.in_flight <= 0:
            self._persist_at = None
            return
        if self._persist_at is None:
            self._persist_at = now + self._persist_delay

    def _on_persist_timeout(self, now: float) -> None:
        """Probe a peer whose receive window has shut.

        Without this the connection deadlocks whenever the window update that
        re-opens the peer is lost: the sender has data, the receiver has room
        it has not told anyone about, and neither side has a reason to speak.
        The probe is deliberately small -- one segment at most -- because the
        peer is expected to refuse it and answer with its current window.
        """
        if self.peer_window > 0:
            # The window came back while the timer was pending.
            self._persist_at = None
            self._persist_delay = DEFAULT_PERSIST_DELAY
            self._flush(now)
            return

        if not is_synchronised(self.state):
            self._persist_at = None
            return

        oldest = self.retx_queue.oldest()
        if oldest is not None:
            # Something is already outstanding at ``snd_una``; resending it is
            # both the probe and, if the peer did have room, the repair.
            self.retransmissions += 1
            self.retx_queue.mark_retransmitted(oldest, now)
            self._transmit(
                seq=oldest.seq,
                flags=oldest.flags,
                payload=oldest.payload,
                now=now,
                track=False,
            )
        else:
            # Nothing outstanding, so the probe is one byte of new data.  It
            # costs a single sequence number and the peer will either take it
            # or answer with its window; either way we learn something.
            payload = self.send_queue.peek(self.send_queue.nxt, 1)
            if payload:
                self._transmit(
                    seq=self.send_queue.nxt,
                    flags=FLAG_ACK | FLAG_PSH,
                    payload=payload,
                    now=now,
                )
                self.send_queue.nxt = seq_add(self.send_queue.nxt, len(payload))

        # Back off, but never give up: a peer may legitimately stay shut for a
        # long time, and the connection is not dead just because it is idle.
        self._persist_delay = min(self._persist_delay * 2.0, MAX_PERSIST_DELAY)
        self._persist_at = now + self._persist_delay

    def _arm_retransmit_timer(self, now: float) -> None:
        if len(self.retx_queue) > 0:
            self._retransmit_at = now + self.rto.rto
        else:
            self._retransmit_at = None

    def _on_retransmit_timeout(self, now: float) -> None:
        oldest = self.retx_queue.oldest()
        if oldest is None:
            self._retransmit_at = None
            return

        if oldest.retransmits >= MAX_RETRANSMITS:
            # The peer is unreachable.  Continuing would just burn bandwidth.
            self._teardown()
            self._notify_closed()
            return

        self.reno.on_timeout()
        self.rto.backoff()
        self.retransmissions += 1
        self.retx_queue.mark_retransmitted(oldest, now)

        # ``send_queue.nxt`` is deliberately left alone.  Rewinding it to the
        # retransmitted sequence number looks tidy but breaks the connection:
        # once that segment is acknowledged, ``una`` moves past ``nxt`` and the
        # send path refuses to transmit anything ever again.
        self._transmit(
            seq=oldest.seq,
            flags=oldest.flags,
            payload=oldest.payload,
            now=now,
            track=False,
        )
        self._retransmit_at = now + self.rto.rto

    def _retransmit_oldest(self, now: float, fast: bool = False) -> None:
        """Resend the oldest unacknowledged segment.

        Called both from the timeout path and from fast retransmit, where three
        duplicate ACKs have already told us a segment went missing.
        """
        oldest = self.retx_queue.oldest()
        if oldest is None:
            return

        self.retransmissions += 1
        self.retx_queue.mark_retransmitted(oldest, now)
        self._transmit(
            seq=oldest.seq,
            flags=oldest.flags,
            payload=oldest.payload,
            now=now,
            track=False,
        )
        if not fast:
            self._retransmit_at = now + self.rto.rto

    def _enter_time_wait(self, now: float) -> None:
        self.state = TIME_WAIT
        self._time_wait_until = now + 2.0 * self.msl
        self.retx_queue.clear()
        self._retransmit_at = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _acceptable(self, seg: TCPSegment) -> bool:
        """Whether a segment is relevant to this connection (RFC 793).

        The upper bound is deliberately the *whole* receive capacity rather
        than the currently free part of it.  This test answers "is this
        segment worth processing at all"; rejecting a segment that straddles
        the window edge would throw away its in-window prefix and force a
        pointless retransmission.  The hard memory bound lives in
        :meth:`ReceiveQueue._accept`, which trims whatever will not fit.
        """
        if not is_synchronised(self.state):
            return True

        window = self.recv_queue.capacity
        if window == 0:
            return len(seg.payload) == 0 and seg.seq == self.recv_queue.nxt

        low = self.recv_queue.nxt
        high = seq_add(low, window)
        seg_end = seg.seq_end

        if len(seg.payload) == 0 and seg.seq_len == 0:
            return seq_ge(seg.seq, low) and seq_lt(seg.seq, high)

        return seq_lt(seg.seq, high) and seq_gt(seg_end, low)

    def _apply_peer_options(self, options: TCPOptions) -> None:
        if options.mss is not None:
            self.peer_mss = max(min(options.mss, self.mss), 64)
        if options.window_scale is not None:
            self.snd_wscale = min(options.window_scale, 14)

    def _syn_options(self) -> TCPOptions:
        return TCPOptions(
            mss=self.mss,
            window_scale=self.rcv_wscale if self.rcv_wscale else None,
            sack_permitted=True,
        )

    def _choose_iss(self) -> int:
        if self._iss_override is not None:
            return self._iss_override & 0xFFFFFFFF
        # RFC 6528 recommends a clock-based ISN; a random 32-bit value is
        # enough for a stack that is not trying to resist off-path injection.
        return self._rng.getrandbits(32)

    def _now(self, value: float | None) -> float:
        return self._clock() if value is None else value

    def _teardown(self) -> None:
        self.state = CLOSED
        self.retx_queue.clear()
        self.send_queue.clear()
        self.recv_queue.clear()
        self._retransmit_at = None
        self._delayed_ack_at = None
        self._time_wait_until = None

    # -- callbacks -------------------------------------------------------

    def _notify_established(self) -> None:
        if self.on_established is not None:
            self.on_established(self)

    def _notify_data(self) -> None:
        if self.on_data is not None:
            self.on_data(self)

    def _notify_closed(self) -> None:
        if self.on_closed is not None:
            self.on_closed(self)
