"""End-to-end tests driving two real TCPConnection objects against each other.

Nothing here is mocked at the protocol level: two genuine connections exchange
genuine segments, built and parsed by the real encoder.  The only stand-in is
the wire, and it is deliberately programmable so that loss, delay and reorder
can be reproduced exactly.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitcp.net.tcp import (  # noqa: E402
    CLOSED,
    CLOSE_WAIT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    LAST_ACK,
    LISTEN,
    SYN_RECEIVED,
    SYN_SENT,
    TIME_WAIT,
    TCPConnection,
    TCPSegment,
)

CLIENT_IP = bytes([10, 0, 0, 1])
SERVER_IP = bytes([10, 0, 0, 2])
CLIENT_PORT = 40000
SERVER_PORT = 80


class FakeClock:
    """A clock the test moves by hand, so timing is never a race."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, delta: float) -> float:
        self.t += delta
        return self.t


class Loopback:
    """Connects a client and a server, with optional loss injection."""

    def __init__(
        self,
        clock: FakeClock,
        receive_capacity: int = 65535,
        window_scale: int = 0,
    ) -> None:
        self.clock = clock
        self.to_server: list = []
        self.to_client: list = []
        self.drop_to_server = 0
        self.drop_to_client = 0
        self.dropped = 0
        self.accepted: list[TCPConnection] = []

        self.client = TCPConnection(
            CLIENT_IP,
            CLIENT_PORT,
            SERVER_IP,
            SERVER_PORT,
            self._from_client,
            clock=clock,
            iss=0x11111111,
            receive_capacity=receive_capacity,
            window_scale=window_scale,
        )
        self.server = TCPConnection(
            SERVER_IP,
            SERVER_PORT,
            CLIENT_IP,
            CLIENT_PORT,
            self._from_server,
            clock=clock,
            iss=0x22222222,
            receive_capacity=receive_capacity,
            window_scale=window_scale,
        )
        self.server.on_accept = self._on_accept

    def _on_accept(self, conn: TCPConnection) -> None:
        self.accepted.append(conn)
        # From now on traffic goes to the child, not the listener.
        self.server = conn

    def _from_client(self, seg, remote_ip) -> None:
        if self.drop_to_server:
            self.drop_to_server -= 1
            self.dropped += 1
            return
        self.to_server.append(seg)

    def _from_server(self, seg, remote_ip) -> None:
        if self.drop_to_client:
            self.drop_to_client -= 1
            self.dropped += 1
            return
        self.to_client.append(seg)

    def pump(self, rounds: int = 500) -> int:
        """Shuttle segments back and forth until both sides go quiet."""
        delivered = 0
        for _ in range(rounds):
            moved = False
            if self.to_server:
                batch, self.to_server = self.to_server, []
                for seg in batch:
                    self.server.on_segment(
                        seg, CLIENT_IP, SERVER_IP, now=self.clock()
                    )
                    delivered += 1
                moved = True
            if self.to_client:
                batch, self.to_client = self.to_client, []
                for seg in batch:
                    self.client.on_segment(
                        seg, SERVER_IP, CLIENT_IP, now=self.clock()
                    )
                    delivered += 1
                moved = True
            if not moved:
                break
        return delivered

    def drain_server(self) -> bytes:
        """Read everything the server has, pumping while doing so."""
        out = bytearray()
        for _ in range(200):
            self.pump()
            chunk = self.server.recv(65536)
            if not chunk:
                if not self.to_client and not self.to_server:
                    break
                continue
            out.extend(chunk)
        return bytes(out)


class TestHandshake(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.lb = Loopback(self.clock)

    def test_three_way_handshake(self) -> None:
        self.lb.server.listen()
        self.assertEqual(self.lb.server.state, LISTEN)

        self.lb.client.connect()
        self.assertEqual(self.lb.client.state, SYN_SENT)

        self.lb.pump()

        self.assertEqual(len(self.lb.accepted), 1, "server did not accept a connection")
        server_conn = self.lb.accepted[0]
        self.assertEqual(server_conn.state, ESTABLISHED)
        self.assertEqual(self.lb.client.state, ESTABLISHED)

        # The SYN consumes exactly one sequence number on each side.
        self.assertEqual(self.lb.client.snd_una, 0x11111111 + 1)
        self.assertEqual(self.lb.client.rcv_nxt, 0x22222222 + 1)

    def test_options_are_negotiated(self) -> None:
        self.lb.server.listen()
        self.lb.client.connect()
        self.lb.pump()
        server_conn = self.lb.accepted[0]

        # Both sides advertised a 1460-byte MSS, so that is what is used.
        self.assertEqual(self.lb.client.peer_mss, 1460)
        self.assertEqual(server_conn.peer_mss, 1460)

    def test_syn_lost_then_retransmitted(self) -> None:
        self.lb.server.listen()
        self.lb.drop_to_server = 1  # the SYN never arrives
        self.lb.client.connect()
        self.lb.pump()

        self.assertEqual(self.lb.client.state, SYN_SENT)
        self.assertEqual(self.lb.accepted, [])

        # Wait out the retransmission timeout and let the retry through.
        self.clock.advance(2.0)
        self.lb.client.on_tick()
        self.lb.pump()

        self.assertEqual(self.lb.client.state, ESTABLISHED)
        self.assertEqual(len(self.lb.accepted), 1)
        self.assertGreaterEqual(self.lb.client.retransmissions, 1)

    def test_reset_refused(self) -> None:
        """A connection refused shows up as an RST, not a timeout."""
        self.lb.client.connect()
        # Nobody is listening, so the client's SYN is answered with an RST.
        from minitcp.net.tcp import FLAG_RST, TCPSegment

        self.lb.client.on_segment(
            TCPSegment(
                src_port=SERVER_PORT,
                dst_port=CLIENT_PORT,
                seq=0,
                ack=0x11111111 + 1,
                flags=FLAG_RST,
                window=0,
            ),
            SERVER_IP,
            CLIENT_IP,
        )
        self.assertEqual(self.lb.client.state, CLOSED)
        self.assertTrue(self.lb.client.reset_received)


class TestDataTransfer(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.lb = Loopback(self.clock)
        self.lb.server.listen()
        self.lb.client.connect()
        self.lb.pump()
        self.server_conn = self.lb.accepted[0]

    def test_small_payload(self) -> None:
        written = self.lb.client.send(b"hello tcp")
        self.assertEqual(written, 9)
        self.lb.pump()
        self.assertEqual(self.server_conn.recv(), b"hello tcp")

    def test_payload_larger_than_one_mss(self) -> None:
        payload = bytes(range(256)) * 40  # 10240 bytes, about seven segments
        self.lb.client.send(payload)
        received = self.lb.drain_server()
        self.assertEqual(received, payload)
        self.assertGreater(self.server_conn.bytes_received, 10000)

    def test_payload_larger_than_the_window(self) -> None:
        """More data than a single receive buffer holds must still get through."""
        payload = bytes((i * 7) % 256 for i in range(200000))
        written = self.lb.client.send(payload)
        self.assertEqual(written, len(payload))
        received = self.lb.drain_server()
        self.assertEqual(len(received), len(payload))
        self.assertEqual(received, payload)

    def test_sequence_numbers_advance_exactly(self) -> None:
        self.lb.client.send(b"12345")
        self.lb.pump()
        # Each side's snd_una lives in its own sequence space...
        self.assertEqual(self.lb.client.snd_una, 0x11111111 + 1 + 5)
        # ...while rcv_nxt tracks the *peer's* space.
        self.assertEqual(self.server_conn.rcv_nxt, 0x11111111 + 1 + 5)
        self.assertEqual(self.lb.client.rcv_nxt, 0x22222222 + 1)

    def test_bidirectional_transfer(self) -> None:
        self.lb.client.send(b"ping")
        self.lb.pump()
        self.assertEqual(self.server_conn.recv(), b"ping")

        self.server_conn.send(b"pong")
        self.lb.pump()
        self.assertEqual(self.lb.client.recv(), b"pong")

    def test_retransmission_recovers_a_lost_segment(self) -> None:
        self.lb.drop_to_server = 1
        self.lb.client.send(b"this segment is lost")
        self.lb.pump()
        self.assertEqual(self.server_conn.recv(), b"")

        self.clock.advance(2.0)
        self.lb.client.on_tick()
        self.lb.pump()

        self.assertEqual(self.server_conn.recv(), b"this segment is lost")
        self.assertGreaterEqual(self.lb.client.retransmissions, 1)

    def test_duplicate_segments_are_ignored(self) -> None:
        """A retransmitted segment the peer already has must not be delivered twice."""
        self.lb.client.send(b"only once")
        self.lb.pump()
        self.assertEqual(self.server_conn.recv(), b"only once")

        # Replay the same segment verbatim.
        from minitcp.net.tcp import FLAG_ACK, FLAG_PSH, TCPSegment

        replay = TCPSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq=0x11111111 + 1,
            ack=self.server_conn.rcv_nxt,
            flags=FLAG_ACK | FLAG_PSH,
            window=65535,
            payload=b"only once",
        )
        self.server_conn.on_segment(replay, CLIENT_IP, SERVER_IP, now=self.clock())
        self.assertEqual(self.server_conn.recv(), b"", "duplicate data was delivered")

    def test_partially_overlapping_segment_is_trimmed(self) -> None:
        """Only the genuinely new tail of an overlapping segment is delivered."""
        from minitcp.net.tcp import FLAG_ACK, FLAG_PSH, TCPSegment

        self.lb.client.send(b"only once")
        self.lb.pump()
        self.assertEqual(self.server_conn.recv(), b"only once")

        # Starts five bytes back, so "once" repeats and "XYZ" is new.
        overlap = TCPSegment(
            src_port=CLIENT_PORT,
            dst_port=SERVER_PORT,
            seq=0x11111111 + 1 + 5,
            ack=self.server_conn.rcv_nxt,
            flags=FLAG_ACK | FLAG_PSH,
            window=65535,
            payload=b"onceXYZ",
        )
        self.server_conn.on_segment(overlap, CLIENT_IP, SERVER_IP, now=self.clock())
        self.assertEqual(self.server_conn.recv(), b"XYZ")
        self.assertGreaterEqual(self.server_conn.recv_queue.duplicates, 1)

    def test_congestion_window_grows(self) -> None:
        initial = self.lb.client.reno.cwnd
        self.lb.client.send(bytes(20000))
        self.lb.drain_server()
        self.assertGreater(self.lb.client.reno.cwnd, initial)


class TestTeardown(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.lb = Loopback(self.clock)
        self.lb.server.listen()
        self.lb.client.connect()
        self.lb.pump()
        self.server_conn = self.lb.accepted[0]

    def test_four_way_close(self) -> None:
        self.lb.client.close()
        self.assertEqual(self.lb.client.state, FIN_WAIT_1)

        self.lb.pump()
        self.assertEqual(self.server_conn.state, CLOSE_WAIT)
        self.assertEqual(self.lb.client.state, FIN_WAIT_2)

        self.server_conn.close()
        self.assertEqual(self.server_conn.state, LAST_ACK)

        self.lb.pump()
        self.assertEqual(self.server_conn.state, CLOSED)
        self.assertEqual(self.lb.client.state, TIME_WAIT)

    def test_time_wait_expires(self) -> None:
        self.lb.client.close()
        self.lb.pump()
        self.server_conn.close()
        self.lb.pump()
        self.assertEqual(self.lb.client.state, TIME_WAIT)

        self.clock.advance(self.lb.client.msl * 2 + 1)
        self.lb.client.on_tick()
        self.assertEqual(self.lb.client.state, CLOSED)

    def test_data_survives_the_close_handshake(self) -> None:
        """Data sent just before close must not be discarded."""
        self.lb.client.send(b"last words")
        self.lb.client.close()
        self.lb.pump()

        self.assertEqual(self.server_conn.recv(), b"last words")
        self.assertEqual(self.server_conn.state, CLOSE_WAIT)

    def test_abort_sends_reset(self) -> None:
        self.lb.client.abort()
        self.lb.pump()
        self.assertEqual(self.server_conn.state, CLOSED)
        self.assertTrue(self.server_conn.reset_received)


class TestFlowControl(unittest.TestCase):
    """The receive window is a promise; these tests hold both sides to it.

    A small buffer is used on purpose.  With the default 64 kB window the
    sender never has to stop, so none of the interesting cases -- the window
    closing, the peer reopening it, the sender probing -- are ever reached.
    """

    def _connect(self, capacity: int = 4096, window_scale: int = 0) -> Loopback:
        clock = FakeClock()
        lb = Loopback(clock, receive_capacity=capacity, window_scale=window_scale)
        lb.server.listen()
        lb.client.connect()
        lb.pump()
        return lb

    def test_window_update_riding_on_a_duplicate_ack_is_honoured(self):
        """Regression: the peer re-opens a closed window with an ACK that
        acknowledges nothing new, because acknowledging bytes we already know
        about cannot advance the number.

        The window field on such a segment used to be discarded outright,
        which left the sender convinced the window was still shut.  The
        connection deadlocked with one side holding data and the other holding
        room for it -- the classic zero-window standoff.
        """
        lb = self._connect(capacity=4096)
        payload = bytes((i * 13) % 256 for i in range(20000))

        self.assertEqual(lb.client.send(payload), len(payload))
        received = lb.drain_server()

        self.assertEqual(len(received), len(payload))
        self.assertEqual(received, payload)

    def test_the_receiver_actually_advertises_a_closed_window(self):
        """If this stopped happening the test above would pass vacuously."""
        lb = self._connect(capacity=4096)
        lb.client.send(b"x" * 20000)
        lb.pump()

        # Fill the server's buffer without letting it read.
        self.assertEqual(lb.server.recv_queue.window, 0)
        self.assertEqual(lb.server._advertised_window(), 0)

    def test_a_sender_that_fills_the_window_is_not_stranded(self):
        """Data sent right as the window closes must still arrive, whether it
        goes out on the first attempt or has to wait for room."""
        lb = self._connect(capacity=8192)
        payload = bytes(range(256)) * 200  # 51200 bytes, several windows' worth
        lb.client.send(payload)
        self.assertEqual(lb.drain_server(), payload)

    def test_a_lost_window_update_is_recovered_by_the_persist_timer(self):
        """If the ACK that re-opens a shut window is lost, neither side has a
        reason to speak: the sender holds data, the receiver holds room it has
        already announced but cannot mention again.  Nothing will move until
        the sender probes, and the persist timer is what makes it probe."""
        lb = self._connect(capacity=4096)
        payload = bytes((i * 17) % 256 for i in range(9000))
        lb.client.send(payload)

        lb.pump()
        received = bytearray(lb.server.recv(65536))
        self.assertEqual(len(received), 4096)

        # Throw away the acknowledgement that re-opens the window, exactly as
        # a lossy wire would.
        lb.to_client.clear()
        self.assertEqual(lb.client.peer_window, 0)
        self.assertGreater(lb.client.send_queue.unsent, 0)

        # Neither side has anything to say, so nothing moves.
        lb.pump()
        self.assertEqual(lb.server.recv(65536), b"")

        # The persist timer is the only thing that can break the tie.
        lb.clock.advance(1.0)
        lb.client.on_tick()
        self.assertGreater(lb.pump(), 0, "the persist probe was never sent")

        received.extend(lb.drain_server())
        self.assertEqual(bytes(received), payload)

    def test_the_persist_probe_is_a_single_segment(self):
        """The probe is expected to be refused, so it must be small: a full
        window's worth of bytes the peer cannot take is just waste."""
        lb = self._connect(capacity=4096)
        lb.client.send(b"z" * 9000)
        lb.pump()
        lb.server.recv(65536)
        lb.to_client.clear()

        sent_before = lb.client.snd_nxt
        lb.clock.advance(1.0)
        lb.client.on_tick()
        self.assertLessEqual(lb.client.snd_nxt - sent_before, lb.client.mss)

    def test_the_persist_timer_backs_off(self):
        """A peer that stays shut for minutes must not be probed every second
        forever, but the connection is not dead either, so it never gives up."""
        lb = self._connect(capacity=4096)
        lb.client.send(b"z" * 9000)
        lb.pump()
        lb.server.recv(65536)
        lb.to_client.clear()

        conn = lb.client
        delays = []
        for _ in range(6):
            delays.append(conn._persist_delay)
            lb.clock.advance(conn._persist_delay)
            conn.on_tick()

        self.assertGreater(delays[-1], delays[0])
        self.assertLessEqual(delays[-1], 60.0)

    def test_a_connection_with_nothing_to_send_does_not_probe(self):
        """The persist timer exists to push data, not to keep an idle
        connection warm."""
        lb = self._connect(capacity=4096)
        lb.client.send(b"tiny")
        lb.pump()
        self.assertEqual(lb.server.recv(65536), b"tiny")
        lb.clock.advance(5.0)
        lb.client.on_tick()
        self.assertIsNone(lb.client._persist_at)

    def test_scaled_windows_negotiate_and_transfer(self):
        """Window scaling is what lets the advertised field mean more than
        64 kB; the shift has to be applied identically on both sides or the
        sender and receiver disagree about how much room exists."""
        lb = self._connect(capacity=1 << 20, window_scale=4)
        self.assertEqual(lb.client.snd_wscale, 4)
        self.assertEqual(lb.server.rcv_wscale, 4)
        # The field itself is still 16 bits; the shift is what makes it mean
        # roughly a megabyte.
        self.assertEqual(lb.server._advertised_window(), 65535)
        self.assertGreater(lb.client.peer_window, 65535)

        payload = bytes((i * 31) % 256 for i in range(400000))
        lb.client.send(payload)
        self.assertEqual(lb.drain_server(), payload)

    def test_the_peer_window_is_taken_at_face_value(self):
        """RFC 793 sets the send window to whatever the segment says.  A
        shrink is not clamped, because in-flight bytes are the retransmission
        timer's responsibility, not the window's."""
        lb = self._connect()
        conn = lb.client
        conn._update_peer_window(TCPSegment(1, 2, 0, 0, 0x010, window=0))
        self.assertEqual(conn.peer_window, 0)
        conn._update_peer_window(TCPSegment(1, 2, 0, 0, 0x010, window=40000))
        self.assertEqual(conn.peer_window, 40000)

    def test_a_reopened_window_reports_itself_exactly_once(self):
        """The re-opening signal is a transition, not a state, so the caller
        resends once rather than on every subsequent segment."""
        lb = self._connect()
        conn = lb.client
        segment = TCPSegment(1, 2, 0, 0, 0x010, window=1000)

        conn._update_peer_window(segment)  # from the initial 65535, not a re-open
        self.assertFalse(conn._update_peer_window(TCPSegment(1, 2, 0, 0, 0x010, window=0)))
        self.assertFalse(conn._update_peer_window(TCPSegment(1, 2, 0, 0, 0x010, window=0)))
        self.assertTrue(conn._update_peer_window(segment))
        self.assertFalse(conn._update_peer_window(segment))


if __name__ == "__main__":
    unittest.main(verbosity=2)
