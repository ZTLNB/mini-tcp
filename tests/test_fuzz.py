"""Fuzz tests: every parser is fed malformed input until it breaks.

These are the tests that matter most for anything that touches the network,
because on a real wire every byte is attacker-controlled.  A parser has
exactly two acceptable outcomes for bad input -- reject it with ``ValueError``,
or return a best-effort object -- and one unacceptable outcome: raising
something else, which means the caller's error handling has a hole in it and
the stack will die on a packet it should have shrugged off.

Everything is seeded, so a failure here reproduces exactly.
"""

from __future__ import annotations

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitcp.net.arp import ARPPacket  # noqa: E402
from minitcp.net.ethernet import ETHERTYPE_IPV4, EthernetFrame, mac_from_str  # noqa: E402
from minitcp.net.icmp import ECHO_REQUEST, EchoMessage, ICMPMessage  # noqa: E402
from minitcp.net.ipv4 import (  # noqa: E402
    PROTO_TCP,
    PROTO_UDP,
    IPv4Packet,
    Reassembler,
    ip_to_bytes,
)
from minitcp.net.tcp import (  # noqa: E402
    ESTABLISHED,
    FLAG_ACK,
    FLAG_FIN,
    FLAG_PSH,
    FLAG_RST,
    FLAG_SYN,
    TCPConnection,
    TCPOptions,
    TCPSegment,
)
from minitcp.net.udp import UDPSegment  # noqa: E402
from minitcp.util import Reader  # noqa: E402

CLIENT_IP = ip_to_bytes("192.0.2.10")
SERVER_IP = ip_to_bytes("192.0.2.20")
CLIENT_MAC = mac_from_str("02:00:00:00:00:01")
SERVER_MAC = mac_from_str("02:00:00:00:00:02")

#: Enough iterations to cover the interesting shapes without making the suite
#: slow.  The seed makes any failure reproducible from this file alone.
ITERATIONS = 3000
SEED = 0xC0FFEE


def _random_bytes(rng: random.Random, low: int = 0, high: int = 200) -> bytes:
    return bytes(rng.randrange(256) for _ in range(rng.randint(low, high)))


def _mutated(rng: random.Random, data: bytes, flips: int = 1) -> bytes:
    """Flip a few bits or splice in a random byte, leaving the length alone.

    Length-preserving mutation is the interesting case: a parser that checks
    its lengths before reading will accept the frame and then has to cope with
    nonsense inside it.
    """
    buffer = bytearray(data)
    for _ in range(flips):
        if rng.random() < 0.5:
            index = rng.randrange(len(buffer))
            buffer[index] ^= 1 << rng.randrange(8)
        else:
            buffer[rng.randrange(len(buffer))] = rng.randrange(256)
    return bytes(buffer)


def _sample_tcp_segment() -> bytes:
    return TCPSegment(
        49152,
        80,
        0xDEADBEEF,
        0x12345678,
        FLAG_ACK | FLAG_PSH,
        64240,
        payload=b"GET / HTTP/1.0\r\n\r\n",
        options=TCPOptions(mss=1460, sack_permitted=True),
    ).to_bytes(CLIENT_IP, SERVER_IP)


def _sample_udp_segment() -> bytes:
    return UDPSegment(53, 5353, b"a dns query").to_bytes(CLIENT_IP, SERVER_IP)


def _sample_ipv4_packet(protocol: int = PROTO_TCP) -> bytes:
    payload = _sample_tcp_segment() if protocol == PROTO_TCP else _sample_udp_segment()
    return IPv4Packet(CLIENT_IP, SERVER_IP, protocol, payload, identification=7).to_bytes()


def _sample_arp_packet() -> bytes:
    return ARPPacket(1, CLIENT_MAC, CLIENT_IP, b"\x00" * 6, SERVER_IP).to_bytes()


def _sample_frame(payload: bytes, ethertype: int = ETHERTYPE_IPV4) -> bytes:
    return EthernetFrame(SERVER_MAC, CLIENT_MAC, ethertype, payload).to_bytes()


class FuzzCase(unittest.TestCase):
    """Shared helper: a parser may reject bad input, but only with ValueError."""

    def assert_survives(self, parse, data: bytes, label: str) -> None:
        try:
            parse(data)
        except ValueError:
            pass
        except Exception as exc:  # noqa: BLE001 - that is the point of the test
            self.fail(
                "%s raised %s for %d bytes of input, which a caller cannot "
                "distinguish from a bug: %r (input %s)"
                % (label, type(exc).__name__, len(data), exc, data.hex())
            )


class TestParserFuzzing(FuzzCase):
    def test_ethernet_survives_random_input(self):
        rng = random.Random(SEED)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng)
            self.assert_survives(EthernetFrame.parse, data, "EthernetFrame.parse")

    def test_ipv4_survives_random_input(self):
        rng = random.Random(SEED + 1)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng)
            self.assert_survives(IPv4Packet.parse, data, "IPv4Packet.parse")

    def test_arp_survives_random_input(self):
        rng = random.Random(SEED + 2)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng)
            self.assert_survives(ARPPacket.parse, data, "ARPPacket.parse")

    def test_udp_survives_random_input(self):
        rng = random.Random(SEED + 3)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng)
            self.assert_survives(
                lambda d: UDPSegment.parse(d, CLIENT_IP, SERVER_IP),
                data,
                "UDPSegment.parse",
            )

    def test_icmp_survives_random_input(self):
        rng = random.Random(SEED + 4)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng)
            self.assert_survives(ICMPMessage.parse, data, "ICMPMessage.parse")

    def test_tcp_survives_random_input(self):
        rng = random.Random(SEED + 5)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng)
            self.assert_survives(
                lambda d: TCPSegment.parse(d, CLIENT_IP, SERVER_IP),
                data,
                "TCPSegment.parse",
            )

    def test_tcp_options_survive_random_input(self):
        rng = random.Random(SEED + 6)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng, high=60)
            self.assert_survives(TCPOptions.parse, data, "TCPOptions.parse")

    def test_reader_survives_random_input(self):
        rng = random.Random(SEED + 7)
        for _ in range(ITERATIONS):
            data = _random_bytes(rng, high=32)
            reader = Reader(data)
            try:
                while reader.remaining > 0:
                    choice = rng.randrange(3)
                    if choice == 0:
                        reader.u8()
                    elif choice == 1:
                        reader.u16()
                    else:
                        reader.u32()
            except ValueError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail("Reader raised %s: %r" % (type(exc).__name__, exc))


class TestTruncationFuzzing(FuzzCase):
    """Every prefix of a valid packet must be rejected cleanly.

    A truncated packet is what a short read or a clipped capture looks like,
    and it is far more common in practice than random garbage.
    """

    def _check_every_prefix(self, data: bytes, parse, label: str) -> None:
        for cut in range(len(data)):
            self.assert_survives(parse, data[:cut], "%s (prefix %d)" % (label, cut))

    def test_every_prefix_of_a_tcp_segment(self):
        self._check_every_prefix(
            _sample_tcp_segment(),
            lambda d: TCPSegment.parse(d, CLIENT_IP, SERVER_IP),
            "TCPSegment.parse",
        )

    def test_every_prefix_of_a_udp_segment(self):
        self._check_every_prefix(
            _sample_udp_segment(),
            lambda d: UDPSegment.parse(d, CLIENT_IP, SERVER_IP),
            "UDPSegment.parse",
        )

    def test_every_prefix_of_an_ipv4_packet(self):
        self._check_every_prefix(_sample_ipv4_packet(), IPv4Packet.parse, "IPv4Packet.parse")

    def test_every_prefix_of_an_arp_packet(self):
        self._check_every_prefix(_sample_arp_packet(), ARPPacket.parse, "ARPPacket.parse")

    def test_every_prefix_of_an_icmp_message(self):
        wire = EchoMessage(1, 1, b"payload").to_icmp(ECHO_REQUEST).to_bytes()
        self._check_every_prefix(wire, ICMPMessage.parse, "ICMPMessage.parse")

    def test_every_prefix_of_an_ethernet_frame(self):
        self._check_every_prefix(
            _sample_frame(_sample_ipv4_packet()), EthernetFrame.parse, "EthernetFrame.parse"
        )


class TestMutationFuzzing(FuzzCase):
    """Take a valid packet, corrupt it, and make sure the parser copes.

    A checksum is supposed to catch this, so most mutations should be
    rejected; the point is that rejection must be clean.
    """

    def test_mutated_tcp_segments(self):
        rng = random.Random(SEED + 10)
        sample = _sample_tcp_segment()
        for _ in range(ITERATIONS):
            data = _mutated(rng, sample, flips=rng.randint(1, 4))
            self.assert_survives(
                lambda d: TCPSegment.parse(d, CLIENT_IP, SERVER_IP),
                data,
                "TCPSegment.parse",
            )

    def test_mutated_ipv4_packets(self):
        rng = random.Random(SEED + 11)
        sample = _sample_ipv4_packet()
        for _ in range(ITERATIONS):
            data = _mutated(rng, sample, flips=rng.randint(1, 4))
            self.assert_survives(IPv4Packet.parse, data, "IPv4Packet.parse")

    def test_mutated_frames(self):
        rng = random.Random(SEED + 12)
        sample = _sample_frame(_sample_ipv4_packet())
        for _ in range(ITERATIONS):
            data = _mutated(rng, sample, flips=rng.randint(1, 4))
            self.assert_survives(EthernetFrame.parse, data, "EthernetFrame.parse")

    def test_a_corrupt_checksum_is_always_rejected(self):
        """Not just "does not crash" -- the checksum has to actually work.

        Any single-bit flip in the TCP header or payload must be caught.
        """
        rng = random.Random(SEED + 13)
        sample = _sample_tcp_segment()
        for _ in range(500):
            index = rng.randrange(len(sample))
            bit = 1 << rng.randrange(8)
            data = bytearray(sample)
            data[index] ^= bit
            with self.assertRaises(
                ValueError, msg="flipping bit %d of byte %d went unnoticed" % (bit, index)
            ):
                TCPSegment.parse(bytes(data), CLIENT_IP, SERVER_IP)

    def test_a_corrupt_ipv4_header_checksum_is_always_rejected(self):
        rng = random.Random(SEED + 14)
        sample = _sample_ipv4_packet()
        for _ in range(500):
            index = rng.randrange(20)  # header only
            bit = 1 << rng.randrange(8)
            data = bytearray(sample)
            data[index] ^= bit
            with self.assertRaises(
                ValueError, msg="flipping bit %d of byte %d went unnoticed" % (bit, index)
            ):
                IPv4Packet.parse(bytes(data))


class TestReassemblyFuzzing(unittest.TestCase):
    """The reassembler is the one place that keeps state between packets, so
    it is where a flood of crafted fragments would be aimed."""

    def test_random_fragments_never_raise_or_grow_without_bound(self):
        rng = random.Random(SEED + 20)
        reassembler = Reassembler(timeout=30.0, max_pending=16)

        for _ in range(2000):
            packet = IPv4Packet(
                src=CLIENT_IP,
                dst=SERVER_IP,
                protocol=PROTO_UDP,
                payload=bytes(rng.randrange(256) for _ in range(rng.randint(1, 64))),
                identification=rng.randrange(65536),
                flags=rng.choice([0, 0x2000, 0x4000]),
                fragment_offset=rng.randrange(0, 8192),
            )
            try:
                reassembler.add(packet)
            except Exception as exc:  # noqa: BLE001
                self.fail("Reassembler.add raised %s: %r" % (type(exc).__name__, exc))

            self.assertLessEqual(
                reassembler.pending,
                16,
                "the pending-fragment cap did not hold; a flood of "
                "first-fragments-only would exhaust memory",
            )


class TestConnectionFuzzing(unittest.TestCase):
    """Drive a live connection with nonsense and make sure it holds together.

    The state machine is the largest attack surface in the stack: every branch
    is reachable by anyone who can send a packet.
    """

    def _established_connection(self) -> TCPConnection:
        sent: list = []
        conn = TCPConnection(
            CLIENT_IP,
            40000,
            SERVER_IP,
            80,
            lambda seg, remote_ip: sent.append(seg),
            iss=0x11111111,
        )
        conn.state = ESTABLISHED
        conn.irs = 0x22222222
        conn.send_queue = type(conn.send_queue)(0x11111111, 1 << 16)
        conn.recv_queue = type(conn.recv_queue)(0x22222222, 1 << 16)
        conn.send_queue.write(b"hello")
        return conn

    def test_random_segments_never_raise(self):
        rng = random.Random(SEED + 30)
        conn = self._established_connection()

        for _ in range(4000):
            segment = TCPSegment(
                src_port=rng.randrange(65536),
                dst_port=40000,
                seq=rng.randrange(1 << 32),
                ack=rng.randrange(1 << 32),
                flags=rng.choice([0, FLAG_ACK, FLAG_ACK | FLAG_PSH, FLAG_SYN,
                                  FLAG_FIN, FLAG_RST, FLAG_ACK | FLAG_FIN]),
                window=rng.randrange(65536),
                payload=bytes(rng.randrange(256) for _ in range(rng.randint(0, 40))),
            )
            try:
                conn.on_segment(segment, SERVER_IP, CLIENT_IP, now=1000.0)
            except Exception as exc:  # noqa: BLE001
                self.fail(
                    "on_segment raised %s for %r: %r"
                    % (type(exc).__name__, segment, exc)
                )
            self.assertLessEqual(
                conn.recv_queue.available + conn.recv_queue.held_out_of_order,
                conn.recv_queue.capacity,
                "the receive buffer outgrew its capacity",
            )

    def test_random_segments_with_random_lengths_never_raise(self):
        """Same, but with payloads long enough to be trimmed and split."""
        rng = random.Random(SEED + 31)
        conn = self._established_connection()

        for _ in range(1000):
            segment = TCPSegment(
                src_port=80,
                dst_port=40000,
                seq=rng.randrange(1 << 32),
                ack=rng.randrange(1 << 32),
                flags=FLAG_ACK | FLAG_PSH,
                window=rng.randrange(0, 2048),
                payload=bytes(rng.randrange(256) for _ in range(rng.randint(0, 9000))),
            )
            try:
                conn.on_segment(segment, SERVER_IP, CLIENT_IP, now=1000.0)
            except Exception as exc:  # noqa: BLE001
                self.fail("on_segment raised %s: %r" % (type(exc).__name__, exc))

            self.assertLessEqual(
                conn.recv_queue.available + conn.recv_queue.held_out_of_order,
                conn.recv_queue.capacity,
            )

    def test_ticking_a_fuzzed_connection_never_raises(self):
        rng = random.Random(SEED + 32)
        conn = self._established_connection()

        for _ in range(1500):
            segment = TCPSegment(
                src_port=80,
                dst_port=40000,
                seq=rng.randrange(1 << 32),
                ack=rng.randrange(1 << 32),
                flags=rng.choice([FLAG_ACK, FLAG_ACK | FLAG_PSH, FLAG_FIN, FLAG_RST]),
                window=rng.randrange(65536),
                payload=bytes(rng.randrange(256) for _ in range(rng.randint(0, 200))),
            )
            conn.on_segment(segment, SERVER_IP, CLIENT_IP, now=1000.0)
            try:
                conn.on_tick(now=1000.0 + rng.random() * 30.0)
            except Exception as exc:  # noqa: BLE001
                self.fail("on_tick raised %s: %r" % (type(exc).__name__, exc))


class TestEndToEndFuzzing(unittest.TestCase):
    """Frames from a hostile peer must not take the stack down either."""

    def test_random_frames_through_a_listening_stack(self):
        from minitcp.link import SimulatedLink, VirtualWire
        from minitcp.stack import Stack

        rng = random.Random(SEED + 40)
        link = SimulatedLink(SERVER_MAC, VirtualWire())
        stack = Stack(link, SERVER_IP, 24)
        stack.tcp_listen(80)

        for _ in range(3000):
            size = rng.randint(0, 120)
            frame = bytes(rng.randrange(256) for _ in range(size))
            stack.handle_frame(frame)

        self.assertGreater(stack.stats["malformed"], 0)
        self.assertEqual(stack.stats["errors"], 0, stack.stats["last_error"])
        stack.stop()

    def test_mutated_valid_frames_through_a_listening_stack(self):
        """The realistic attack: a well-formed frame with a crafted payload."""
        from minitcp.link import SimulatedLink, VirtualWire
        from minitcp.stack import Stack

        rng = random.Random(SEED + 41)
        link = SimulatedLink(SERVER_MAC, VirtualWire())
        stack = Stack(link, SERVER_IP, 24)
        stack.tcp_listen(80)

        samples = [
            _sample_frame(_sample_ipv4_packet(PROTO_TCP)),
            _sample_frame(_sample_ipv4_packet(PROTO_UDP)),
            _sample_frame(_sample_arp_packet(), ethertype=0x0806),
        ]

        for _ in range(3000):
            data = _mutated(rng, rng.choice(samples), flips=rng.randint(1, 6))
            stack.handle_frame(data)

        self.assertEqual(stack.stats["errors"], 0, stack.stats["last_error"])
        stack.stop()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
