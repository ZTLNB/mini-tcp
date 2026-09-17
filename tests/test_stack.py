"""Integration tests for the whole stack, driven through the socket API.

These tests exercise the real path end to end: an application calls ``sendall``,
the bytes become a TCP segment, the segment becomes an IPv4 datagram, the
datagram becomes an Ethernet frame, and the frame crosses a virtual wire into
a second independent stack that unwraps it all again.

Nothing is stubbed.  Two complete stacks with their own ARP caches, routing
tables, connection tables and background threads talk to each other.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitcp.link import FaultProfile, SimulatedLink, VirtualWire  # noqa: E402
from minitcp.socket import (  # noqa: E402
    AF_INET,
    SOCK_DGRAM,
    SOCK_STREAM,
    socket,
)
from minitcp.stack import Stack  # noqa: E402

MAC_A = bytes([0x02, 0, 0, 0, 0, 0x01])
MAC_B = bytes([0x02, 0, 0, 0, 0, 0x02])

IP_A = "10.0.0.1"
IP_B = "10.0.0.2"


class StackPair:
    """Two stacks joined by a wire, torn down together."""

    def __init__(self, fault: FaultProfile | None = None) -> None:
        self.wire = VirtualWire(fault)
        self.link_a = SimulatedLink(MAC_A, self.wire, name="A")
        self.link_b = SimulatedLink(MAC_B, self.wire, name="B")
        self.stack_a = Stack(self.link_a, IP_A, 24)
        self.stack_b = Stack(self.link_b, IP_B, 24)

    def start(self) -> "StackPair":
        self.stack_a.start()
        self.stack_b.start()
        return self

    def stop(self) -> None:
        for stack in (self.stack_a, self.stack_b):
            try:
                stack.stop(timeout=1.0)
            except Exception:
                pass

    def __enter__(self) -> "StackPair":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()


class TestTcpOverTheStack(unittest.TestCase):
    def setUp(self) -> None:
        self.pair = StackPair().start()
        self.addCleanup(self.pair.stop)

    def _listen(self, port: int = 8080):
        server = socket(self.pair.stack_b, AF_INET, SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen()
        server.settimeout(5.0)
        return server

    def test_connect_and_round_trip(self) -> None:
        server = self._listen()

        client = socket(self.pair.stack_a, AF_INET, SOCK_STREAM)
        client.settimeout(5.0)
        client.connect((IP_B, 8080))

        conn, address = server.accept()
        self.assertEqual(address[0], IP_A)
        self.assertEqual(address[1], client.getsockname()[1])

        client.sendall(b"hello over a hand-built stack")
        self.assertEqual(conn.recv(4096), b"hello over a hand-built stack")

        conn.sendall(b"and back again")
        self.assertEqual(client.recv(4096), b"and back again")

        client.close()
        conn.close()
        server.close()

    def test_arp_resolution_happens_automatically(self) -> None:
        server = self._listen(8081)
        client = socket(self.pair.stack_a, AF_INET, SOCK_STREAM)
        client.settimeout(5.0)
        client.connect((IP_B, 8081))

        # The client had to resolve the server's MAC before its SYN could leave.
        self.assertGreaterEqual(self.pair.stack_a.stats["arp_requests_sent"], 1)
        self.assertIn(
            bytes([10, 0, 0, 2]),
            self.pair.stack_a.arp_cache.snapshot(),
            "the server address was never learned",
        )

        client.close()
        server.close()

    def test_large_transfer_across_many_segments(self) -> None:
        server = self._listen(8082)
        client = socket(self.pair.stack_a, AF_INET, SOCK_STREAM)
        client.settimeout(20.0)
        client.connect((IP_B, 8082))
        conn, _ = server.accept()
        conn.settimeout(20.0)

        payload = bytes((i * 31) % 256 for i in range(300000))
        received = bytearray()

        def reader() -> None:
            while len(received) < len(payload):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)

        thread = threading.Thread(target=reader)
        thread.start()
        client.sendall(payload)
        thread.join(timeout=25)

        self.assertEqual(len(received), len(payload))
        self.assertEqual(bytes(received), payload)

        client.close()
        conn.close()
        server.close()

    def test_bidirectional_concurrent_transfer(self) -> None:
        server = self._listen(8083)
        client = socket(self.pair.stack_a, AF_INET, SOCK_STREAM)
        client.settimeout(15.0)
        client.connect((IP_B, 8083))
        conn, _ = server.accept()
        conn.settimeout(15.0)

        up = b"client to server " * 500
        down = b"server to client " * 500

        results: dict[str, bytes] = {}

        def server_side() -> None:
            # Read until the client half-closes, then answer and half-close in
            # turn.  Closing only after the reply is what lets the client see
            # end of stream.
            results["up"] = conn.recv_all()
            conn.sendall(down)
            conn.shutdown()

        thread = threading.Thread(target=server_side)
        thread.start()

        client.sendall(up)
        client.shutdown()
        results["down"] = client.recv_all()
        thread.join(timeout=15)

        self.assertEqual(results.get("up"), up)
        self.assertEqual(results.get("down"), down)

        conn.close()
        server.close()

    def test_connection_refused_when_nothing_listens(self) -> None:
        client = socket(self.pair.stack_a, AF_INET, SOCK_STREAM)
        client.settimeout(3.0)
        with self.assertRaises((ConnectionRefusedError, TimeoutError)):
            client.connect((IP_B, 9999))
        client.close()

    def test_graceful_close_delivers_trailing_data(self) -> None:
        server = self._listen(8084)
        client = socket(self.pair.stack_a, AF_INET, SOCK_STREAM)
        client.settimeout(5.0)
        client.connect((IP_B, 8084))
        conn, _ = server.accept()
        conn.settimeout(5.0)

        client.sendall(b"final message")
        client.close()

        self.assertEqual(conn.recv_all(), b"final message")
        conn.close()
        server.close()


class TestUdpOverTheStack(unittest.TestCase):
    def setUp(self) -> None:
        self.pair = StackPair().start()
        self.addCleanup(self.pair.stop)

    def test_datagram_round_trip(self) -> None:
        server = socket(self.pair.stack_b, AF_INET, SOCK_DGRAM)
        server.bind(("0.0.0.0", 5353))
        server.settimeout(5.0)

        client = socket(self.pair.stack_a, AF_INET, SOCK_DGRAM)
        client.bind(("0.0.0.0", 44444))
        client.sendto(b"dns query?", (IP_B, 5353))

        payload, address = server.recvfrom(4096)
        self.assertEqual(payload, b"dns query?")
        self.assertEqual(address[0], IP_A)

        server.sendto(b"answer", (IP_A, 44444))
        reply, _ = client.recvfrom(4096)
        self.assertEqual(reply, b"answer")

        client.close()
        server.close()

    def test_datagrams_are_independent(self) -> None:
        server = socket(self.pair.stack_b, AF_INET, SOCK_DGRAM)
        server.bind(("0.0.0.0", 5354))
        server.settimeout(5.0)

        client = socket(self.pair.stack_a, AF_INET, SOCK_DGRAM)
        for index in range(5):
            client.sendto(b"packet %d" % index, (IP_B, 5354))

        seen = [server.recvfrom(1024)[0] for _ in range(5)]
        self.assertEqual(seen, [b"packet %d" % i for i in range(5)])

        client.close()
        server.close()


class TestIcmpPing(unittest.TestCase):
    def test_stack_answers_echo_requests(self) -> None:
        from minitcp.net.ethernet import ETHERTYPE_IPV4, EthernetFrame
        from minitcp.net.icmp import ECHO_REPLY, ECHO_REQUEST, EchoMessage, ICMPMessage
        from minitcp.net.ipv4 import PROTO_ICMP, IPv4Packet, ip_to_bytes

        # A tap endpoint stands in for the client.  It is deliberately not a
        # Stack, because a Stack would run its own reader thread and the two
        # would fight over the frames.
        wire = VirtualWire()
        link_b = SimulatedLink(MAC_B, wire, name="B")
        tap_mac = bytes([0x02, 0, 0, 0, 0, 0xAA])
        tap = SimulatedLink(tap_mac, wire, name="tap")

        stack_b = Stack(link_b, IP_B, 24).start()
        self.addCleanup(stack_b.stop)

        # Seed the cache so the reply needs no ARP exchange.
        stack_b.arp_cache.store(ip_to_bytes(IP_A), tap_mac)

        request = (
            EchoMessage(0x1234, 1, b"ping payload").to_icmp(ECHO_REQUEST).to_bytes()
        )
        tap.send_frame(
            EthernetFrame(
                dst=MAC_B,
                src=tap_mac,
                ethertype=ETHERTYPE_IPV4,
                payload=IPv4Packet(
                    src=ip_to_bytes(IP_A),
                    dst=ip_to_bytes(IP_B),
                    protocol=PROTO_ICMP,
                    payload=request,
                ).to_bytes(),
            ).to_bytes()
        )

        replies = []
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not replies:
            raw = tap.recv_frame(timeout=0.2)
            if raw is None:
                continue
            frame = EthernetFrame.parse(raw)
            if frame.ethertype != ETHERTYPE_IPV4:
                continue
            packet = IPv4Packet.parse(frame.payload)
            if packet.protocol == PROTO_ICMP:
                replies.append(ICMPMessage.parse(packet.payload))

        self.assertTrue(replies, "no ICMP reply came back")
        reply = replies[0]
        self.assertEqual(reply.type, ECHO_REPLY)
        echo = EchoMessage.from_icmp(reply)
        self.assertEqual(echo.identifier, 0x1234)
        self.assertEqual(echo.data, b"ping payload")


class TestLossyNetwork(unittest.TestCase):
    def test_transfer_survives_ten_percent_loss(self) -> None:
        """Reliability is the whole point of TCP, so prove it under loss."""
        fault = FaultProfile(loss=0.10, seed=1234)
        pair = StackPair(fault).start()
        self.addCleanup(pair.stop)

        server = socket(pair.stack_b, AF_INET, SOCK_STREAM)
        server.bind(("0.0.0.0", 9000))
        server.listen()
        server.settimeout(60.0)

        client = socket(pair.stack_a, AF_INET, SOCK_STREAM)
        client.settimeout(60.0)
        client.connect((IP_B, 9000))
        conn, _ = server.accept()
        conn.settimeout(60.0)

        payload = bytes((i * 13) % 256 for i in range(20000))
        received = bytearray()

        def reader() -> None:
            while len(received) < len(payload):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)

        thread = threading.Thread(target=reader)
        thread.start()
        client.sendall(payload)
        thread.join(timeout=60)

        self.assertEqual(len(received), len(payload), "data was lost despite TCP")
        self.assertEqual(bytes(received), payload)

        stats = pair.wire.stats()
        self.assertGreater(stats["dropped"], 0, "the wire never actually dropped anything")

        client.close()
        conn.close()
        server.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
