"""The protocol stack: demultiplexing, routing, ARP resolution and timers.

:class:`Stack` is the piece that turns a pile of parsers into something that
behaves like a network interface.  It owns one link, one IPv4 address and one
set of protocol handlers, and it does four jobs:

**Demultiplexing.**  A frame arrives, gets peeled apart layer by layer, and is
handed to whichever connection or handler claims it.  The order matters: ARP
before IP, IP fragments reassembled before the transport layer, and within TCP
the four-tuple ``(local_ip, local_port, remote_ip, remote_port)`` decides which
connection sees the segment.

**Address resolution.**  IPv4 addresses mean nothing to Ethernet, so a frame
cannot be built until ARP has supplied a MAC address.  Rather than block, the
stack parks outgoing packets against the unresolved address and flushes them the
moment a reply arrives.  A burst of packets to a new peer therefore costs one
ARP exchange, not one per packet.

**Timers.**  A background thread wakes on a fixed interval and calls
``on_tick`` on every connection.  Retransmission, delayed ACKs and TIME-WAIT
expiry all run from that single thread, so no connection needs a timer of its
own.

**Routing.**  Deciding whether a destination is on-link or must go through the
gateway is one line of subnet arithmetic, but getting it wrong means nothing
leaves the machine.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from .link.base import Link
from .net.arp import ARP_REPLY, ARP_REQUEST, ARPCache, ARPPacket
from .net.ethernet import (
    BROADCAST_MAC,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
)
from .net.icmp import ECHO_REPLY, ECHO_REQUEST, EchoMessage, ICMPMessage
from .net.ipv4 import (
    IP_ANY,
    IP_BROADCAST,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    IPv4Packet,
    Reassembler,
    ip_to_bytes,
    ip_to_str,
    prefix_to_mask,
    same_subnet,
)
from .net.tcp.connection import TCPConnection
from .net.tcp.segment import FLAG_ACK, FLAG_RST, TCPSegment
from .net.tcp.seqno import seq_add
from .net.udp import UDPSegment

__all__ = ["Stack", "StackError"]

#: Ephemeral ports are handed out from here, matching common practice.
FIRST_EPHEMERAL_PORT = 49152
LAST_EPHEMERAL_PORT = 65535


class StackError(RuntimeError):
    """Raised for configuration and lifecycle problems."""


class Stack:
    """A complete IPv4/TCP/UDP stack attached to a single link."""

    def __init__(
        self,
        link: Link,
        ip: bytes | str,
        netmask: bytes | str | int = 24,
        gateway: bytes | str | None = None,
        *,
        tick_interval: float = 0.01,
        promiscuous: bool = False,
        max_arp_pending: int = 32,
        receive_capacity: int = 65535,
    ) -> None:
        self.link = link
        self.mac = link.mac
        self.ip = ip_to_bytes(ip) if isinstance(ip, str) else bytes(ip)
        self.netmask = self._coerce_netmask(netmask)
        if gateway is None:
            self.gateway = None
        else:
            self.gateway = (
                ip_to_bytes(gateway) if isinstance(gateway, str) else bytes(gateway)
            )

        self.promiscuous = promiscuous
        self.receive_capacity = receive_capacity

        self.arp_cache = ARPCache()
        self.reassembler = Reassembler()

        self._lock = threading.RLock()
        self._connections: dict[tuple, TCPConnection] = {}
        self._listeners: dict[int, TCPConnection] = {}
        self._accept_queues: dict[int, deque] = {}
        self._read_events: dict[TCPConnection, threading.Event] = {}
        self._udp_handlers: dict[int, Callable] = {}
        self._arp_pending: dict[bytes, list[IPv4Packet]] = {}

        self._max_arp_pending = max_arp_pending
        self._next_port = FIRST_EPHEMERAL_PORT
        self._next_id = 1

        self._tick_interval = tick_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        self.stats = {
            "frames_in": 0,
            "frames_out": 0,
            "frames_dropped": 0,
            "ipv4_in": 0,
            "ipv4_out": 0,
            "arp_requests_sent": 0,
            "arp_replies_sent": 0,
            "icmp_echo_replied": 0,
            "tcp_in": 0,
            "tcp_out": 0,
            "udp_in": 0,
            "udp_out": 0,
            "reassembly_failures": 0,
            "malformed": 0,
            #: Unexpected exceptions caught in the reader thread.  These are
            #: bugs, not bad packets, so they are counted separately and the
            #: message is kept -- a silently dying reader thread looks exactly
            #: like a quiet network, which is a miserable thing to debug.
            "errors": 0,
            "last_error": None,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> "Stack":
        """Start the background reader and timer thread."""
        if self._running:
            return self
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="minitcp-stack", daemon=True
        )
        self._thread.start()
        return self

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the background thread and release the link."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)
        self.link.close()

    def __enter__(self) -> "Stack":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()

    def _run(self) -> None:
        """Reader and timer loop.

        The link is polled with a short timeout rather than blocked on
        indefinitely, so the timer still fires when the network is quiet.
        """
        next_tick = time.monotonic()
        while self._running:
            try:
                frame = self.link.recv_frame(timeout=self._tick_interval)
            except Exception:
                if not self._running:
                    break
                frame = None

            if frame is not None:
                self.stats["frames_in"] += 1
                try:
                    self.handle_frame(frame)
                except Exception as exc:  # noqa: BLE001 - the thread must survive
                    # handle_frame already deals with malformed packets, so
                    # anything reaching here is a bug in this stack.  Record
                    # it rather than letting the reader thread die.
                    self.stats["errors"] += 1
                    self.stats["last_error"] = "%s: %s" % (type(exc).__name__, exc)

            now = time.monotonic()
            if now >= next_tick:
                self.tick(now)
                next_tick = now + self._tick_interval

    def tick(self, now: float | None = None) -> None:
        """Advance every connection's timers.  Called by the reader thread."""
        now = time.monotonic() if now is None else now
        with self._lock:
            connections = list(self._connections.values())
        for conn in connections:
            try:
                conn.on_tick(now)
            except Exception as exc:  # noqa: BLE001 - one bad connection must
                # not stop the timer for every other connection.
                self.stats["errors"] += 1
                self.stats["last_error"] = "%s: %s" % (type(exc).__name__, exc)
        self.arp_cache.expire(now)

    # ------------------------------------------------------------------
    # Inbound path
    # ------------------------------------------------------------------

    def handle_frame(self, raw: bytes) -> None:
        """Process one raw Ethernet frame.

        A frame that cannot be decoded is dropped and counted, not raised: on
        a real segment, malformed input is routine, and a stack that throws on
        it hands any passer-by a denial of service.  The same goes for a
        well-formed frame whose payload turns out to be nonsense.

        Anything other than ``ValueError`` is a genuine bug and is allowed to
        propagate, so that it surfaces instead of being swallowed here.
        """
        try:
            frame = EthernetFrame.parse(raw)

            if not self.promiscuous and not frame.accepted_by(self.mac):
                self.stats["frames_dropped"] += 1
                return

            if frame.ethertype == ETHERTYPE_ARP:
                self._handle_arp(frame)
            elif frame.ethertype == ETHERTYPE_IPV4:
                self._handle_ipv4_frame(frame)
            else:
                self.stats["frames_dropped"] += 1
        except ValueError:
            self.stats["malformed"] += 1

    def _handle_arp(self, frame: EthernetFrame) -> None:
        packet = ARPPacket.parse(frame.payload)

        # Any ARP traffic teaches us where the sender lives.  Learning from
        # requests as well as replies is what keeps a busy segment quiet.
        self.arp_cache.store(packet.sender_ip, packet.sender_mac)

        if packet.is_request and packet.target_ip == self.ip:
            reply = ARPPacket(
                operation=ARP_REPLY,
                sender_mac=self.mac,
                sender_ip=self.ip,
                target_mac=packet.sender_mac,
                target_ip=packet.sender_ip,
            )
            self.stats["arp_replies_sent"] += 1
            self._emit(packet.sender_mac, ETHERTYPE_ARP, reply.to_bytes())
        elif packet.is_reply:
            self._flush_pending(packet.sender_ip, packet.sender_mac)

    def _handle_ipv4_frame(self, frame: EthernetFrame) -> None:
        try:
            packet = IPv4Packet.parse(frame.payload)
        except ValueError:
            self.stats["malformed"] += 1
            return

        self.stats["ipv4_in"] += 1

        if packet.is_fragmented:
            rebuilt = self.reassembler.add(packet)
            if rebuilt is None:
                return
            packet = rebuilt

        if packet.dst != self.ip and packet.dst != IP_BROADCAST:
            self.stats["frames_dropped"] += 1
            return

        self._dispatch_ipv4(packet)

    def _dispatch_ipv4(self, packet: IPv4Packet) -> None:
        try:
            if packet.protocol == PROTO_ICMP:
                self._handle_icmp(packet)
            elif packet.protocol == PROTO_TCP:
                self._handle_tcp(packet)
            elif packet.protocol == PROTO_UDP:
                self._handle_udp(packet)
        except ValueError:
            self.stats["malformed"] += 1

    def _handle_icmp(self, packet: IPv4Packet) -> None:
        message = ICMPMessage.parse(packet.payload)

        if message.type != ECHO_REQUEST:
            return

        # Answer pings aimed at us; this is what makes the stack pingable.
        echo = EchoMessage.from_icmp(message)
        reply = echo.to_icmp(ECHO_REPLY)
        self.stats["icmp_echo_replied"] += 1
        self.send_ipv4(
            IPv4Packet(
                src=self.ip,
                dst=packet.src,
                protocol=PROTO_ICMP,
                payload=reply.to_bytes(),
                ttl=64,
                identification=self._allocate_id(),
            )
        )

    def _handle_tcp(self, packet: IPv4Packet) -> None:
        segment = TCPSegment.parse(packet.payload, packet.src, packet.dst)
        self.stats["tcp_in"] += 1

        key = (packet.dst, segment.dst_port, packet.src, segment.src_port)
        with self._lock:
            conn = self._connections.get(key)
            listener = self._listeners.get(segment.dst_port)

        if conn is not None:
            conn.on_segment(segment, packet.src, packet.dst)
            return

        if listener is not None:
            listener.on_segment(segment, packet.src, packet.dst)
            return

        # Nothing owns this port; the peer deserves to know.
        self._send_reset(packet, segment)

    def _handle_udp(self, packet: IPv4Packet) -> None:
        segment = UDPSegment.parse(packet.payload, packet.src, packet.dst)
        self.stats["udp_in"] += 1

        with self._lock:
            handler = self._udp_handlers.get(segment.dst_port)
        if handler is not None:
            handler(segment.payload, packet.src, segment.src_port)

    def _send_reset(self, packet: IPv4Packet, segment: TCPSegment) -> None:
        if segment.is_rst:
            return
        reset = TCPSegment(
            src_port=segment.dst_port,
            dst_port=segment.src_port,
            seq=segment.ack if segment.is_ack else 0,
            ack=seq_add(segment.seq, segment.seq_len) if not segment.is_ack else 0,
            flags=FLAG_RST | (0 if segment.is_ack else FLAG_ACK),
            window=0,
        )
        self.send_ipv4(
            IPv4Packet(
                src=self.ip,
                dst=packet.src,
                protocol=PROTO_TCP,
                payload=reset.to_bytes(self.ip, packet.src),
                ttl=64,
                identification=self._allocate_id(),
            )
        )

    # ------------------------------------------------------------------
    # Outbound path
    # ------------------------------------------------------------------

    def send_ipv4(self, packet: IPv4Packet) -> bool:
        """Send a datagram, resolving the next hop's MAC if necessary.

        Returns ``False`` when the packet had to be parked pending an ARP
        reply, in which case it will be sent automatically once that arrives.
        """
        if packet.dst == IP_BROADCAST:
            self._emit(BROADCAST_MAC, ETHERTYPE_IPV4, packet.to_bytes())
            return True

        next_hop = self._next_hop(packet.dst)
        mac = self.arp_cache.lookup(next_hop)

        if mac is None:
            self._park_pending(next_hop, packet)
            return False

        self._emit(mac, ETHERTYPE_IPV4, packet.to_bytes())
        return True

    def _next_hop(self, dst: bytes) -> bytes:
        """On-link destinations go direct; everything else goes via the gateway."""
        if same_subnet(dst, self.ip, self.netmask):
            return dst
        if self.gateway is not None:
            return self.gateway
        return dst

    def _emit(self, dst_mac: bytes, ethertype: int, payload: bytes) -> None:
        frame = EthernetFrame(dst=dst_mac, src=self.mac, ethertype=ethertype,
                              payload=payload)
        self.stats["frames_out"] += 1
        if ethertype == ETHERTYPE_IPV4:
            self.stats["ipv4_out"] += 1
        self.link.send_frame(frame.to_bytes())

    def _park_pending(self, ip: bytes, packet: IPv4Packet) -> None:
        with self._lock:
            queue = self._arp_pending.setdefault(ip, [])
            if len(queue) >= self._max_arp_pending:
                self.stats["frames_dropped"] += 1
                return
            queue.append(packet)
        self._send_arp_request(ip)

    def _flush_pending(self, ip: bytes, mac: bytes) -> None:
        with self._lock:
            queue = self._arp_pending.pop(ip, [])
        for packet in queue:
            self._emit(mac, ETHERTYPE_IPV4, packet.to_bytes())

    def _send_arp_request(self, target_ip: bytes) -> None:
        request = ARPPacket(
            operation=ARP_REQUEST,
            sender_mac=self.mac,
            sender_ip=self.ip,
            target_mac=b"\x00" * 6,
            target_ip=target_ip,
        )
        self.stats["arp_requests_sent"] += 1
        self._emit(BROADCAST_MAC, ETHERTYPE_ARP, request.to_bytes())

    # ------------------------------------------------------------------
    # TCP API
    # ------------------------------------------------------------------

    def tcp_listen(self, port: int, backlog: int = 16) -> TCPConnection:
        """Register a listening socket on *port*."""
        with self._lock:
            if port in self._listeners:
                raise StackError("port %d is already listening" % port)
            listener = TCPConnection(
                self.ip,
                port,
                IP_ANY,
                0,
                self._transmit_segment,
                receive_capacity=self.receive_capacity,
                on_accept=lambda child: self._enqueue_accept(port, child),
                on_closed=lambda conn: self._forget(conn),
            )
            listener.listen()
            self._listeners[port] = listener
            self._accept_queues[port] = deque()
        return listener

    def tcp_accept(self, port: int, timeout: float | None = None) -> TCPConnection:
        """Wait for and return the next inbound connection on *port*."""
        with self._lock:
            queue = self._accept_queues.get(port)
            if queue is None:
                raise StackError("port %d is not listening" % port)

        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                if self._accept_queues.get(port):
                    return self._accept_queues[port].popleft()
            remaining = 0.05
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("no connection arrived on port %d" % port)
                remaining = min(remaining, left)
            time.sleep(remaining)

    def tcp_connect(
        self,
        remote_ip: bytes | str,
        remote_port: int,
        local_port: int = 0,
        timeout: float = 5.0,
    ) -> TCPConnection:
        """Open a connection and block until the handshake completes."""
        remote_ip = (
            ip_to_bytes(remote_ip) if isinstance(remote_ip, str) else bytes(remote_ip)
        )
        local_port = local_port or self._allocate_port()

        established = threading.Event()
        failed = threading.Event()

        conn = TCPConnection(
            self.ip,
            local_port,
            remote_ip,
            remote_port,
            self._transmit_segment,
            receive_capacity=self.receive_capacity,
            on_established=lambda c: established.set(),
            on_closed=lambda c: (established.set(), failed.set()),
            on_reset=lambda c: failed.set(),
        )
        with self._lock:
            self._connections[(self.ip, local_port, remote_ip, remote_port)] = conn
            self._read_events[conn] = threading.Event()

        conn.connect()
        if not established.wait(timeout):
            conn.abort()
            self._forget(conn)
            raise TimeoutError(
                "connection to %s:%d timed out"
                % (ip_to_str(remote_ip), remote_port)
            )
        if failed.is_set() and not conn.is_established:
            self._forget(conn)
            raise ConnectionRefusedError(
                "connection to %s:%d was refused"
                % (ip_to_str(remote_ip), remote_port)
            )
        return conn

    def tcp_close(self, conn: TCPConnection, timeout: float = 5.0) -> None:
        """Close a connection, waiting briefly for the handshake to finish."""
        conn.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if conn.is_closed:
                break
            time.sleep(0.01)

    def wait_readable(self, conn: TCPConnection, timeout: float | None = None) -> bool:
        """Block until *conn* has data, or the timeout expires."""
        with self._lock:
            event = self._read_events.get(conn)
        if event is None:
            return False
        if conn.recv_queue.available:
            return True
        return event.wait(timeout)

    # ------------------------------------------------------------------
    # UDP API
    # ------------------------------------------------------------------

    def udp_bind(self, port: int, handler: Callable) -> None:
        """Register *handler(payload, src_ip, src_port)* for inbound datagrams."""
        with self._lock:
            self._udp_handlers[port] = handler

    def udp_unbind(self, port: int) -> None:
        with self._lock:
            self._udp_handlers.pop(port, None)

    def udp_send(
        self,
        payload: bytes,
        remote_ip: bytes | str,
        remote_port: int,
        local_port: int = 0,
    ) -> bool:
        """Send one datagram."""
        remote_ip = (
            ip_to_bytes(remote_ip) if isinstance(remote_ip, str) else bytes(remote_ip)
        )
        segment = UDPSegment(
            src_port=local_port or self._allocate_port(),
            dst_port=remote_port,
            payload=payload,
        )
        self.stats["udp_out"] += 1
        return self.send_ipv4(
            IPv4Packet(
                src=self.ip,
                dst=remote_ip,
                protocol=PROTO_UDP,
                payload=segment.to_bytes(self.ip, remote_ip),
                ttl=64,
                identification=self._allocate_id(),
            )
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _transmit_segment(self, segment: TCPSegment, remote_ip: bytes) -> None:
        """The callback every TCP connection uses to put a segment on the wire."""
        self.stats["tcp_out"] += 1
        self.send_ipv4(
            IPv4Packet(
                src=self.ip,
                dst=remote_ip,
                protocol=PROTO_TCP,
                payload=segment.to_bytes(self.ip, remote_ip),
                ttl=64,
                identification=self._allocate_id(),
            )
        )

    def _enqueue_accept(self, port: int, child: TCPConnection) -> None:
        key = (self.ip, child.local_port, child.remote_ip, child.remote_port)
        with self._lock:
            self._connections[key] = child
            self._read_events[child] = threading.Event()
            child.on_data = lambda c: self._signal_readable(c)
            child.on_closed = lambda c: self._forget(c)
            queue = self._accept_queues.get(port)
            if queue is not None:
                queue.append(child)

    def _signal_readable(self, conn: TCPConnection) -> None:
        with self._lock:
            event = self._read_events.get(conn)
        if event is not None:
            event.set()

    def _forget(self, conn: TCPConnection) -> None:
        with self._lock:
            self._read_events.pop(conn, None)
            for key, value in list(self._connections.items()):
                if value is conn:
                    del self._connections[key]

    def _allocate_port(self) -> int:
        with self._lock:
            for _ in range(LAST_EPHEMERAL_PORT - FIRST_EPHEMERAL_PORT):
                port = self._next_port
                self._next_port += 1
                if self._next_port > LAST_EPHEMERAL_PORT:
                    self._next_port = FIRST_EPHEMERAL_PORT
                if not self._port_in_use(port):
                    return port
        raise StackError("no ephemeral ports available")

    def _port_in_use(self, port: int) -> bool:
        if port in self._listeners:
            return True
        return any(key[1] == port for key in self._connections)

    def _allocate_id(self) -> int:
        with self._lock:
            value = self._next_id
            self._next_id = (self._next_id + 1) & 0xFFFF
            if self._next_id == 0:
                self._next_id = 1
            return value

    @staticmethod
    def _coerce_netmask(value: bytes | str | int) -> bytes:
        if isinstance(value, int):
            return prefix_to_mask(value)
        if isinstance(value, str):
            return ip_to_bytes(value)
        if len(value) != 4:
            raise StackError("a netmask is 4 bytes")
        return bytes(value)

    @property
    def connections(self) -> list[TCPConnection]:
        with self._lock:
            return list(self._connections.values())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Stack %s/%d mac=%s>" % (
            ip_to_str(self.ip),
            bin(int.from_bytes(self.netmask, "big")).count("1"),
            self.mac.hex(":"),
        )
