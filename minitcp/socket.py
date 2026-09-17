"""A BSD-style socket API on top of the stack.

The point of this layer is familiarity.  Anyone who has written a Python
network client already knows ``connect``, ``sendall`` and ``recv``, so wrapping
the stack in those names means the example programs look like ordinary
networking code rather than like a protocol exercise.

The mapping is not one-to-one, and the differences are worth knowing:

* ``recv`` returns ``b""`` to mean end of stream, exactly like the standard
  library, so the usual ``while chunk := sock.recv(n)`` loop works unchanged.
* Blocking is implemented with condition polling rather than OS primitives.
  A ``timeout`` of ``None`` blocks indefinitely; anything else raises
  :class:`TimeoutError`.
* UDP sockets receive into an internal queue, so ``recvfrom`` never loses a
  datagram that arrived while the application was busy.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from .net.ipv4 import ip_to_bytes, ip_to_str
from .net.tcp.state import CLOSED, is_closed

__all__ = [
    "AF_INET",
    "SOCK_STREAM",
    "SOCK_DGRAM",
    "SHUT_RD",
    "SHUT_WR",
    "SHUT_RDWR",
    "socket",
    "create_connection",
]

AF_INET = 2
SOCK_STREAM = 1
SOCK_DGRAM = 2

SHUT_RD = 0
SHUT_WR = 1
SHUT_RDWR = 2

DEFAULT_BACKLOG = 16
_POLL_INTERVAL = 0.01


class socket:
    """A connection endpoint, modelled on :class:`socket.socket`."""

    def __init__(self, stack, family: int = AF_INET, type: int = SOCK_STREAM) -> None:
        if family != AF_INET:
            raise ValueError("only AF_INET is supported")
        if type not in (SOCK_STREAM, SOCK_DGRAM):
            raise ValueError("only SOCK_STREAM and SOCK_DGRAM are supported")

        self.stack = stack
        self.family = family
        self.type = type
        self.timeout: float | None = None

        self._bound_port: int | None = None
        self._conn = None
        self._listener = None
        self._closed = False

        self._udp_queue: deque = deque()
        self._udp_event = threading.Event()

    # ------------------------------------------------------------------
    # Address handling
    # ------------------------------------------------------------------

    def bind(self, address: tuple) -> None:
        """Bind to ``(host, port)``.

        The host is accepted for compatibility but ignored: this stack has one
        address, so binding is really about claiming a port.
        """
        self._check_open()
        _, port = address
        if not 0 <= port <= 0xFFFF:
            raise ValueError("port out of range")
        self._bound_port = port

        if self.type == SOCK_DGRAM:
            self.stack.udp_bind(port, self._on_udp)

    def listen(self, backlog: int = DEFAULT_BACKLOG) -> None:
        """Start accepting connections.  Only valid for stream sockets."""
        self._check_open()
        if self.type != SOCK_STREAM:
            raise OSError("listen() requires a stream socket")
        if self._bound_port is None:
            raise OSError("bind() must be called before listen()")
        self._listener = self.stack.tcp_listen(self._bound_port, backlog)

    def accept(self) -> tuple["socket", tuple]:
        """Block until a connection arrives; returns ``(socket, address)``."""
        self._check_open()
        if self._listener is None:
            raise OSError("listen() must be called before accept()")

        child = self.stack.tcp_accept(self._bound_port, self.timeout)

        peer = socket(self.stack, self.family, self.type)
        peer.timeout = self.timeout
        peer._conn = child
        peer._bound_port = child.local_port
        return peer, (ip_to_str(child.remote_ip), child.remote_port)

    def connect(self, address: tuple) -> None:
        """Open a connection, blocking until the handshake completes."""
        self._check_open()
        host, port = address

        if self.type == SOCK_DGRAM:
            # Datagram sockets have no handshake; just remember the peer.
            self._peer = (ip_to_bytes(host), port)
            if self._bound_port is None:
                self._bound_port = 0
            return

        timeout = 5.0 if self.timeout is None else self.timeout
        self._conn = self.stack.tcp_connect(
            host, port, self._bound_port or 0, timeout=timeout
        )
        self._bound_port = self._conn.local_port

    def connect_ex(self, address: tuple) -> int:
        """Like :meth:`connect` but returns an error code instead of raising."""
        try:
            self.connect(address)
            return 0
        except (TimeoutError, ConnectionRefusedError, OSError):
            return 1

    # ------------------------------------------------------------------
    # Data transfer
    # ------------------------------------------------------------------

    def send(self, data: bytes) -> int:
        """Send bytes, returning how many were accepted."""
        self._check_open()
        if not data:
            return 0

        if self.type == SOCK_DGRAM:
            peer = getattr(self, "_peer", None)
            if peer is None:
                raise OSError("destination address required")
            ok = self.stack.udp_send(data, peer[0], peer[1], self._bound_port or 0)
            return len(data) if ok else 0

        if self._conn is None:
            raise OSError("socket is not connected")

        written = self._conn.send(data)
        # The connection window may be full; wait for it to drain rather than
        # silently dropping bytes the caller believes were accepted.
        while written < len(data):
            if is_closed(self._conn.state):
                break
            time.sleep(_POLL_INTERVAL)
            written += self._conn.send(data[written:])
        return written

    def sendall(self, data: bytes) -> None:
        """Send every byte, or raise if the connection drops first."""
        total = self.send(data)
        while total < len(data):
            if self._conn is None or is_closed(self._conn.state):
                raise ConnectionResetError("connection closed during send")
            chunk = self.send(data[total:])
            if chunk == 0:
                time.sleep(_POLL_INTERVAL)
            total += chunk

    def sendto(self, data: bytes, address: tuple) -> int:
        """Send a datagram to an explicit address."""
        self._check_open()
        if self.type != SOCK_DGRAM:
            raise OSError("sendto() requires a datagram socket")
        host, port = address
        ok = self.stack.udp_send(data, host, port, self._bound_port or 0)
        return len(data) if ok else 0

    def recv(self, bufsize: int = 65536) -> bytes:
        """Receive up to *bufsize* bytes; ``b""`` means the peer has closed."""
        self._check_open()

        if self.type == SOCK_DGRAM:
            payload, _ = self.recvfrom(bufsize)
            return payload

        if self._conn is None:
            raise OSError("socket is not connected")

        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        while True:
            data = self._conn.recv(bufsize)
            if data:
                return data

            # No data buffered.  Has the peer finished, or should we wait?
            if is_closed(self._conn.state) or self._conn.peer_closed:
                return b""

            remaining = 0.05
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("recv timed out")
                remaining = min(remaining, left)

            self.stack.wait_readable(self._conn, remaining)

    def recvfrom(self, bufsize: int = 65536) -> tuple[bytes, tuple]:
        """Receive a datagram and the address it came from."""
        self._check_open()
        if self.type != SOCK_DGRAM:
            raise OSError("recvfrom() requires a datagram socket")

        while not self._udp_queue:
            if not self._udp_event.wait(self.timeout):
                raise TimeoutError("recvfrom timed out")
            self._udp_event.clear()

        payload, address = self._udp_queue.popleft()
        return payload[:bufsize], address

    def recv_all(self, chunk_size: int = 65536) -> bytes:
        """Read until the peer closes.  Convenient for request/response protocols."""
        out = bytearray()
        while True:
            chunk = self.recv(chunk_size)
            if not chunk:
                return bytes(out)
            out.extend(chunk)

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def shutdown(self, how: int = SHUT_WR) -> None:
        """Half-close the connection."""
        if self._conn is None:
            return
        if how in (SHUT_WR, SHUT_RDWR):
            self._conn.close()

    def close(self) -> None:
        """Close the socket, shutting down gracefully where possible."""
        if self._closed:
            return
        self._closed = True

        if self.type == SOCK_DGRAM and self._bound_port is not None:
            self.stack.udp_unbind(self._bound_port)

        if self._conn is not None:
            try:
                self.stack.tcp_close(self._conn)
            except Exception:
                self._conn.abort()

        self._conn = None
        self._listener = None

    def __enter__(self) -> "socket":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Options and introspection
    # ------------------------------------------------------------------

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def gettimeout(self) -> float | None:
        return self.timeout

    def setblocking(self, flag: bool) -> None:
        self.timeout = None if flag else 0.0

    def getsockname(self) -> tuple:
        return (ip_to_str(self.stack.ip), self._bound_port or 0)

    def getpeername(self) -> tuple:
        if self._conn is None:
            raise OSError("socket is not connected")
        return (ip_to_str(self._conn.remote_ip), self._conn.remote_port)

    @property
    def connection(self):
        """The underlying :class:`TCPConnection`, for diagnostics."""
        return self._conn

    def _on_udp(self, payload: bytes, src_ip: bytes, src_port: int) -> None:
        self._udp_queue.append((payload, (ip_to_str(src_ip), src_port)))
        self._udp_event.set()

    def _check_open(self) -> None:
        if self._closed:
            raise OSError("socket is closed")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        kind = "tcp" if self.type == SOCK_STREAM else "udp"
        state = self._conn.state if self._conn is not None else "unconnected"
        return "<minitcp.socket %s port=%s %s>" % (kind, self._bound_port, state)


def create_connection(
    stack,
    address: tuple,
    timeout: float | None = None,
) -> socket:
    """Connect to *address* and return a ready-to-use socket."""
    sock = socket(stack, AF_INET, SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(address)
    return sock
