"""The boundary between the protocol stack and the wire.

A :class:`Link` is deliberately the *only* thing the stack knows about the
outside world.  Everything above it speaks in Ethernet frames; everything below
it is replaceable.  Two implementations ship with the project:

``SimulatedLink``
    An in-process virtual wire.  Runs anywhere, and can be told to drop,
    delay, reorder, duplicate or corrupt frames.

``TunLink``
    A real TUN device on Linux, which hands frames to and from the kernel's own
    network stack.

Keeping the seam in one place is what lets the same protocol code be tested
exhaustively on Windows and then pointed at a live network on Linux.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

__all__ = ["Link", "LinkError"]


class LinkError(RuntimeError):
    """Raised when a link is unusable or a frame cannot be sent."""


class Link(ABC):
    """A bidirectional, unreliable, packet-oriented interface."""

    #: Largest payload this link will carry, excluding the Ethernet header.
    mtu: int = 1500

    @property
    @abstractmethod
    def mac(self) -> bytes:
        """The 48-bit hardware address of this endpoint."""

    @abstractmethod
    def send_frame(self, frame: bytes) -> None:
        """Transmit one complete Ethernet frame.

        The call is best effort: a frame may be lost in transit and the caller
        is never told.  That is exactly the guarantee real Ethernet provides,
        and the reason TCP has to exist.
        """

    @abstractmethod
    def recv_frame(self, timeout: float | None = None) -> bytes | None:
        """Return the next inbound frame, or ``None`` on timeout."""

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the link.

        Abstract rather than a no-op default: every link owns something that
        has to be given back (a socket, a file descriptor, a thread).  Leaving
        the base empty makes "forgot to implement close" a silent leak instead
        of an error at class-definition time.
        """
