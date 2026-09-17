"""ICMP messages, enough of them to implement ``ping``.

An ICMP message is a 4-byte header followed by a type-specific body::

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          body, meaning depends on Type and Code               |

Unlike TCP and UDP, ICMP has no pseudo-header: the checksum covers the ICMP
message alone.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..util.checksum import checksum

__all__ = [
    "ECHO_REPLY",
    "DEST_UNREACHABLE",
    "ECHO_REQUEST",
    "TIME_EXCEEDED",
    "ICMPMessage",
    "EchoMessage",
]

ECHO_REPLY = 0
DEST_UNREACHABLE = 3
ECHO_REQUEST = 8
TIME_EXCEEDED = 11

HEADER_LEN = 4

_TYPE_NAMES = {
    ECHO_REPLY: "echo-reply",
    DEST_UNREACHABLE: "destination-unreachable",
    ECHO_REQUEST: "echo-request",
    TIME_EXCEEDED: "time-exceeded",
}


@dataclass
class ICMPMessage:
    """A decoded ICMP message."""

    type: int
    code: int
    body: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialise the message, computing the checksum."""
        header = struct.pack("!BBH", self.type, self.code, 0) + self.body
        csum = checksum(header)
        return header[:2] + struct.pack("!H", csum) + header[4:]

    @classmethod
    def parse(cls, data: bytes) -> "ICMPMessage":
        if len(data) < HEADER_LEN:
            raise ValueError(
                "ICMP message too short: %d bytes, need at least %d"
                % (len(data), HEADER_LEN)
            )
        if checksum(data) != 0:
            raise ValueError("ICMP checksum mismatch")
        type_, code, _ = struct.unpack_from("!BBH", data, 0)
        return cls(type_, code, data[HEADER_LEN:])

    @property
    def type_name(self) -> str:
        return _TYPE_NAMES.get(self.type, "type-%d" % self.type)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<ICMP %s code=%d len=%d>" % (self.type_name, self.code, len(self.body))


@dataclass
class EchoMessage:
    """The body of an echo request or reply.

    The identifier is what lets a host tell its own outstanding pings apart
    from anyone else's on the same machine; the sequence number orders them.
    """

    identifier: int
    sequence: int
    data: bytes = b""

    def to_icmp(self, type_: int) -> ICMPMessage:
        body = struct.pack("!HH", self.identifier & 0xFFFF, self.sequence & 0xFFFF)
        return ICMPMessage(type_, 0, body + self.data)

    @classmethod
    def from_icmp(cls, message: ICMPMessage) -> "EchoMessage":
        if len(message.body) < 4:
            raise ValueError("echo body needs at least 4 bytes")
        identifier, sequence = struct.unpack_from("!HH", message.body, 0)
        return cls(identifier, sequence, message.body[4:])
