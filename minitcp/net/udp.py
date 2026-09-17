"""UDP: eight bytes of header over IP.

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Length             |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          data ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

UDP is a thin veneer over IP: no connection, no ordering, no retransmission,
no flow control.  It adds ports and a checksum and stops there.

One quirk worth knowing: in IPv4 the checksum is optional and a value of zero
means "not computed".  Because of that, a checksum that legitimately computes
to zero must be transmitted as 0xFFFF instead -- otherwise the receiver would
read it as "no checksum" and accept a corrupt datagram.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..util.checksum import transport_checksum
from .ipv4 import PROTO_UDP

__all__ = ["HEADER_LEN", "UDPSegment"]

HEADER_LEN = 8
MAX_PORT = 0xFFFF


@dataclass
class UDPSegment:
    """A decoded UDP datagram."""

    src_port: int
    dst_port: int
    payload: bytes = b""
    checksum: int = 0

    @property
    def length(self) -> int:
        """Value of the length field: header plus payload."""
        return HEADER_LEN + len(self.payload)

    def to_bytes(
        self,
        src_ip: bytes | None = None,
        dst_ip: bytes | None = None,
        compute_checksum: bool = True,
    ) -> bytes:
        """Serialise the datagram.

        The addresses are needed for the pseudo-header.  Passing
        ``compute_checksum=False`` produces a zero checksum, which is legal
        over IPv4 but means any corruption goes undetected.
        """
        if not 0 <= self.src_port <= MAX_PORT:
            raise ValueError("source port out of range")
        if not 0 <= self.dst_port <= MAX_PORT:
            raise ValueError("destination port out of range")
        if self.length > 0xFFFF:
            raise ValueError("UDP datagram of %d bytes is too large" % self.length)

        header = struct.pack("!HHHH", self.src_port, self.dst_port, self.length, 0)
        body = header + self.payload

        if compute_checksum:
            if src_ip is None or dst_ip is None:
                raise ValueError(
                    "source and destination addresses are required "
                    "to compute the UDP checksum"
                )
            csum = transport_checksum(src_ip, dst_ip, PROTO_UDP, body)
            if csum == 0:
                # Zero means "no checksum" in IPv4, so transmit the equivalent
                # all-ones value instead.
                csum = 0xFFFF
        else:
            csum = self.checksum

        return header[:6] + struct.pack("!H", csum) + self.payload

    @classmethod
    def parse(cls, data: bytes, src_ip: bytes, dst_ip: bytes) -> "UDPSegment":
        """Decode a datagram and verify its checksum."""
        if len(data) < HEADER_LEN:
            raise ValueError(
                "UDP datagram too short: %d bytes, need at least %d"
                % (len(data), HEADER_LEN)
            )

        src_port, dst_port, length, csum = struct.unpack_from("!HHHH", data, 0)

        if length < HEADER_LEN:
            raise ValueError("UDP length field %d is below the header size" % length)
        if length > len(data):
            raise ValueError(
                "UDP length field claims %d bytes but only %d were received"
                % (length, len(data))
            )

        body = data[:length]
        if csum != 0 and transport_checksum(src_ip, dst_ip, PROTO_UDP, body) != 0:
            raise ValueError("UDP checksum mismatch")

        return cls(src_port, dst_port, body[HEADER_LEN:], csum)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<UDP %d -> %d len=%d>" % (
            self.src_port,
            self.dst_port,
            len(self.payload),
        )
