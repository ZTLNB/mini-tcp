"""Ethernet II frame encoding and decoding.

The frame layout is 6 bytes of destination, 6 bytes of source, a 2-byte
EtherType, then the payload::

    +----------+----------+--------+-------------------+
    | dst (6)  | src (6)  | type   | payload           |
    +----------+----------+--------+-------------------+

Two details matter in practice.  The first is that a frame shorter than 60
bytes is padded up to 60 before transmission, so a receiver cannot trust the
frame length to tell it how long the payload is -- it has to read a length
field inside the payload instead.  The second is that the trailing 4-byte FCS
is generated and checked by hardware and is therefore absent from anything the
kernel or a TUN device hands us.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..util.byteio import Reader, Writer

__all__ = [
    "ETHERTYPE_IPV4",
    "ETHERTYPE_ARP",
    "BROADCAST_MAC",
    "HEADER_LEN",
    "MIN_FRAME_LEN",
    "EthernetFrame",
]

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806

BROADCAST_MAC = b"\xff" * 6

HEADER_LEN = 14
MIN_FRAME_LEN = 60  # excluding the 4-byte FCS


@dataclass
class EthernetFrame:
    """A decoded Ethernet II frame."""

    dst: bytes
    src: bytes
    ethertype: int
    payload: bytes

    def to_bytes(self, pad: bool = True) -> bytes:
        """Serialise the frame, padding short payloads up to the minimum."""
        writer = Writer()
        writer.raw(self.dst).raw(self.src).u16(self.ethertype).raw(self.payload)
        frame = writer.bytes()
        if pad and len(frame) < MIN_FRAME_LEN:
            frame += b"\x00" * (MIN_FRAME_LEN - len(frame))
        return frame

    @classmethod
    def parse(cls, data: bytes) -> "EthernetFrame":
        """Decode a frame.

        Any padding is deliberately left in ``payload``.  Upper layers know
        their own length fields, so trimming here would only hide bugs.
        """
        if len(data) < HEADER_LEN:
            raise ValueError(
                "ethernet frame too short: %d bytes, need at least %d"
                % (len(data), HEADER_LEN)
            )
        reader = Reader(data)
        dst = reader.raw(6)
        src = reader.raw(6)
        ethertype = reader.u16()
        return cls(dst, src, ethertype, reader.rest())

    @property
    def is_broadcast(self) -> bool:
        return self.dst == BROADCAST_MAC

    @property
    def is_multicast(self) -> bool:
        """True when the group bit (the low bit of the first octet) is set.

        A broadcast address is also a multicast address, which is exactly what
        the bit means; the distinction is only in the scope.
        """
        return bool(self.dst[0] & 0x01)

    def accepted_by(self, mac: bytes) -> bool:
        """Whether an interface with address *mac* should process this frame."""
        return self.dst == mac or self.is_broadcast or self.is_multicast

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<EthernetFrame %s -> %s type=0x%04x len=%d>" % (
            self.src.hex(":"),
            self.dst.hex(":"),
            self.ethertype,
            len(self.payload),
        )


def mac_to_str(mac: bytes) -> str:
    """Format a MAC address the way every other tool does."""
    return mac.hex(":")


def mac_from_str(text: str) -> bytes:
    """Parse ``aa:bb:cc:dd:ee:ff`` (or ``aabbccddeeff``) into 6 bytes."""
    cleaned = text.replace(":", "").replace("-", "").replace(".", "")
    if len(cleaned) != 12:
        raise ValueError("a MAC address needs 12 hex digits, got %r" % text)
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("invalid MAC address %r" % text) from exc
