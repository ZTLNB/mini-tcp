"""Internet checksum, as specified in RFC 1071.

The checksum is the 16-bit one's complement of the one's complement sum of
every 16-bit word in the data.  IPv4, ICMP, UDP and TCP all use it, but the
three transport protocols compute it over a *pseudo-header* that additionally
covers the source address, destination address, protocol number and length.
That stops a segment from being delivered to the wrong endpoint.

The whole computation fits in a handful of lines, but the carry folding is the
part people get wrong: a sum of 0xFFFF words can carry more than once, so the
fold has to be applied until the value fits in 16 bits.
"""

from __future__ import annotations

import struct

__all__ = ["checksum", "transport_checksum", "verify"]


def _ones_complement_sum(data: bytes) -> int:
    """Return the 16-bit one's complement sum of *data*."""
    if len(data) & 1:
        # An odd trailing byte is padded with a zero byte, not shifted.
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) >> 1), data))
    # Fold the carries back in.  Two passes are enough for any input we can
    # realistically build, but the loop makes the intent explicit.
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum(data: bytes) -> int:
    """Compute the Internet checksum of *data*."""
    return (~_ones_complement_sum(data)) & 0xFFFF


def transport_checksum(
    src: bytes, dst: bytes, protocol: int, segment: bytes
) -> int:
    """Compute the TCP or UDP checksum over the IPv4 pseudo-header.

    *src* and *dst* are 4-byte addresses, *protocol* is the IP protocol number
    (6 for TCP, 17 for UDP) and *segment* is the complete transport message
    including its own header.
    """
    pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(segment))
    return checksum(pseudo + segment)


def verify(data: bytes) -> bool:
    """Return ``True`` if *data* already contains a correct checksum.

    Re-running the checksum over data that includes the checksum field yields
    zero when the original value was correct, so no special-casing is needed.
    """
    return checksum(data) == 0
