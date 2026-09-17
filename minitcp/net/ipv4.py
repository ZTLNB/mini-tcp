"""IPv4 packet encoding, decoding, fragmentation and reassembly.

The header is 20 bytes plus optional padding::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |    DSCP/ECN   |          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      TTL      |    Protocol   |        Header Checksum        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Source Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Destination Address                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Three things trip people up here.

The header checksum covers *only the header*, never the payload, and must be
computed with the checksum field set to zero.

The fragment offset counts 8-byte units, so a payload that does not divide by
eight can only be the last fragment.  ``fragment()`` rounds down accordingly.

An IPv4 packet carried in a 60-byte padded Ethernet frame is *shorter* than the
frame, so the payload has to be trimmed using ``total_length`` rather than the
number of bytes handed up from the link layer.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass, field

from ..util.byteio import Reader
from ..util.checksum import checksum

__all__ = [
    "PROTO_ICMP",
    "PROTO_TCP",
    "PROTO_UDP",
    "FLAG_RESERVED",
    "FLAG_DF",
    "FLAG_MF",
    "IP_ANY",
    "IP_BROADCAST",
    "HEADER_LEN",
    "DEFAULT_MTU",
    "MIN_MTU",
    "ip_to_bytes",
    "ip_to_str",
    "prefix_to_mask",
    "mask_to_prefix",
    "same_subnet",
    "IPv4Packet",
    "fragment",
    "Reassembler",
]

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

FLAG_RESERVED = 0x8000
FLAG_DF = 0x4000  # do not fragment
FLAG_MF = 0x2000  # more fragments follow
FLAG_MASK = 0xE000
FRAG_OFFSET_MASK = 0x1FFF

HEADER_LEN = 20
DEFAULT_MTU = 1500
MIN_MTU = 68  # RFC 791: every host must accept datagrams this large
MAX_PACKET = 0xFFFF

IP_ANY = b"\x00\x00\x00\x00"
IP_BROADCAST = b"\xff\xff\xff\xff"


# --------------------------------------------------------------------------
# Address helpers
# --------------------------------------------------------------------------


def ip_to_bytes(text: str) -> bytes:
    """Parse dotted-quad notation into four bytes."""
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError("an IPv4 address has four octets, got %r" % text)
    octets = []
    for part in parts:
        if not part.isdigit() or (len(part) > 1 and part[0] == "0"):
            raise ValueError("invalid octet %r in %r" % (part, text))
        value = int(part)
        if value > 255:
            raise ValueError("octet %d out of range in %r" % (value, text))
        octets.append(value)
    return bytes(octets)


def ip_to_str(addr: bytes) -> str:
    """Format four bytes as dotted-quad notation."""
    if len(addr) != 4:
        raise ValueError("an IPv4 address is 4 bytes, got %d" % len(addr))
    return "%d.%d.%d.%d" % tuple(addr)


def prefix_to_mask(prefix: int) -> bytes:
    """Turn a prefix length into a netmask, e.g. 24 -> 255.255.255.0."""
    if not 0 <= prefix <= 32:
        raise ValueError("prefix length must be between 0 and 32, got %d" % prefix)
    value = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return value.to_bytes(4, "big")


def mask_to_prefix(mask: bytes) -> int:
    """Turn a netmask into a prefix length, rejecting non-contiguous masks."""
    if len(mask) != 4:
        raise ValueError("a netmask is 4 bytes, got %d" % len(mask))
    value = int.from_bytes(mask, "big")
    prefix = bin(value).count("1")
    if value != int.from_bytes(prefix_to_mask(prefix), "big"):
        raise ValueError("netmask %s is not contiguous" % ip_to_str(mask))
    return prefix


def same_subnet(a: bytes, b: bytes, mask: bytes) -> bool:
    """Whether two addresses share a subnet under *mask*."""
    return all((x & m) == (y & m) for x, y, m in zip(a, b, mask))


# --------------------------------------------------------------------------
# Packet
# --------------------------------------------------------------------------


@dataclass
class IPv4Packet:
    """A decoded IPv4 datagram."""

    src: bytes
    dst: bytes
    protocol: int
    payload: bytes
    ttl: int = 64
    identification: int = 0
    flags: int = 0
    fragment_offset: int = 0  # in 8-byte units
    dscp: int = 0
    options: bytes = b""

    @property
    def ihl(self) -> int:
        """Header length in 32-bit words."""
        return (HEADER_LEN + len(self.options)) // 4

    @property
    def header_length(self) -> int:
        return self.ihl * 4

    @property
    def total_length(self) -> int:
        return self.header_length + len(self.payload)

    @property
    def is_fragmented(self) -> bool:
        """True if this datagram is one piece of a larger one."""
        return bool(self.flags & FLAG_MF) or self.fragment_offset > 0

    @property
    def dont_fragment(self) -> bool:
        return bool(self.flags & FLAG_DF)

    def to_bytes(self) -> bytes:
        """Serialise the datagram, computing the header checksum."""
        if len(self.src) != 4 or len(self.dst) != 4:
            raise ValueError("IPv4 addresses must be 4 bytes")
        if len(self.options) % 4:
            raise ValueError("IPv4 options must pad to a 4-byte boundary")
        if len(self.options) > 40:
            raise ValueError("IPv4 options may not exceed 40 bytes")
        if self.total_length > MAX_PACKET:
            raise ValueError(
                "IPv4 datagram of %d bytes exceeds the %d byte limit"
                % (self.total_length, MAX_PACKET)
            )
        if not 0 <= self.fragment_offset <= FRAG_OFFSET_MASK:
            raise ValueError("fragment offset out of range")
        if not 0 <= self.ttl <= 255:
            raise ValueError("TTL must be between 0 and 255")

        vihl = (4 << 4) | self.ihl
        flags_frag = (self.flags & FLAG_MASK) | self.fragment_offset
        header = struct.pack(
            "!BBHHHBBH4s4s",
            vihl,
            self.dscp,
            self.total_length,
            self.identification & 0xFFFF,
            flags_frag,
            self.ttl,
            self.protocol,
            0,
            self.src,
            self.dst,
        ) + self.options

        csum = checksum(header)
        return header[:10] + struct.pack("!H", csum) + header[12:] + self.payload

    @classmethod
    def parse(cls, data: bytes) -> "IPv4Packet":
        """Decode a datagram, validating the header.

        Raises :class:`ValueError` on anything malformed, so a corrupt frame
        from the wire turns into a dropped packet rather than a crash.
        """
        if len(data) < HEADER_LEN:
            raise ValueError(
                "IPv4 datagram too short: %d bytes, need at least %d"
                % (len(data), HEADER_LEN)
            )

        version = data[0] >> 4
        if version != 4:
            raise ValueError("not an IPv4 datagram (version %d)" % version)

        ihl = data[0] & 0x0F
        if ihl < 5:
            raise ValueError("IPv4 header length %d is below the minimum of 5" % ihl)
        header_len = ihl * 4
        if len(data) < header_len:
            raise ValueError(
                "IPv4 header claims %d bytes but only %d were received"
                % (header_len, len(data))
            )

        if checksum(data[:header_len]) != 0:
            raise ValueError("IPv4 header checksum mismatch")

        (
            _,
            dscp,
            total_length,
            identification,
            flags_frag,
            ttl,
            protocol,
            _,
            src,
            dst,
        ) = struct.unpack_from("!BBHHHBBH4s4s", data, 0)

        if total_length < header_len:
            raise ValueError(
                "IPv4 total length %d is smaller than its header (%d)"
                % (total_length, header_len)
            )
        if total_length > len(data):
            raise ValueError(
                "IPv4 datagram claims %d bytes but only %d were received"
                % (total_length, len(data))
            )

        reader = Reader(data)
        reader.raw(header_len)
        payload = data[header_len:total_length]

        return cls(
            src=src,
            dst=dst,
            protocol=protocol,
            payload=payload,
            ttl=ttl,
            identification=identification,
            flags=flags_frag & FLAG_MASK,
            fragment_offset=flags_frag & FRAG_OFFSET_MASK,
            dscp=dscp,
            options=data[HEADER_LEN:header_len],
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<IPv4 %s -> %s proto=%d len=%d ttl=%d%s>" % (
            ip_to_str(self.src),
            ip_to_str(self.dst),
            self.protocol,
            len(self.payload),
            self.ttl,
            " frag+%d" % (self.fragment_offset * 8) if self.is_fragmented else "",
        )


# --------------------------------------------------------------------------
# Fragmentation
# --------------------------------------------------------------------------


def fragment(packet: IPv4Packet, mtu: int = DEFAULT_MTU) -> list[IPv4Packet]:
    """Split *packet* so no fragment exceeds *mtu* bytes.

    Returns ``[packet]`` unchanged when it already fits.  Raises if the packet
    has the don't-fragment bit set, since silently ignoring it would produce
    the kind of bug that only shows up on a different link.
    """
    if mtu < MIN_MTU:
        raise ValueError("MTU %d is below the required minimum of %d" % (mtu, MIN_MTU))

    header_len = packet.header_length
    if header_len + len(packet.payload) <= mtu:
        return [packet]

    if packet.dont_fragment:
        raise ValueError("packet has DF set and cannot be fragmented")

    max_payload = (mtu - header_len) & ~7
    if max_payload <= 0:
        raise ValueError("MTU %d leaves no room for payload" % mtu)

    total = len(packet.payload)
    pieces: list[IPv4Packet] = []
    offset = 0
    while offset < total:
        chunk = packet.payload[offset:offset + max_payload]
        more = offset + len(chunk) < total
        pieces.append(
            IPv4Packet(
                src=packet.src,
                dst=packet.dst,
                protocol=packet.protocol,
                payload=chunk,
                ttl=packet.ttl,
                identification=packet.identification,
                flags=(packet.flags & FLAG_DF) | (FLAG_MF if more else 0),
                fragment_offset=offset // 8,
                dscp=packet.dscp,
            )
        )
        offset += len(chunk)
    return pieces


# --------------------------------------------------------------------------
# Reassembly
# --------------------------------------------------------------------------


@dataclass
class _FragmentSet:
    """Fragments collected for one (src, dst, protocol, id) tuple."""

    first_seen: float
    total_length: int | None = None
    header: IPv4Packet | None = None
    pieces: dict[int, bytes] = field(default_factory=dict)


class Reassembler:
    """Collects fragments and rebuilds complete datagrams.

    A fragment set is only completed once every byte from 0 up to the length
    implied by the last fragment has arrived, so overlapping fragments and
    holes are both handled.  Incomplete sets are dropped after *timeout*
    seconds, which stops a stream of first-fragments-only from exhausting
    memory -- a classic and very cheap denial of service.
    """

    def __init__(self, timeout: float = 30.0, max_pending: int = 64) -> None:
        self._sets: dict[tuple, _FragmentSet] = {}
        self._timeout = timeout
        self._max_pending = max_pending
        self._lock = threading.Lock()
        self.reassembled = 0
        self.dropped = 0

    def add(self, packet: IPv4Packet) -> IPv4Packet | None:
        """Feed in a datagram; returns the rebuilt packet when complete."""
        if not packet.is_fragmented:
            return packet

        key = (packet.src, packet.dst, packet.protocol, packet.identification)
        offset = packet.fragment_offset * 8
        now = time.monotonic()

        with self._lock:
            self._expire(now)
            entry = self._sets.get(key)
            if entry is None:
                if len(self._sets) >= self._max_pending:
                    self.dropped += 1
                    return None
                entry = _FragmentSet(first_seen=now)
                self._sets[key] = entry

            entry.pieces[offset] = packet.payload
            if entry.header is None:
                entry.header = packet
            if not packet.flags & FLAG_MF:
                entry.total_length = offset + len(packet.payload)

            rebuilt = self._try_complete(entry)
            if rebuilt is None:
                return None

            del self._sets[key]
            self.reassembled += 1
            return rebuilt

    @staticmethod
    def _try_complete(entry: _FragmentSet) -> IPv4Packet | None:
        if entry.total_length is None or not entry.pieces:
            return None

        ordered = sorted(entry.pieces.items())
        cursor = 0
        for offset, data in ordered:
            if offset > cursor:
                return None  # a hole remains
            cursor = max(cursor, offset + len(data))
        if cursor < entry.total_length:
            return None

        buffer = bytearray(entry.total_length)
        for offset, data in ordered:
            end = min(offset + len(data), entry.total_length)
            buffer[offset:end] = data[: end - offset]

        head = entry.header
        assert head is not None
        return IPv4Packet(
            src=head.src,
            dst=head.dst,
            protocol=head.protocol,
            payload=bytes(buffer),
            ttl=head.ttl,
            identification=head.identification,
            flags=0,
            fragment_offset=0,
            dscp=head.dscp,
        )

    def _expire(self, now: float) -> None:
        stale = [k for k, v in self._sets.items() if now - v.first_seen > self._timeout]
        for key in stale:
            del self._sets[key]
            self.dropped += 1

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._sets)
