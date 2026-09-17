"""TCP segment encoding, decoding and option parsing.

The fixed header is 20 bytes and may be followed by up to 40 bytes of options::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |     |U|A|P|R|S|F|                                     |
    | Offset| Rsvd|R|C|S|S|Y|I|            Window                   |
    |       |     |G|K|H|T|N|N|                                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options (up to 40 bytes)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The subtle part is the option area.  Options are variable length, may be
separated by single-byte NOPs, and are terminated early by an EOL byte.  A
parser that assumes fixed stride will read garbage the moment it meets a
segment from a real host, so :meth:`TCPOptions.parse` walks the list properly
and stops on anything malformed rather than trusting the lengths it is given.

Flags occupy nine bits spread across two bytes, which is why the NS flag is
unusual enough to be worth a comment: it lives in the low bit of the
data-offset byte, not alongside the other eight.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ...util.checksum import transport_checksum
from ..ipv4 import PROTO_TCP
from .seqno import SEQ_MASK

__all__ = [
    "FLAG_FIN",
    "FLAG_SYN",
    "FLAG_RST",
    "FLAG_PSH",
    "FLAG_ACK",
    "FLAG_URG",
    "FLAG_ECE",
    "FLAG_CWR",
    "FLAG_NS",
    "HEADER_LEN",
    "MAX_HEADER_LEN",
    "OPT_END",
    "OPT_NOP",
    "OPT_MSS",
    "OPT_WINDOW_SCALE",
    "OPT_SACK_PERMITTED",
    "OPT_SACK",
    "OPT_TIMESTAMP",
    "TCPOptions",
    "TCPSegment",
]

FLAG_FIN = 0x001
FLAG_SYN = 0x002
FLAG_RST = 0x004
FLAG_PSH = 0x008
FLAG_ACK = 0x010
FLAG_URG = 0x020
FLAG_ECE = 0x040
FLAG_CWR = 0x080
FLAG_NS = 0x100

HEADER_LEN = 20
MAX_HEADER_LEN = 60

OPT_END = 0
OPT_NOP = 1
OPT_MSS = 2
OPT_WINDOW_SCALE = 3
OPT_SACK_PERMITTED = 4
OPT_SACK = 5
OPT_TIMESTAMP = 8

_FLAG_NAMES = (
    (FLAG_SYN, "SYN"),
    (FLAG_ACK, "ACK"),
    (FLAG_FIN, "FIN"),
    (FLAG_RST, "RST"),
    (FLAG_PSH, "PSH"),
    (FLAG_URG, "URG"),
    (FLAG_ECE, "ECE"),
    (FLAG_CWR, "CWR"),
    (FLAG_NS, "NS"),
)


def describe_flags(flags: int) -> str:
    """Render a flag word as the familiar ``SYN,ACK`` shorthand."""
    names = [name for bit, name in _FLAG_NAMES if flags & bit]
    return ",".join(names) if names else "-"


@dataclass
class TCPOptions:
    """The options we understand, decoded from the option area.

    Unknown options are skipped over rather than rejected: a real peer may send
    anything, and refusing to talk to it because of an option we do not use
    would be a poor design.
    """

    mss: int | None = None
    window_scale: int | None = None
    sack_permitted: bool = False
    sack_blocks: tuple[tuple[int, int], ...] = ()
    timestamp: int | None = None
    timestamp_echo: int | None = None

    def is_empty(self) -> bool:
        return not any(
            (
                self.mss is not None,
                self.window_scale is not None,
                self.sack_permitted,
                self.sack_blocks,
                self.timestamp is not None,
            )
        )

    def to_bytes(self) -> bytes:
        """Serialise the options, padded to a 4-byte boundary."""
        parts: list[bytes] = []

        if self.mss is not None:
            if not 0 < self.mss <= 0xFFFF:
                raise ValueError("MSS must be between 1 and 65535")
            parts.append(struct.pack("!BBH", OPT_MSS, 4, self.mss))

        if self.sack_permitted:
            parts.append(struct.pack("!BB", OPT_SACK_PERMITTED, 2))

        if self.window_scale is not None:
            if not 0 <= self.window_scale <= 14:
                raise ValueError("window scale must be between 0 and 14")
            parts.append(struct.pack("!BBB", OPT_WINDOW_SCALE, 3, self.window_scale))

        if self.timestamp is not None:
            parts.append(
                struct.pack(
                    "!BBII",
                    OPT_TIMESTAMP,
                    10,
                    self.timestamp & 0xFFFFFFFF,
                    (self.timestamp_echo or 0) & 0xFFFFFFFF,
                )
            )

        for left, right in self.sack_blocks:
            parts.append(
                struct.pack(
                    "!BBII",
                    OPT_SACK,
                    10,
                    left & 0xFFFFFFFF,
                    right & 0xFFFFFFFF,
                )
            )

        raw = b"".join(parts)
        if len(raw) > 40:
            raise ValueError("TCP options may not exceed 40 bytes")

        padding = (-len(raw)) % 4
        if padding == 3:
            raw += b"\x01\x01\x01"
        elif padding == 2:
            raw += b"\x01\x01"
        elif padding == 1:
            # A single EOL byte is the only one-byte filler available.
            raw += b"\x00"
        return raw

    @classmethod
    def parse(cls, data: bytes) -> "TCPOptions":
        """Walk the option list, ignoring anything we do not recognise."""
        options = cls()
        pos = 0
        while pos < len(data):
            kind = data[pos]

            if kind == OPT_END:
                break
            if kind == OPT_NOP:
                pos += 1
                continue
            if pos + 1 >= len(data):
                # A kind byte with no length is malformed; stop here rather
                # than reading past the end of the buffer.
                break

            length = data[pos + 1]
            if length < 2 or pos + length > len(data):
                break

            body = data[pos + 2: pos + length]

            if kind == OPT_MSS and length == 4:
                options.mss = struct.unpack("!H", body)[0]
            elif kind == OPT_WINDOW_SCALE and length == 3:
                options.window_scale = body[0]
            elif kind == OPT_SACK_PERMITTED and length == 2:
                options.sack_permitted = True
            elif kind == OPT_TIMESTAMP and length == 10:
                options.timestamp, options.timestamp_echo = struct.unpack("!II", body)
            elif kind == OPT_SACK and len(body) >= 8:
                blocks = []
                for offset in range(0, len(body) - 7, 8):
                    blocks.append(struct.unpack_from("!II", body, offset))
                options.sack_blocks = tuple(blocks)

            pos += length

        return options

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        bits = []
        if self.mss is not None:
            bits.append("mss=%d" % self.mss)
        if self.window_scale is not None:
            bits.append("wscale=%d" % self.window_scale)
        if self.sack_permitted:
            bits.append("sack-ok")
        if self.sack_blocks:
            bits.append("sack=%d" % len(self.sack_blocks))
        if self.timestamp is not None:
            bits.append("ts=%d" % self.timestamp)
        return "<TCPOptions %s>" % (" ".join(bits) or "empty")


@dataclass
class TCPSegment:
    """A decoded TCP segment."""

    src_port: int
    dst_port: int
    seq: int
    ack: int = 0
    flags: int = 0
    window: int = 0
    payload: bytes = b""
    options: TCPOptions = field(default_factory=TCPOptions)
    urgent_pointer: int = 0
    checksum: int = 0

    # -- flag helpers ----------------------------------------------------

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & FLAG_SYN)

    @property
    def is_ack(self) -> bool:
        return bool(self.flags & FLAG_ACK)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & FLAG_FIN)

    @property
    def is_rst(self) -> bool:
        return bool(self.flags & FLAG_RST)

    @property
    def is_psh(self) -> bool:
        return bool(self.flags & FLAG_PSH)

    @property
    def is_urg(self) -> bool:
        return bool(self.flags & FLAG_URG)

    # -- sequence arithmetic ---------------------------------------------

    @property
    def seq_len(self) -> int:
        """How much sequence space this segment occupies.

        SYN and FIN each consume one sequence number even though they carry no
        data.  Forgetting that is the classic cause of an off-by-one that only
        shows up when a connection closes.
        """
        return len(self.payload) + (1 if self.is_syn else 0) + (1 if self.is_fin else 0)

    @property
    def seq_end(self) -> int:
        """Sequence number just past this segment."""
        return (self.seq + self.seq_len) & SEQ_MASK

    def acknowledges(self, seq: int) -> bool:
        """Whether this segment's ACK covers *seq*."""
        from .seqno import seq_ge

        return self.is_ack and seq_ge(self.ack, seq)

    # -- serialisation ---------------------------------------------------

    @property
    def header_length(self) -> int:
        return HEADER_LEN + len(self.options.to_bytes())

    def to_bytes(
        self,
        src_ip: bytes | None = None,
        dst_ip: bytes | None = None,
        compute_checksum: bool = True,
    ) -> bytes:
        """Serialise the segment.

        Without the addresses the checksum cannot be computed, so the caller
        must either supply them or accept a zero checksum via
        ``compute_checksum=False``.
        """
        if not 0 <= self.src_port <= 0xFFFF:
            raise ValueError("source port out of range")
        if not 0 <= self.dst_port <= 0xFFFF:
            raise ValueError("destination port out of range")
        if not 0 <= self.window <= 0xFFFF:
            raise ValueError("window must fit in 16 bits; use a window scale")

        options_bytes = self.options.to_bytes()
        data_offset = (HEADER_LEN + len(options_bytes)) // 4
        if data_offset > 15:
            raise ValueError("TCP header cannot exceed 60 bytes")

        offset_byte = (data_offset << 4) | ((self.flags >> 8) & 0x01)

        header = struct.pack(
            "!HHIIBBHHH",
            self.src_port,
            self.dst_port,
            self.seq & SEQ_MASK,
            self.ack & SEQ_MASK,
            offset_byte,
            self.flags & 0xFF,
            self.window,
            0,
            self.urgent_pointer,
        ) + options_bytes

        if compute_checksum:
            if src_ip is None or dst_ip is None:
                raise ValueError(
                    "source and destination addresses are required "
                    "to compute the TCP checksum"
                )
            csum = transport_checksum(src_ip, dst_ip, PROTO_TCP, header + self.payload)
        else:
            csum = self.checksum

        return header[:16] + struct.pack("!H", csum) + header[18:] + self.payload

    @classmethod
    def parse(
        cls,
        data: bytes,
        src_ip: bytes | None = None,
        dst_ip: bytes | None = None,
        verify_checksum: bool = True,
    ) -> "TCPSegment":
        """Decode a segment.

        Checksum verification needs both addresses.  It is skipped when they
        are absent, and also when the field is zero, which some senders use to
        mean "not computed".
        """
        if len(data) < HEADER_LEN:
            raise ValueError(
                "TCP segment too short: %d bytes, need at least %d"
                % (len(data), HEADER_LEN)
            )

        data_offset = data[12] >> 4
        header_len = data_offset * 4
        if header_len < HEADER_LEN:
            raise ValueError("TCP data offset %d is below the minimum of 5" % data_offset)
        if len(data) < header_len:
            raise ValueError(
                "TCP header claims %d bytes but only %d were received"
                % (header_len, len(data))
            )

        (
            src_port,
            dst_port,
            seq,
            ack,
            _,
            flags_low,
            window,
            csum,
            urgent_pointer,
        ) = struct.unpack_from("!HHIIBBHHH", data, 0)

        flags = ((data[12] & 0x01) << 8) | flags_low

        if (
            verify_checksum
            and csum != 0
            and src_ip is not None
            and dst_ip is not None
            and transport_checksum(src_ip, dst_ip, PROTO_TCP, data) != 0
        ):
            raise ValueError("TCP checksum mismatch")

        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=window,
            payload=data[header_len:],
            options=TCPOptions.parse(data[HEADER_LEN:header_len]),
            urgent_pointer=urgent_pointer,
            checksum=csum,
        )

    def describe(self) -> str:
        """One-line summary in roughly tcpdump's format."""
        parts = [
            "%d > %d" % (self.src_port, self.dst_port),
            describe_flags(self.flags),
            "seq=%u" % self.seq,
        ]
        if self.is_ack:
            parts.append("ack=%u" % self.ack)
        parts.append("win=%d" % self.window)
        if self.payload:
            parts.append("len=%d" % len(self.payload))
        if not self.options.is_empty():
            parts.append(str(self.options))
        return " ".join(parts)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<TCPSegment %s>" % self.describe()
