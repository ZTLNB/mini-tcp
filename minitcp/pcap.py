"""Write captured frames to a pcap file.

Being able to open your own packets in Wireshark is the fastest way to find out
whether a bug is in your stack or in your understanding of the protocol.  The
capture format is refreshingly simple: a 24-byte file header, then one 16-byte
record header plus the raw frame for every packet.

Everything is written little-endian with the magic number ``0xa1b2c3d4``, which
is the byte order Wireshark assumes when it reads the file.  Timestamps are
microsecond resolution.
"""

from __future__ import annotations

import struct
import time

__all__ = ["PcapWriter", "LINKTYPE_ETHERNET", "DEFAULT_SNAPLEN"]

#: Written little-endian, this is the classic libpcap magic number.
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

#: Link type 1 is Ethernet, which is what everything in this project produces.
LINKTYPE_ETHERNET = 1

DEFAULT_SNAPLEN = 65535

_FILE_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")


class PcapWriter:
    """Appends frames to a capture file, one at a time.

    Usable as a context manager, and as a callback: :meth:`write` takes the raw
    frame bytes, so an instance can be dropped straight into any hook that
    hands out frames.
    """

    def __init__(self, path, snaplen: int = DEFAULT_SNAPLEN) -> None:
        self.path = str(path)
        self.snaplen = snaplen
        self._file = open(self.path, "wb")
        self._file.write(
            _FILE_HEADER.pack(
                PCAP_MAGIC,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,  # thiszone: GMT offset, always zero in practice
                0,  # sigfigs: timestamp accuracy, unused
                snaplen,
                LINKTYPE_ETHERNET,
            )
        )
        self._count = 0
        self._bytes = 0

    def write(self, frame: bytes, timestamp: float | None = None) -> None:
        """Append one frame."""
        if self._file.closed:
            raise ValueError("capture file is already closed")

        when = time.time() if timestamp is None else timestamp
        seconds = int(when)
        microseconds = int(round((when - seconds) * 1_000_000))
        if microseconds >= 1_000_000:  # guard against rounding up
            seconds += 1
            microseconds -= 1_000_000

        captured = frame[: self.snaplen]
        self._file.write(
            _RECORD_HEADER.pack(seconds, microseconds, len(captured), len(frame))
        )
        self._file.write(captured)
        self._count += 1
        self._bytes += len(captured)

    def flush(self) -> None:
        if not self._file.closed:
            self._file.flush()

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def packet_count(self) -> int:
        return self._count

    @property
    def byte_count(self) -> int:
        return self._bytes

    def __len__(self) -> int:
        return self._count

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<PcapWriter %s packets=%d>" % (self.path, self._count)
