"""Sequential big-endian readers and writers.

Every protocol header in this project is a fixed layout of network byte order
integers followed by optional data.  ``struct.unpack_from`` with a running
offset would work, but it is easy to get an offset wrong when a header has a
variable-length option area.  These two helpers make the layout read like the
diagram in the RFC.
"""

from __future__ import annotations

import struct

__all__ = ["Reader", "Writer"]


class Reader:
    """Sequential big-endian reader over a bytes object.

    Every accessor raises :class:`ValueError` when there are not enough bytes
    left.  That matters because these readers are pointed at data that arrived
    from the network: callers need one predictable exception type to catch for
    "this packet is malformed", distinct from the ``struct.error`` and
    ``IndexError`` that a programming mistake would produce.
    """

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def _need(self, length: int) -> None:
        if self._pos + length > len(self._data):
            raise ValueError(
                "truncated data: wanted %d bytes, %d available"
                % (length, len(self._data) - self._pos)
            )

    def u8(self) -> int:
        self._need(1)
        value = self._data[self._pos]
        self._pos += 1
        return value

    def u16(self) -> int:
        self._need(2)
        value = struct.unpack_from("!H", self._data, self._pos)[0]
        self._pos += 2
        return value

    def u32(self) -> int:
        self._need(4)
        value = struct.unpack_from("!I", self._data, self._pos)[0]
        self._pos += 4
        return value

    def raw(self, length: int) -> bytes:
        self._need(length)
        end = self._pos + length
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

    def rest(self) -> bytes:
        chunk = self._data[self._pos:]
        self._pos = len(self._data)
        return chunk


class Writer:
    """Accumulating big-endian writer.

    Out-of-range values raise :class:`ValueError` rather than the
    ``struct.error`` that ``struct.pack`` would produce, so the two halves of
    this module present the same contract.
    """

    __slots__ = ("_parts",)

    def __init__(self) -> None:
        self._parts: list[bytes] = []

    @staticmethod
    def _check(value: int, bits: int) -> None:
        if not 0 <= value < (1 << bits):
            raise ValueError("value %r does not fit in %d bits" % (value, bits))

    def u8(self, value: int) -> "Writer":
        self._check(value, 8)
        self._parts.append(struct.pack("!B", value))
        return self

    def u16(self, value: int) -> "Writer":
        self._check(value, 16)
        self._parts.append(struct.pack("!H", value))
        return self

    def u32(self, value: int) -> "Writer":
        self._check(value, 32)
        self._parts.append(struct.pack("!I", value))
        return self

    def raw(self, data: bytes) -> "Writer":
        self._parts.append(data)
        return self

    def bytes(self) -> bytes:
        return b"".join(self._parts)

    def __len__(self) -> int:
        return sum(len(part) for part in self._parts)
