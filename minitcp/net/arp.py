"""ARP: turning an IPv4 address into a MAC address.

An ARP packet for Ethernet and IPv4 is exactly 28 bytes::

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Hardware Type          |        Protocol Type          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  HW Addr Len  | Proto Addr Len|          Operation            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Sender Hardware Address (6)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Sender Protocol Address (4)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Target Hardware Address (6)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Target Protocol Address (4)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The target hardware address is all zeros in a request, because that is
precisely what the sender is asking for.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass

from .ethernet import ETHERTYPE_IPV4

__all__ = [
    "HARDWARE_ETHERNET",
    "ARP_REQUEST",
    "ARP_REPLY",
    "PACKET_LEN",
    "ARPPacket",
    "ARPCache",
]

HARDWARE_ETHERNET = 1
ARP_REQUEST = 1
ARP_REPLY = 2

PACKET_LEN = 28


@dataclass
class ARPPacket:
    """A decoded ARP request or reply."""

    operation: int
    sender_mac: bytes
    sender_ip: bytes
    target_mac: bytes
    target_ip: bytes
    hardware_type: int = HARDWARE_ETHERNET
    protocol_type: int = ETHERTYPE_IPV4
    hardware_len: int = 6
    protocol_len: int = 4

    def to_bytes(self) -> bytes:
        if len(self.sender_mac) != self.hardware_len:
            raise ValueError("sender MAC length does not match hardware_len")
        if len(self.target_mac) != self.hardware_len:
            raise ValueError("target MAC length does not match hardware_len")
        if len(self.sender_ip) != self.protocol_len:
            raise ValueError("sender IP length does not match protocol_len")
        if len(self.target_ip) != self.protocol_len:
            raise ValueError("target IP length does not match protocol_len")
        return (
            struct.pack(
                "!HHBBH",
                self.hardware_type,
                self.protocol_type,
                self.hardware_len,
                self.protocol_len,
                self.operation,
            )
            + self.sender_mac
            + self.sender_ip
            + self.target_mac
            + self.target_ip
        )

    @classmethod
    def parse(cls, data: bytes) -> "ARPPacket":
        if len(data) < PACKET_LEN:
            raise ValueError(
                "ARP packet too short: %d bytes, need at least %d"
                % (len(data), PACKET_LEN)
            )
        (
            hardware_type,
            protocol_type,
            hardware_len,
            protocol_len,
            operation,
        ) = struct.unpack_from("!HHBBH", data, 0)

        if hardware_len != 6 or protocol_len != 4:
            raise ValueError(
                "unsupported ARP address sizes: hardware=%d protocol=%d"
                % (hardware_len, protocol_len)
            )
        if len(data) < 8 + 2 * (hardware_len + protocol_len):
            raise ValueError("ARP packet truncated")

        pos = 8
        sender_mac = data[pos:pos + hardware_len]
        pos += hardware_len
        sender_ip = data[pos:pos + protocol_len]
        pos += protocol_len
        target_mac = data[pos:pos + hardware_len]
        pos += hardware_len
        target_ip = data[pos:pos + protocol_len]

        return cls(
            operation=operation,
            sender_mac=sender_mac,
            sender_ip=sender_ip,
            target_mac=target_mac,
            target_ip=target_ip,
            hardware_type=hardware_type,
            protocol_type=protocol_type,
            hardware_len=hardware_len,
            protocol_len=protocol_len,
        )

    @property
    def is_request(self) -> bool:
        return self.operation == ARP_REQUEST

    @property
    def is_reply(self) -> bool:
        return self.operation == ARP_REPLY

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        from .ipv4 import ip_to_str

        kind = "request" if self.is_request else "reply"
        return "<ARP %s who-has %s tell %s>" % (
            kind,
            ip_to_str(self.target_ip),
            ip_to_str(self.sender_ip),
        )


class ARPCache:
    """A small, expiring map from IPv4 address to MAC address.

    Entries are stored on *any* ARP traffic we see, not just replies, because a
    request tells us the sender's address just as usefully.  That is how real
    stacks avoid a broadcast storm on a busy segment.
    """

    def __init__(self, timeout: float = 300.0, max_entries: int = 256) -> None:
        self._entries: dict[bytes, tuple[bytes, float]] = {}
        self._timeout = timeout
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def lookup(self, ip: bytes, now: float | None = None) -> bytes | None:
        """Return the MAC for *ip*, or ``None`` if unknown or expired.

        *now* exists for the same reason it does on :meth:`store`: without it
        expiry could only be tested by sleeping, which makes for a slow and
        flaky suite.
        """
        stamp = time.monotonic() if now is None else now
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return None
            mac, expires_at = entry
            if stamp >= expires_at:
                del self._entries[ip]
                return None
            return mac

    def store(self, ip: bytes, mac: bytes, now: float | None = None) -> None:
        """Record *ip* -> *mac*, refreshing the expiry."""
        stamp = time.monotonic() if now is None else now
        with self._lock:
            if ip not in self._entries and len(self._entries) >= self._max_entries:
                # Evict the entry closest to expiry.
                oldest = min(self._entries, key=lambda k: self._entries[k][1])
                del self._entries[oldest]
            self._entries[ip] = (mac, stamp + self._timeout)

    def expire(self, now: float | None = None) -> int:
        """Drop expired entries; returns how many were removed."""
        stamp = time.monotonic() if now is None else now
        with self._lock:
            stale = [k for k, (_, exp) in self._entries.items() if stamp >= exp]
            for key in stale:
                del self._entries[key]
            return len(stale)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def snapshot(self) -> dict[bytes, bytes]:
        """Non-expiring view of the cache, for tests and diagnostics."""
        with self._lock:
            return {ip: mac for ip, (mac, _) in self._entries.items()}

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
