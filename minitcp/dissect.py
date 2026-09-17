"""One-line frame summaries, in the spirit of tcpdump.

Useful for demos, for debugging a failing handshake, and for convincing
yourself that what went onto the wire is what you meant to send.

Every parser here is the same code the stack itself uses, so a summary can only
be produced for a frame the stack would also accept.  Checksum verification is
switched off, though: a capture should show a corrupt packet rather than hide
it behind a parse error.
"""

from __future__ import annotations

from .net.arp import ARPPacket
from .net.ethernet import ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame
from .net.icmp import (
    DEST_UNREACHABLE,
    ECHO_REPLY,
    ECHO_REQUEST,
    TIME_EXCEEDED,
    EchoMessage,
    ICMPMessage,
)
from .net.ipv4 import PROTO_ICMP, PROTO_TCP, PROTO_UDP, IPv4Packet, ip_to_str
from .net.tcp.segment import TCPSegment, describe_flags
from .net.udp import UDPSegment

__all__ = ["describe_frame"]

_ICMP_LABELS = {
    ECHO_REQUEST: "echo-request",
    ECHO_REPLY: "echo-reply",
    DEST_UNREACHABLE: "destination-unreachable",
    TIME_EXCEEDED: "time-exceeded",
}


def describe_frame(raw: bytes) -> str:
    """Summarise one raw Ethernet frame as a single line."""
    try:
        frame = EthernetFrame.parse(raw)
    except ValueError as exc:
        return "<unparseable frame: %s>" % exc

    if frame.ethertype == ETHERTYPE_ARP:
        return _describe_arp(frame)
    if frame.ethertype == ETHERTYPE_IPV4:
        return _describe_ipv4(frame)
    return "ethertype=0x%04x len=%d" % (frame.ethertype, len(frame.payload))


def _describe_arp(frame: EthernetFrame) -> str:
    try:
        packet = ARPPacket.parse(frame.payload)
    except ValueError as exc:
        return "ARP malformed: %s" % exc

    if packet.is_request:
        return "ARP who-has %s tell %s" % (
            ip_to_str(packet.target_ip),
            ip_to_str(packet.sender_ip),
        )
    return "ARP %s is-at %s" % (
        ip_to_str(packet.sender_ip),
        packet.sender_mac.hex(":"),
    )


def _describe_ipv4(frame: EthernetFrame) -> str:
    try:
        packet = IPv4Packet.parse(frame.payload)
    except ValueError as exc:
        return "IPv4 malformed: %s" % exc

    prefix = "%s > %s" % (ip_to_str(packet.src), ip_to_str(packet.dst))

    if packet.is_fragmented:
        prefix += " (frag offset=%d%s)" % (
            packet.fragment_offset * 8,
            " more" if packet.flags & 0x2000 else " last",
        )

    if packet.protocol == PROTO_TCP:
        return prefix + " " + _describe_tcp(packet)
    if packet.protocol == PROTO_UDP:
        return prefix + " " + _describe_udp(packet)
    if packet.protocol == PROTO_ICMP:
        return prefix + " " + _describe_icmp(packet)
    return "%s protocol=%d len=%d" % (prefix, packet.protocol, len(packet.payload))


def _describe_tcp(packet: IPv4Packet) -> str:
    try:
        segment = TCPSegment.parse(
            packet.payload, packet.src, packet.dst, verify_checksum=False
        )
    except ValueError as exc:
        return "TCP malformed: %s" % exc

    parts = [
        "TCP",
        "%d > %d" % (segment.src_port, segment.dst_port),
        "[%s]" % describe_flags(segment.flags),
        "seq=%u" % segment.seq,
    ]
    if segment.is_ack:
        parts.append("ack=%u" % segment.ack)
    parts.append("win=%d" % segment.window)
    if segment.payload:
        parts.append("len=%d" % len(segment.payload))
    if not segment.options.is_empty():
        parts.append(str(segment.options))
    return " ".join(parts)


def _describe_udp(packet: IPv4Packet) -> str:
    try:
        segment = UDPSegment.parse(packet.payload, packet.src, packet.dst)
    except ValueError:
        # A checksum failure should not hide the datagram entirely.
        try:
            segment = UDPSegment(
                src_port=int.from_bytes(packet.payload[0:2], "big"),
                dst_port=int.from_bytes(packet.payload[2:4], "big"),
                payload=packet.payload[8:],
            )
        except Exception:
            return "UDP malformed"
        return "UDP %d > %d len=%d [bad checksum]" % (
            segment.src_port,
            segment.dst_port,
            len(segment.payload),
        )
    return "UDP %d > %d len=%d" % (
        segment.src_port,
        segment.dst_port,
        len(segment.payload),
    )


def _describe_icmp(packet: IPv4Packet) -> str:
    try:
        message = ICMPMessage.parse(packet.payload)
    except ValueError as exc:
        return "ICMP malformed: %s" % exc

    label = _ICMP_LABELS.get(message.type, "type-%d" % message.type)
    if message.type in (ECHO_REQUEST, ECHO_REPLY):
        try:
            echo = EchoMessage.from_icmp(message)
            return "ICMP %s id=%d seq=%d len=%d" % (
                label,
                echo.identifier,
                echo.sequence,
                len(echo.data),
            )
        except ValueError:
            pass
    return "ICMP %s code=%d" % (label, message.code)
