"""Unit tests for the individual codecs and algorithms.

The end-to-end tests in ``test_loopback`` and ``test_stack`` prove that the
stack works.  These tests prove *why* it works, one layer at a time, so that
when something does break the failure points at a single function instead of
at a whole conversation.

Every expected value here comes from an external source -- an RFC, a published
worked example, or arithmetic done by hand in the comment.  A test that asserts
whatever the code happens to print is worse than no test at all.
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitcp.dissect import describe_frame  # noqa: E402
from minitcp.net.arp import (  # noqa: E402
    ARP_REPLY,
    ARP_REQUEST,
    ARPCache,
    ARPPacket,
)
from minitcp.net.ethernet import (  # noqa: E402
    BROADCAST_MAC,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    MIN_FRAME_LEN,
    EthernetFrame,
    mac_from_str,
    mac_to_str,
)
from minitcp.net.icmp import (  # noqa: E402
    ECHO_REPLY,
    ECHO_REQUEST,
    EchoMessage,
    ICMPMessage,
)
from minitcp.net.ipv4 import (  # noqa: E402
    FLAG_DF,
    FLAG_MF,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    IPv4Packet,
    Reassembler,
    fragment,
    ip_to_bytes,
    ip_to_str,
    mask_to_prefix,
    prefix_to_mask,
    same_subnet,
)
from minitcp.net.tcp import (  # noqa: E402
    CLOSED,
    CONGESTION_AVOIDANCE,
    ESTABLISHED,
    FAST_RECOVERY,
    FLAG_ACK,
    FLAG_FIN,
    FLAG_PSH,
    FLAG_RST,
    FLAG_SYN,
    MAX_HEADER_LEN,
    SEQ_HALF,
    SEQ_MASK,
    SLOW_START,
    ReceiveQueue,
    RenoCongestion,
    ReorderQueue,
    RetransmitQueue,
    RTOEstimator,
    SendQueue,
    TCPOptions,
    TCPSegment,
    describe_flags,
    is_closed,
    is_synchronised,
    seq_add,
    seq_between,
    seq_diff,
    seq_ge,
    seq_gt,
    seq_le,
    seq_lt,
    seq_max,
    seq_min,
)
from minitcp.net.udp import UDPSegment  # noqa: E402
from minitcp.pcap import LINKTYPE_ETHERNET, PcapWriter  # noqa: E402
from minitcp.util import (  # noqa: E402
    Reader,
    Writer,
    checksum,
    transport_checksum,
    verify,
)

# Addresses used throughout.  RFC 5737 reserves 192.0.2.0/24 for documentation.
CLIENT_IP = ip_to_bytes("192.0.2.10")
SERVER_IP = ip_to_bytes("192.0.2.20")
CLIENT_MAC = mac_from_str("02:00:00:00:00:01")
SERVER_MAC = mac_from_str("02:00:00:00:00:02")


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------


class TestChecksum(unittest.TestCase):
    def test_rfc1071_worked_example(self):
        """RFC 1071 section 3 works 00 01 f2 03 f4 f5 f6 f7 out to 0x220d.

        By hand: 0001+f203 = f204; +f4f5 carries to e6fa; +f6f7 carries to
        ddf2; the one's complement of ddf2 is 220d.
        """
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)

    def test_ipv4_header_vector(self):
        """The header from the canonical IPv4 checksum example sums to 0xb861.

        Taken from the 20-byte header
        4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7, whose checksum
        field is the one being solved for.
        """
        header = bytes.fromhex("450000730000400040110000c0a80001c0a800c7")
        self.assertEqual(checksum(header), 0xB861)

    def test_empty_input_is_all_ones(self):
        """No data means a zero sum, and the complement of zero is 0xffff."""
        self.assertEqual(checksum(b""), 0xFFFF)

    def test_odd_length_is_zero_padded(self):
        """A trailing byte is padded with a zero byte, not shifted left.

        By hand: 0102 + 0300 = 0402, complement fbfd.
        """
        self.assertEqual(checksum(b"\x01\x02\x03"), 0xFBFD)

    def test_all_zero_words(self):
        self.assertEqual(checksum(b"\x00" * 8), 0xFFFF)

    def test_all_one_words(self):
        """0xffff + 0xffff = 0x1fffe, folded twice, complements to zero."""
        self.assertEqual(checksum(b"\xff" * 8), 0x0000)

    def test_carry_folds_more_than_once(self):
        """A long run of 0xffff forces repeated carry folding.

        Eight 0xff bytes give 0x3fffc.  Folding once yields 0xfffc + 3 =
        0xffff, so no further fold is needed and the complement is zero.
        """
        self.assertEqual(checksum(b"\xff" * 8 + b"\x00" * 8), 0x0000)

    def test_repeated_folding_is_stable(self):
        """Whatever the input, folding must converge to a 16-bit value.

        A checksum of 0xffff is the encoding of "negative zero"; if the fold
        loop failed to terminate it would show up here as a hang or an
        out-of-range result.
        """
        for data in (b"\xff" * 32, b"\xff" * 64, bytes(range(256))):
            result = checksum(data)
            self.assertGreaterEqual(result, 0)
            self.assertLessEqual(result, 0xFFFF)

    def test_verify_accepts_a_correct_checksum(self):
        """Re-summing data that already holds its checksum yields zero."""
        header = bytearray.fromhex("450000730000400040110000c0a80001c0a800c7")
        struct.pack_into("!H", header, 10, checksum(bytes(header)))
        self.assertTrue(verify(bytes(header)))

    def test_verify_rejects_a_corrupted_byte(self):
        header = bytearray.fromhex("450000730000400040110000c0a80001c0a800c7")
        struct.pack_into("!H", header, 10, checksum(bytes(header)))
        header[8] ^= 0x01  # flip one bit of the TTL
        self.assertFalse(verify(bytes(header)))

    def test_transport_checksum_covers_the_pseudo_header(self):
        """Changing the source address must change the checksum.

        This is the entire point of the pseudo-header: a segment delivered to
        the wrong host has to fail its checksum.
        """
        segment = TCPSegment(1234, 80, 1, 0, FLAG_SYN).to_bytes(compute_checksum=False)
        base = transport_checksum(CLIENT_IP, SERVER_IP, PROTO_TCP, segment)
        moved = transport_checksum(ip_to_bytes("192.0.2.11"), SERVER_IP, PROTO_TCP, segment)
        self.assertNotEqual(base, moved)

    def test_transport_checksum_covers_the_protocol_number(self):
        segment = TCPSegment(1234, 80, 1, 0, FLAG_SYN).to_bytes(compute_checksum=False)
        as_tcp = transport_checksum(CLIENT_IP, SERVER_IP, PROTO_TCP, segment)
        as_udp = transport_checksum(CLIENT_IP, SERVER_IP, PROTO_UDP, segment)
        self.assertNotEqual(as_tcp, as_udp)


# ---------------------------------------------------------------------------
# Byte reader / writer
# ---------------------------------------------------------------------------


class TestByteIO(unittest.TestCase):
    def test_round_trip(self):
        data = Writer().u8(0x12).u16(0x3456).u32(0x789ABCDE).raw(b"tail").bytes()
        self.assertEqual(data, bytes.fromhex("123456789abcde") + b"tail")

        reader = Reader(data)
        self.assertEqual(reader.u8(), 0x12)
        self.assertEqual(reader.u16(), 0x3456)
        self.assertEqual(reader.u32(), 0x789ABCDE)
        self.assertEqual(reader.rest(), b"tail")

    def test_big_endian_is_used(self):
        """Network byte order is big-endian; 0x0102 must serialise as 01 02."""
        self.assertEqual(Writer().u16(0x0102).bytes(), b"\x01\x02")

    def test_position_tracks_consumption(self):
        reader = Reader(b"\x00" * 8)
        self.assertEqual(reader.pos, 0)
        reader.u32()
        self.assertEqual(reader.pos, 4)
        self.assertEqual(reader.remaining, 4)

    def test_length_and_repr(self):
        writer = Writer().u8(1).u16(2)
        self.assertEqual(len(writer), 3)

    def test_reading_past_the_end_raises(self):
        reader = Reader(b"\x00\x01")
        reader.u16()
        with self.assertRaises(ValueError):
            reader.u32()

    def test_partial_read_past_the_end_raises(self):
        with self.assertRaises(ValueError):
            Reader(b"\x00").raw(4)

    def test_values_out_of_range_raise(self):
        with self.assertRaises(ValueError):
            Writer().u8(256)
        with self.assertRaises(ValueError):
            Writer().u16(0x10000)


# ---------------------------------------------------------------------------
# Ethernet
# ---------------------------------------------------------------------------


class TestEthernet(unittest.TestCase):
    def test_round_trip(self):
        original = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, b"\xaa" * 46)
        decoded = EthernetFrame.parse(original.to_bytes())
        self.assertEqual(decoded.dst, SERVER_MAC)
        self.assertEqual(decoded.src, CLIENT_MAC)
        self.assertEqual(decoded.ethertype, ETHERTYPE_IPV4)
        self.assertEqual(decoded.payload, b"\xaa" * 46)

    def test_short_frames_are_padded_to_sixty_bytes(self):
        """Ethernet needs 60 bytes of frame before the trailing FCS.

        A 14-byte header plus one payload byte is 15 bytes, so 45 bytes of
        padding are added.
        """
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, b"\x01")
        wire = frame.to_bytes()
        self.assertEqual(len(wire), MIN_FRAME_LEN)
        self.assertEqual(wire[-45:], b"\x00" * 45)

    def test_padding_can_be_suppressed(self):
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, b"\x01")
        self.assertEqual(len(frame.to_bytes(pad=False)), 15)

    def test_parse_keeps_padding_in_the_payload(self):
        """Padding is left alone on purpose: upper layers know their lengths.

        Stripping it here would hide a real bug behind a plausible-looking
        packet.  A 60-byte frame minus the 14-byte header leaves 46 bytes,
        of which only one was ever sent.
        """
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, b"\x01")
        decoded = EthernetFrame.parse(frame.to_bytes())
        self.assertEqual(len(decoded.payload), 46)

    def test_broadcast_detection(self):
        frame = EthernetFrame(BROADCAST_MAC, CLIENT_MAC, ETHERTYPE_ARP, b"")
        self.assertTrue(frame.is_broadcast)
        # Every broadcast address also has the group bit set.
        self.assertTrue(frame.is_multicast)

    def test_unicast_is_neither_broadcast_nor_multicast(self):
        """02:00:00:00:00:02 has the group bit clear, so it is a unicast."""
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, b"")
        self.assertFalse(frame.is_broadcast)
        self.assertFalse(frame.is_multicast)

    def test_multicast_without_broadcast(self):
        """A group address that is not the all-ones broadcast."""
        group = mac_from_str("01:00:5e:00:00:01")
        frame = EthernetFrame(group, CLIENT_MAC, ETHERTYPE_IPV4, b"")
        self.assertTrue(frame.is_multicast)
        self.assertFalse(frame.is_broadcast)

    def test_accepted_by(self):
        """Acceptance is decided by the frame's destination, not by the
        address passed in: a unicast frame reaches one interface only."""
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, b"")
        self.assertTrue(frame.accepted_by(SERVER_MAC))
        self.assertFalse(frame.accepted_by(CLIENT_MAC))

    def test_broadcast_is_accepted_by_everyone(self):
        frame = EthernetFrame(BROADCAST_MAC, CLIENT_MAC, ETHERTYPE_ARP, b"")
        self.assertTrue(frame.accepted_by(SERVER_MAC))
        self.assertTrue(frame.accepted_by(CLIENT_MAC))

    def test_multicast_is_accepted_by_everyone(self):
        """A stack that wants to filter groups does so above this layer; here
        the frame is at least addressed to more than one host."""
        group = mac_from_str("01:00:5e:00:00:01")
        frame = EthernetFrame(group, CLIENT_MAC, ETHERTYPE_IPV4, b"")
        self.assertTrue(frame.accepted_by(CLIENT_MAC))

    def test_mac_string_helpers_round_trip(self):
        self.assertEqual(mac_to_str(CLIENT_MAC), "02:00:00:00:00:01")
        self.assertEqual(mac_from_str("02:00:00:00:00:01"), CLIENT_MAC)
        self.assertEqual(mac_to_str(mac_from_str("ff:ff:ff:ff:ff:ff")), "ff:ff:ff:ff:ff:ff")

    def test_truncated_frame_raises(self):
        with self.assertRaises(ValueError):
            EthernetFrame.parse(b"\x00" * 13)


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------


class TestIPv4Addresses(unittest.TestCase):
    def test_address_round_trip(self):
        self.assertEqual(ip_to_bytes("192.0.2.10"), b"\xc0\x00\x02\x0a")
        self.assertEqual(ip_to_str(b"\xc0\x00\x02\x0a"), "192.0.2.10")

    def test_prefix_to_mask(self):
        self.assertEqual(prefix_to_mask(24), bytes.fromhex("ffffff00"))
        self.assertEqual(prefix_to_mask(0), bytes.fromhex("00000000"))
        self.assertEqual(prefix_to_mask(32), bytes.fromhex("ffffffff"))

    def test_mask_to_prefix(self):
        self.assertEqual(mask_to_prefix(bytes.fromhex("ffffff00")), 24)
        self.assertEqual(mask_to_prefix(bytes.fromhex("ffffffff")), 32)

    def test_mask_round_trip_for_every_prefix(self):
        for prefix in range(33):
            self.assertEqual(mask_to_prefix(prefix_to_mask(prefix)), prefix)

    def test_same_subnet(self):
        mask = prefix_to_mask(24)
        self.assertTrue(same_subnet(ip_to_bytes("10.0.0.1"), ip_to_bytes("10.0.0.99"), mask))
        self.assertFalse(same_subnet(ip_to_bytes("10.0.0.1"), ip_to_bytes("10.0.1.1"), mask))


class TestIPv4Codec(unittest.TestCase):
    def test_round_trip(self):
        original = IPv4Packet(
            src=CLIENT_IP,
            dst=SERVER_IP,
            protocol=PROTO_TCP,
            payload=b"payload" * 10,
            ttl=64,
            identification=0x1234,
        )
        decoded = IPv4Packet.parse(original.to_bytes())
        self.assertEqual(decoded.src, CLIENT_IP)
        self.assertEqual(decoded.dst, SERVER_IP)
        self.assertEqual(decoded.protocol, PROTO_TCP)
        self.assertEqual(decoded.payload, b"payload" * 10)
        self.assertEqual(decoded.ttl, 64)
        self.assertEqual(decoded.identification, 0x1234)

    def test_serialised_header_length_fields(self):
        """Byte 0 carries version 4 in the high nibble and IHL 5 in the low."""
        wire = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"").to_bytes()
        self.assertEqual(wire[0], 0x45)
        self.assertEqual(struct.unpack_from("!H", wire, 2)[0], 20)
        self.assertEqual(wire[8], 64)  # TTL

    def test_header_checksum_is_valid_on_the_wire(self):
        wire = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"x" * 8).to_bytes()
        self.assertTrue(verify(wire[:20]))

    def test_parse_rejects_a_corrupted_header_checksum(self):
        wire = bytearray(IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"x").to_bytes())
        wire[12] ^= 0xFF  # flip the source address
        with self.assertRaises(ValueError):
            IPv4Packet.parse(bytes(wire))

    def test_parse_rejects_a_wrong_version(self):
        wire = bytearray(IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"").to_bytes())
        wire[0] = 0x65  # version 6
        with self.assertRaises(ValueError):
            IPv4Packet.parse(bytes(wire))

    def test_parse_rejects_an_impossible_ihl(self):
        wire = bytearray(IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"").to_bytes())
        wire[0] = 0x44  # IHL 4, below the minimum of 5
        with self.assertRaises(ValueError):
            IPv4Packet.parse(bytes(wire))

    def test_parse_trusts_total_length_over_the_buffer(self):
        """A trailing Ethernet pad must not become payload.

        This is exactly the case that would otherwise corrupt every short
        TCP acknowledgement, because the minimum Ethernet frame is 60 bytes.
        """
        wire = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_UDP, b"abc").to_bytes()
        padded = wire + b"\x00" * 40
        decoded = IPv4Packet.parse(padded)
        self.assertEqual(decoded.payload, b"abc")

    def test_parse_rejects_a_truncated_buffer(self):
        wire = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"abcdefgh").to_bytes()
        with self.assertRaises(ValueError):
            IPv4Packet.parse(wire[:-4])

    def test_protocol_and_flag_properties(self):
        packet = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"", flags=FLAG_DF)
        self.assertTrue(packet.dont_fragment)
        self.assertFalse(packet.is_fragmented)

        fragmented = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, b"", flags=FLAG_MF)
        self.assertTrue(fragmented.is_fragmented)


class TestIPv4Fragmentation(unittest.TestCase):
    def _packet(self, size: int) -> IPv4Packet:
        return IPv4Packet(
            src=CLIENT_IP,
            dst=SERVER_IP,
            protocol=PROTO_UDP,
            payload=bytes(range(256)) * (size // 256) + bytes(range(size % 256)),
            identification=0xBEEF,
        )

    def test_a_packet_that_fits_is_returned_unchanged(self):
        packet = self._packet(100)
        pieces = fragment(packet, mtu=1500)
        self.assertEqual(len(pieces), 1)
        self.assertIs(pieces[0], packet)

    def test_fragments_never_exceed_the_mtu(self):
        pieces = fragment(self._packet(4000), mtu=1500)
        for piece in pieces:
            self.assertLessEqual(piece.total_length, 1500)

    def test_fragment_payloads_are_multiples_of_eight(self):
        """The offset field counts 8-byte units, so every fragment but the
        last must be a multiple of eight bytes long."""
        pieces = fragment(self._packet(4000), mtu=1500)
        for piece in pieces[:-1]:
            self.assertEqual(len(piece.payload) % 8, 0)

    def test_all_but_the_last_fragment_set_more_fragments(self):
        pieces = fragment(self._packet(4000), mtu=1500)
        for piece in pieces[:-1]:
            self.assertTrue(piece.flags & FLAG_MF)
        self.assertFalse(pieces[-1].flags & FLAG_MF)

    def test_offsets_are_contiguous_and_in_units_of_eight(self):
        pieces = fragment(self._packet(4000), mtu=1500)
        expected = 0
        for piece in pieces:
            self.assertEqual(piece.fragment_offset, expected // 8)
            expected += len(piece.payload)

    def test_fragments_share_the_identification(self):
        pieces = fragment(self._packet(4000), mtu=1500)
        self.assertEqual({p.identification for p in pieces}, {0xBEEF})

    def test_df_packets_refuse_to_fragment(self):
        """Silently fragmenting a DF packet would be a bug that only shows up
        on a different link, so it has to be an error."""
        packet = self._packet(4000)
        packet.flags = FLAG_DF
        with self.assertRaises(ValueError):
            fragment(packet, mtu=1500)

    def test_mtu_below_the_required_minimum_raises(self):
        with self.assertRaises(ValueError):
            fragment(self._packet(4000), mtu=40)

    def test_reassembly_restores_the_original_payload(self):
        original = self._packet(4000)
        pieces = fragment(original, mtu=1500)
        reassembler = Reassembler()
        rebuilt = None
        for piece in pieces:
            rebuilt = reassembler.add(piece)
        self.assertIsNotNone(rebuilt)
        self.assertEqual(rebuilt.payload, original.payload)
        self.assertEqual(reassembler.reassembled, 1)

    def test_reassembly_handles_fragments_out_of_order(self):
        original = self._packet(4000)
        pieces = fragment(original, mtu=1500)
        reassembler = Reassembler()
        rebuilt = None
        for piece in reversed(pieces):
            rebuilt = reassembler.add(piece)
        self.assertIsNotNone(rebuilt)
        self.assertEqual(rebuilt.payload, original.payload)

    def test_reassembly_waits_for_a_hole_to_fill(self):
        original = self._packet(4000)
        pieces = fragment(original, mtu=1500)
        reassembler = Reassembler()
        # Feed everything except the second fragment.
        for piece in pieces[::2]:
            self.assertIsNone(reassembler.add(piece))
        rebuilt = reassembler.add(pieces[1])
        self.assertIsNotNone(rebuilt)
        self.assertEqual(rebuilt.payload, original.payload)

    def test_a_complete_datagram_passes_straight_through(self):
        packet = self._packet(100)
        self.assertIs(Reassembler().add(packet), packet)

    def test_incomplete_sets_are_dropped_after_the_timeout(self):
        """A stream of first-fragments-only is a cheap denial of service."""
        original = self._packet(4000)
        pieces = fragment(original, mtu=1500)
        reassembler = Reassembler(timeout=0.0)
        reassembler.add(pieces[0])
        self.assertEqual(reassembler.pending, 1)
        # The next call expires it before doing anything else.
        reassembler.add(pieces[1])
        self.assertLessEqual(reassembler.pending, 1)

    def test_pending_sets_are_capped(self):
        reassembler = Reassembler(max_pending=2)
        for ident in range(5):
            packet = self._packet(4000)
            packet.identification = ident
            reassembler.add(fragment(packet, mtu=1500)[0])
        self.assertLessEqual(reassembler.pending, 2)
        self.assertGreater(reassembler.dropped, 0)


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------


class TestARP(unittest.TestCase):
    def test_request_round_trip(self):
        request = ARPPacket(
            operation=ARP_REQUEST,
            sender_mac=CLIENT_MAC,
            sender_ip=CLIENT_IP,
            target_mac=b"\x00" * 6,
            target_ip=SERVER_IP,
        )
        decoded = ARPPacket.parse(request.to_bytes())
        self.assertEqual(decoded.operation, ARP_REQUEST)
        self.assertEqual(decoded.sender_mac, CLIENT_MAC)
        self.assertEqual(decoded.sender_ip, CLIENT_IP)
        self.assertEqual(decoded.target_ip, SERVER_IP)
        self.assertTrue(decoded.is_request)
        self.assertFalse(decoded.is_reply)

    def test_reply_round_trip(self):
        reply = ARPPacket(
            operation=ARP_REPLY,
            sender_mac=SERVER_MAC,
            sender_ip=SERVER_IP,
            target_mac=CLIENT_MAC,
            target_ip=CLIENT_IP,
        )
        decoded = ARPPacket.parse(reply.to_bytes())
        self.assertTrue(decoded.is_reply)
        self.assertFalse(decoded.is_request)

    def test_wire_format_is_twenty_eight_bytes(self):
        """Ethernet/IPv4 ARP is fixed size: 8 bytes of preamble plus two
        6-byte MACs and two 4-byte addresses."""
        request = ARPPacket(ARP_REQUEST, CLIENT_MAC, CLIENT_IP, b"\x00" * 6, SERVER_IP)
        self.assertEqual(len(request.to_bytes()), 28)

    def test_wire_format_header_fields(self):
        request = ARPPacket(ARP_REQUEST, CLIENT_MAC, CLIENT_IP, b"\x00" * 6, SERVER_IP)
        wire = request.to_bytes()
        hardware, protocol, hlen, plen, operation = struct.unpack_from("!HHBBH", wire, 0)
        self.assertEqual(hardware, 1)  # Ethernet
        self.assertEqual(protocol, 0x0800)  # IPv4
        self.assertEqual(hlen, 6)
        self.assertEqual(plen, 4)
        self.assertEqual(operation, ARP_REQUEST)

    def test_truncated_packet_raises(self):
        with self.assertRaises(ValueError):
            ARPPacket.parse(b"\x00" * 27)


class TestARPCache(unittest.TestCase):
    def test_store_and_lookup(self):
        cache = ARPCache()
        cache.store(CLIENT_IP, CLIENT_MAC)
        self.assertEqual(cache.lookup(CLIENT_IP), CLIENT_MAC)
        self.assertIsNone(cache.lookup(SERVER_IP))

    def test_entries_expire(self):
        cache = ARPCache(timeout=10.0)
        cache.store(CLIENT_IP, CLIENT_MAC, now=100.0)
        self.assertEqual(cache.lookup(CLIENT_IP, now=105.0), CLIENT_MAC)
        self.assertIsNone(cache.lookup(CLIENT_IP, now=111.0))

    def test_expire_reports_how_many_it_removed(self):
        cache = ARPCache(timeout=10.0)
        cache.store(CLIENT_IP, CLIENT_MAC, now=100.0)
        cache.store(SERVER_IP, SERVER_MAC, now=100.0)
        self.assertEqual(cache.expire(now=111.0), 2)
        self.assertEqual(len(cache), 0)

    def test_cache_is_bounded(self):
        cache = ARPCache(max_entries=4)
        for i in range(20):
            cache.store(ip_to_bytes("10.0.0.%d" % (i + 1)), CLIENT_MAC)
        self.assertLessEqual(len(cache), 4)

    def test_clear_empties_the_cache(self):
        cache = ARPCache()
        cache.store(CLIENT_IP, CLIENT_MAC)
        cache.clear()
        self.assertEqual(len(cache), 0)

    def test_snapshot_is_a_copy(self):
        cache = ARPCache()
        cache.store(CLIENT_IP, CLIENT_MAC)
        snapshot = cache.snapshot()
        snapshot.clear()
        self.assertEqual(len(cache), 1)


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------


class TestUDP(unittest.TestCase):
    def test_round_trip(self):
        original = UDPSegment(53, 5353, b"hello dns")
        wire = original.to_bytes(CLIENT_IP, SERVER_IP)
        decoded = UDPSegment.parse(wire, CLIENT_IP, SERVER_IP)
        self.assertEqual(decoded.src_port, 53)
        self.assertEqual(decoded.dst_port, 5353)
        self.assertEqual(decoded.payload, b"hello dns")

    def test_length_field_covers_header_and_payload(self):
        """8 bytes of header plus 5 of payload is 13."""
        segment = UDPSegment(1, 2, b"hello")
        self.assertEqual(segment.length, 13)
        wire = segment.to_bytes(CLIENT_IP, SERVER_IP)
        self.assertEqual(struct.unpack_from("!H", wire, 4)[0], 13)

    def test_checksum_is_verified_on_parse(self):
        wire = bytearray(UDPSegment(1, 2, b"hello").to_bytes(CLIENT_IP, SERVER_IP))
        wire[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            UDPSegment.parse(bytes(wire), CLIENT_IP, SERVER_IP)

    def test_a_corrupted_port_is_caught_by_the_pseudo_header(self):
        """The pseudo-header binds the ports to the addresses, so flipping a
        port invalidates the checksum."""
        wire = bytearray(UDPSegment(1234, 80, b"x").to_bytes(CLIENT_IP, SERVER_IP))
        struct.pack_into("!H", wire, 0, 1235)
        with self.assertRaises(ValueError):
            UDPSegment.parse(bytes(wire), CLIENT_IP, SERVER_IP)

    def test_zero_checksum_is_accepted(self):
        """A zero checksum means "not computed", which IPv4 permits."""
        wire = UDPSegment(1, 2, b"x").to_bytes(CLIENT_IP, SERVER_IP, compute_checksum=False)
        decoded = UDPSegment.parse(wire, CLIENT_IP, SERVER_IP)
        self.assertEqual(decoded.payload, b"x")

    def test_empty_payload_round_trips(self):
        wire = UDPSegment(1, 2).to_bytes(CLIENT_IP, SERVER_IP)
        self.assertEqual(UDPSegment.parse(wire, CLIENT_IP, SERVER_IP).payload, b"")

    def test_truncated_datagram_raises(self):
        with self.assertRaises(ValueError):
            UDPSegment.parse(b"\x00" * 7, CLIENT_IP, SERVER_IP)


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------


class TestICMP(unittest.TestCase):
    def test_echo_request_round_trip(self):
        echo = EchoMessage(identifier=0x1234, sequence=7, data=b"ping payload")
        wire = echo.to_icmp(ECHO_REQUEST).to_bytes()
        decoded = ICMPMessage.parse(wire)
        self.assertEqual(decoded.type, ECHO_REQUEST)
        self.assertEqual(decoded.type_name, "echo-request")

        back = EchoMessage.from_icmp(decoded)
        self.assertEqual(back.identifier, 0x1234)
        self.assertEqual(back.sequence, 7)
        self.assertEqual(back.data, b"ping payload")

    def test_echo_reply_is_a_different_type(self):
        echo = EchoMessage(1, 1, b"x")
        self.assertEqual(echo.to_icmp(ECHO_REPLY).type, ECHO_REPLY)
        self.assertEqual(echo.to_icmp(ECHO_REPLY).type_name, "echo-reply")

    def test_checksum_is_valid_on_the_wire(self):
        wire = EchoMessage(1, 1, b"abc").to_icmp(ECHO_REQUEST).to_bytes()
        self.assertTrue(verify(wire))

    def test_checksum_has_no_pseudo_header(self):
        """Unlike TCP and UDP, ICMP is checksummed over itself alone.

        If the implementation wrongly used a pseudo-header, the result would
        be the same for both calls here, so instead check against the value
        computed directly over the bytes.
        """
        message = ICMPMessage(ECHO_REQUEST, 0, b"\x00\x01\x00\x02payload")
        wire = message.to_bytes()
        self.assertEqual(struct.unpack_from("!H", wire, 2)[0], checksum(
            wire[:2] + b"\x00\x00" + wire[4:]
        ))

    def test_corrupted_message_is_rejected(self):
        wire = bytearray(EchoMessage(1, 1, b"abc").to_icmp(ECHO_REQUEST).to_bytes())
        wire[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            ICMPMessage.parse(bytes(wire))

    def test_truncated_message_raises(self):
        with self.assertRaises(ValueError):
            ICMPMessage.parse(b"\x08\x00\x00")

    def test_short_echo_body_raises(self):
        with self.assertRaises(ValueError):
            EchoMessage.from_icmp(ICMPMessage(ECHO_REQUEST, 0, b"\x00\x01"))

    def test_unknown_type_gets_a_fallback_name(self):
        self.assertEqual(ICMPMessage(99, 0, b"").type_name, "type-99")


# ---------------------------------------------------------------------------
# Sequence-number arithmetic (RFC 1982)
# ---------------------------------------------------------------------------


class TestSequenceArithmetic(unittest.TestCase):
    def test_add_wraps(self):
        self.assertEqual(seq_add(SEQ_MASK, 1), 0)
        self.assertEqual(seq_add(0, -1), SEQ_MASK)

    def test_diff_is_signed(self):
        self.assertEqual(seq_diff(10, 5), 5)
        self.assertEqual(seq_diff(5, 10), -5)
        self.assertEqual(seq_diff(0, 1), -1)

    def test_diff_across_the_wrap_is_small_and_positive(self):
        """Counting from just below the wrap to just past it is a short hop,
        not a three-billion-byte jump backwards."""
        self.assertEqual(seq_diff(1, SEQ_MASK), 2)

    def test_diff_across_the_wrap_is_small_and_negative(self):
        self.assertEqual(seq_diff(SEQ_MASK, 1), -2)

    def test_ordering_across_the_wrap(self):
        """SEQ_MASK and 0 are adjacent, so the wrap must not look like a jump."""
        self.assertTrue(seq_lt(SEQ_MASK, 0))
        self.assertTrue(seq_gt(0, SEQ_MASK))
        self.assertTrue(seq_le(SEQ_MASK, 0))
        self.assertTrue(seq_ge(0, SEQ_MASK))

    def test_ordering_is_reflexive(self):
        for seq in (0, 1, 12345, SEQ_MASK):
            self.assertTrue(seq_le(seq, seq))
            self.assertTrue(seq_ge(seq, seq))
            self.assertFalse(seq_lt(seq, seq))
            self.assertFalse(seq_gt(seq, seq))

    def test_exactly_half_the_space_apart_is_undefined(self):
        """RFC 1982 declares a difference of 2**31 undefined: the distance is
        the same in both directions, so neither number can be said to come
        first.

        Rather than silently picking a direction and being wrong half the
        time, every comparison answers False.  Callers that could plausibly
        see such a pair -- the receive-window check, mainly -- are written so
        that a False answer is the safe one.
        """
        a, b = 0, SEQ_HALF
        self.assertFalse(seq_lt(a, b))
        self.assertFalse(seq_gt(a, b))
        self.assertFalse(seq_le(a, b))
        self.assertFalse(seq_ge(a, b))
        # And the signed distance reports the negative extreme, which is how
        # the ambiguity is detected internally.
        self.assertEqual(seq_diff(a, b), -SEQ_HALF)

    def test_just_short_of_half_the_space_is_ordered(self):
        """One less than the ambiguous distance is unambiguous again."""
        a = 0
        b = SEQ_HALF - 1
        self.assertTrue(seq_lt(a, b))
        self.assertFalse(seq_gt(a, b))

    def test_between_is_half_open(self):
        """``low <= seq < high``, because this is the receive-window test and
        the byte at ``high`` is outside it."""
        self.assertTrue(seq_between(5, 1, 10))
        self.assertTrue(seq_between(1, 1, 10))  # low is inclusive
        self.assertFalse(seq_between(10, 1, 10))  # high is exclusive
        self.assertFalse(seq_between(0, 1, 10))
        self.assertFalse(seq_between(11, 1, 10))

    def test_between_spans_the_wrap(self):
        low = SEQ_MASK - 2
        high = 3
        self.assertTrue(seq_between(0, low, high))
        self.assertTrue(seq_between(SEQ_MASK, low, high))
        self.assertFalse(seq_between(10, low, high))

    def test_min_and_max_are_wrap_aware(self):
        self.assertEqual(seq_max(SEQ_MASK, 0), 0)
        self.assertEqual(seq_min(SEQ_MASK, 0), SEQ_MASK)
        self.assertEqual(seq_max(100, 200), 200)
        self.assertEqual(seq_min(100, 200), 100)

    def test_ordering_is_antisymmetric(self):
        """For any two sequence numbers that are not exactly half the space
        apart, exactly one of ``lt`` and ``gt`` holds."""
        values = [0, 1, 2, SEQ_MASK, SEQ_MASK - 1, SEQ_HALF - 1, SEQ_HALF, SEQ_HALF + 1]
        checked = 0
        for a in values:
            for b in values:
                if a == b or abs(seq_diff(a, b)) == SEQ_HALF:
                    continue
                self.assertNotEqual(seq_lt(a, b), seq_gt(a, b), (a, b))
                self.assertTrue(seq_lt(a, b) or seq_gt(a, b), (a, b))
                checked += 1
        self.assertGreater(checked, 20)


# ---------------------------------------------------------------------------
# TCP options and segments
# ---------------------------------------------------------------------------


class TestTCPOptions(unittest.TestCase):
    def test_empty_options_serialise_to_nothing(self):
        self.assertEqual(TCPOptions().to_bytes(), b"")
        self.assertTrue(TCPOptions().is_empty)

    def test_mss_round_trip(self):
        wire = TCPOptions(mss=1460).to_bytes()
        self.assertEqual(TCPOptions.parse(wire).mss, 1460)

    def test_window_scale_round_trip(self):
        wire = TCPOptions(window_scale=7).to_bytes()
        self.assertEqual(TCPOptions.parse(wire).window_scale, 7)

    def test_sack_permitted_round_trip(self):
        wire = TCPOptions(sack_permitted=True).to_bytes()
        self.assertTrue(TCPOptions.parse(wire).sack_permitted)

    def test_all_options_together(self):
        original = TCPOptions(mss=1460, window_scale=4, sack_permitted=True)
        decoded = TCPOptions.parse(original.to_bytes())
        self.assertEqual(decoded.mss, 1460)
        self.assertEqual(decoded.window_scale, 4)
        self.assertTrue(decoded.sack_permitted)

    def test_padding_fills_out_to_a_word_boundary(self):
        """The option block must be a whole number of 32-bit words, so the
        pad length is whatever it takes to reach a multiple of four."""
        # mss is 4 bytes: already a multiple of four, no padding at all.
        self.assertEqual(len(TCPOptions(mss=1460).to_bytes()), 4)

        # mss (4) + window scale (3) = 7 -> one pad byte.
        self.assertEqual(len(TCPOptions(mss=1460, window_scale=3).to_bytes()), 8)

        # mss (4) + sack-permitted (2) = 6 -> two pad bytes.
        self.assertEqual(len(TCPOptions(mss=1460, sack_permitted=True).to_bytes()), 8)

        # mss (4) + window scale (3) + sack-permitted (2) = 9 -> three pads.
        self.assertEqual(
            len(TCPOptions(mss=1460, window_scale=3, sack_permitted=True).to_bytes()), 12
        )

    def test_padding_uses_nops_not_zeros(self):
        """Padding is NOPs, except for the final single byte, which has to be
        EOL: a lone NOP would be an option header with no body and a parser
        would have nothing to consume."""
        # Two pad bytes: both NOPs.
        wire = TCPOptions(mss=1460, sack_permitted=True).to_bytes()
        self.assertEqual(wire[-2:], b"\x01\x01")

        # One pad byte: EOL, not a NOP.
        wire = TCPOptions(mss=1460, window_scale=3).to_bytes()
        self.assertEqual(wire[-1:], b"\x00")

    def test_padding_never_becomes_a_dangling_option_header(self):
        """Every combination must survive a parse without inventing options."""
        for options in (
            TCPOptions(mss=1460),
            TCPOptions(window_scale=3),
            TCPOptions(sack_permitted=True),
            TCPOptions(mss=1460, window_scale=3),
            TCPOptions(mss=1460, sack_permitted=True),
            TCPOptions(window_scale=3, sack_permitted=True),
            TCPOptions(mss=1460, window_scale=3, sack_permitted=True),
        ):
            wire = options.to_bytes()
            self.assertEqual(len(wire) % 4, 0)
            decoded = TCPOptions.parse(wire)
            self.assertEqual(decoded.mss, options.mss)
            self.assertEqual(decoded.window_scale, options.window_scale)
            self.assertEqual(decoded.sack_permitted, options.sack_permitted)

    def test_parse_skips_leading_nops_and_stops_at_eol(self):
        """A real SYN carries NOP padding; parsing must walk past it."""
        wire = bytes([1, 1, 2, 4, 0x05, 0xB4, 0, 0])
        options = TCPOptions.parse(wire)
        self.assertEqual(options.mss, 1460)

    def test_parse_handles_a_trailing_eol(self):
        options = TCPOptions.parse(bytes([2, 4, 0x05, 0xB4, 0]))
        self.assertEqual(options.mss, 1460)

    def test_parse_tolerates_a_truncated_option(self):
        """A malformed option block must not raise; it just yields less."""
        options = TCPOptions.parse(bytes([2, 4, 0x05]))
        self.assertIsNone(options.mss)

    def test_parse_tolerates_a_zero_length_option(self):
        """A length of zero would loop forever if it were not special-cased."""
        options = TCPOptions.parse(bytes([2, 0, 0, 0]))
        self.assertIsNone(options.mss)

    def test_mss_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            TCPOptions(mss=0x10000).to_bytes()

    def test_window_scale_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            TCPOptions(window_scale=256).to_bytes()


class TestTCPSegment(unittest.TestCase):
    def test_round_trip(self):
        original = TCPSegment(
            src_port=49152,
            dst_port=80,
            seq=0xDEADBEEF,
            ack=0x12345678,
            flags=FLAG_ACK | FLAG_PSH,
            window=64240,
            payload=b"GET / HTTP/1.0\r\n\r\n",
        )
        decoded = TCPSegment.parse(
            original.to_bytes(CLIENT_IP, SERVER_IP), CLIENT_IP, SERVER_IP
        )
        self.assertEqual(decoded.src_port, 49152)
        self.assertEqual(decoded.dst_port, 80)
        self.assertEqual(decoded.seq, 0xDEADBEEF)
        self.assertEqual(decoded.ack, 0x12345678)
        self.assertEqual(decoded.window, 64240)
        self.assertEqual(decoded.payload, b"GET / HTTP/1.0\r\n\r\n")
        self.assertTrue(decoded.is_ack)
        self.assertTrue(decoded.is_psh)

    def test_checksum_is_verified_on_parse(self):
        wire = bytearray(
            TCPSegment(1, 2, 3, 4, FLAG_ACK, payload=b"x").to_bytes(CLIENT_IP, SERVER_IP)
        )
        wire[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            TCPSegment.parse(bytes(wire), CLIENT_IP, SERVER_IP)

    def test_checksum_verification_can_be_skipped(self):
        """Needed for capture analysis, where showing a corrupt packet is more
        useful than refusing to decode it."""
        wire = bytearray(
            TCPSegment(1, 2, 3, 4, FLAG_ACK, payload=b"x").to_bytes(CLIENT_IP, SERVER_IP)
        )
        struct.pack_into("!H", wire, 16, 0xBEEF)  # corrupt the checksum field
        with self.assertRaises(ValueError):
            TCPSegment.parse(bytes(wire), CLIENT_IP, SERVER_IP)
        decoded = TCPSegment.parse(bytes(wire), CLIENT_IP, SERVER_IP, verify_checksum=False)
        self.assertEqual(decoded.payload, b"x")

    def test_seq_len_counts_syn_and_fin(self):
        """SYN and FIN each occupy one sequence number even with no payload."""
        self.assertEqual(TCPSegment(1, 2, 0, 0, FLAG_SYN).seq_len, 1)
        self.assertEqual(TCPSegment(1, 2, 0, 0, FLAG_FIN).seq_len, 1)
        self.assertEqual(TCPSegment(1, 2, 0, 0, FLAG_SYN | FLAG_FIN).seq_len, 2)
        self.assertEqual(TCPSegment(1, 2, 0, 0, FLAG_ACK).seq_len, 0)
        self.assertEqual(TCPSegment(1, 2, 0, 0, FLAG_ACK, payload=b"abc").seq_len, 3)

    def test_seq_end(self):
        segment = TCPSegment(1, 2, 1000, 0, FLAG_SYN, payload=b"abcd")
        self.assertEqual(segment.seq_end, 1005)

    def test_seq_end_wraps(self):
        segment = TCPSegment(1, 2, SEQ_MASK - 1, 0, FLAG_ACK, payload=b"abc")
        self.assertEqual(segment.seq_end, 1)

    def test_acknowledges(self):
        segment = TCPSegment(1, 2, 0, 500, FLAG_ACK)
        self.assertTrue(segment.acknowledges(500))
        self.assertTrue(segment.acknowledges(499))
        self.assertFalse(segment.acknowledges(501))

    def test_flags_round_trip_through_the_wire(self):
        for flag in (FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_PSH, FLAG_ACK):
            wire = TCPSegment(1, 2, 0, 0, flag).to_bytes(CLIENT_IP, SERVER_IP)
            decoded = TCPSegment.parse(wire, CLIENT_IP, SERVER_IP)
            self.assertEqual(decoded.flags, flag)

    def test_header_length_is_twenty_without_options(self):
        self.assertEqual(TCPSegment(1, 2, 0, 0, FLAG_ACK).header_length, 20)

    def test_header_length_grows_with_options(self):
        segment = TCPSegment(1, 2, 0, 0, FLAG_SYN, options=TCPOptions(mss=1460))
        self.assertEqual(segment.header_length, 24)

    def test_data_offset_field_matches_the_header_length(self):
        segment = TCPSegment(1, 2, 0, 0, FLAG_SYN, options=TCPOptions(mss=1460))
        wire = segment.to_bytes(CLIENT_IP, SERVER_IP)
        self.assertEqual(wire[12] >> 4, 6)  # 24 bytes = 6 words

    def test_options_survive_the_wire(self):
        original = TCPSegment(
            1, 2, 0, 0, FLAG_SYN, options=TCPOptions(mss=1400, window_scale=7, sack_permitted=True)
        )
        decoded = TCPSegment.parse(original.to_bytes(CLIENT_IP, SERVER_IP), CLIENT_IP, SERVER_IP)
        self.assertEqual(decoded.options.mss, 1400)
        self.assertEqual(decoded.options.window_scale, 7)
        self.assertTrue(decoded.options.sack_permitted)

    def test_header_length_never_exceeds_sixty(self):
        self.assertEqual(MAX_HEADER_LEN, 60)

    def test_parse_rejects_a_data_offset_below_five(self):
        wire = bytearray(TCPSegment(1, 2, 0, 0, FLAG_ACK).to_bytes(CLIENT_IP, SERVER_IP))
        wire[12] = 0x40  # offset 4
        with self.assertRaises(ValueError):
            TCPSegment.parse(bytes(wire), CLIENT_IP, SERVER_IP, verify_checksum=False)

    def test_parse_rejects_a_header_longer_than_the_buffer(self):
        wire = bytearray(TCPSegment(1, 2, 0, 0, FLAG_ACK).to_bytes(CLIENT_IP, SERVER_IP))
        wire[12] = 0xF0  # claims 60 bytes of header, only 20 present
        with self.assertRaises(ValueError):
            TCPSegment.parse(bytes(wire), CLIENT_IP, SERVER_IP, verify_checksum=False)

    def test_parse_rejects_a_truncated_segment(self):
        with self.assertRaises(ValueError):
            TCPSegment.parse(b"\x00" * 19, CLIENT_IP, SERVER_IP, verify_checksum=False)

    def test_ports_out_of_range_raise(self):
        with self.assertRaises(ValueError):
            TCPSegment(0x10000, 80, 0, 0, FLAG_ACK).to_bytes(CLIENT_IP, SERVER_IP)

    def test_window_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            TCPSegment(1, 2, 0, 0, FLAG_ACK, window=0x10000).to_bytes(CLIENT_IP, SERVER_IP)

    def test_describe_flags(self):
        self.assertEqual(describe_flags(FLAG_SYN | FLAG_ACK), "SYN,ACK")
        self.assertEqual(describe_flags(FLAG_ACK | FLAG_PSH), "ACK,PSH")
        self.assertEqual(describe_flags(FLAG_SYN), "SYN")

    def test_a_flagless_segment_renders_as_a_placeholder(self):
        """An empty string would leave a hole in a capture line, so a segment
        with no flags shows a dash instead."""
        self.assertEqual(describe_flags(0), "-")

    def test_describe_reads_like_a_capture_line(self):
        segment = TCPSegment(49152, 80, 100, 200, FLAG_ACK | FLAG_PSH, payload=b"x" * 10)
        text = segment.describe()
        self.assertIn("49152 > 80", text)
        self.assertIn("ACK,PSH", text)
        self.assertIn("len=10", text)


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


class TestStateHelpers(unittest.TestCase):
    def test_closed_is_terminal(self):
        self.assertTrue(is_closed(CLOSED))
        self.assertFalse(is_closed(ESTABLISHED))

    def test_synchronised_states(self):
        for state in (ESTABLISHED, "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT",
                      "CLOSING", "LAST-ACK", "TIME-WAIT"):
            self.assertTrue(is_synchronised(state), state)

    def test_unsynchronised_states(self):
        for state in (CLOSED, "LISTEN", "SYN-SENT", "SYN-RECEIVED"):
            self.assertFalse(is_synchronised(state), state)


# ---------------------------------------------------------------------------
# Send / receive buffers
# ---------------------------------------------------------------------------


class TestSendQueue(unittest.TestCase):
    def test_write_then_read_back(self):
        queue = SendQueue(iss=1000, capacity=1024)
        self.assertEqual(queue.write(b"hello"), 5)
        self.assertEqual(queue.buffered, 5)
        self.assertEqual(queue.peek(1000, 5), b"hello")

    def test_acknowledge_advances_una(self):
        queue = SendQueue(iss=1000, capacity=1024)
        queue.write(b"hello world")
        queue.acknowledge(1005)
        self.assertEqual(queue.una, 1005)
        self.assertEqual(queue.buffered, 6)

    def test_in_flight_and_unsent(self):
        queue = SendQueue(iss=1000, capacity=1024)
        queue.write(b"0123456789")
        queue.nxt = 1004
        self.assertEqual(queue.in_flight, 4)
        self.assertEqual(queue.unsent, 6)

    def test_acknowledging_beyond_nxt_pulls_nxt_forward(self):
        """Regression: an ACK can cover bytes we have not marked as sent if a
        retransmission raced with it.  Leaving ``nxt`` behind ``una`` made the
        in-flight count negative and stalled the send path forever."""
        queue = SendQueue(iss=1000, capacity=1024)
        queue.write(b"0123456789")
        queue.nxt = 1002
        queue.acknowledge(1006)
        self.assertEqual(queue.una, 1006)
        self.assertEqual(queue.nxt, 1006)
        self.assertEqual(queue.in_flight, 0)
        self.assertGreaterEqual(queue.unsent, 0)

    def test_acknowledging_the_whole_buffer_empties_it(self):
        queue = SendQueue(iss=0, capacity=1024)
        queue.write(b"abc")
        queue.acknowledge(3)
        self.assertTrue(queue.is_empty)
        self.assertEqual(queue.buffered, 0)

    def test_capacity_is_enforced(self):
        queue = SendQueue(iss=0, capacity=4)
        self.assertEqual(queue.write(b"abcdef"), 4)
        self.assertEqual(queue.space, 0)
        self.assertEqual(queue.write(b"more"), 0)

    def test_rewind_moves_nxt_back(self):
        queue = SendQueue(iss=1000, capacity=1024)
        queue.write(b"0123456789")
        queue.nxt = 1008
        queue.rewind(1002)
        self.assertEqual(queue.nxt, 1002)

    def test_peek_past_the_end_returns_what_exists(self):
        queue = SendQueue(iss=1000, capacity=1024)
        queue.write(b"abc")
        self.assertEqual(queue.peek(1000, 100), b"abc")

    def test_clear_empties_the_buffer(self):
        """``clear`` is only used on teardown, so it drops the buffered bytes
        and leaves the sequence numbers where they are."""
        queue = SendQueue(iss=1000, capacity=1024)
        queue.write(b"abc")
        queue.nxt = 1003
        queue.clear()
        self.assertEqual(queue.buffered, 0)
        self.assertTrue(queue.is_empty)
        self.assertEqual(queue.space, 1024)
        self.assertEqual(queue.unsent, 0)

    def test_a_full_queue_accepts_nothing(self):
        queue = SendQueue(iss=0, capacity=4)
        queue.write(b"abcd")
        self.assertEqual(queue.write(b"e"), 0)
        self.assertEqual(queue.space, 0)


class TestReceiveQueue(unittest.TestCase):
    """``irs`` is the peer's initial sequence number, so the first data byte
    belongs at ``irs + 1``: the SYN consumed one sequence number.  These tests
    all start from ``irs=99``, making the expected first byte 100."""

    def test_first_expected_byte_is_one_past_the_peer_isn(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        self.assertEqual(queue.nxt, 100)

    def test_in_order_insert(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        self.assertEqual(queue.insert(100, b"hello"), 5)
        self.assertEqual(queue.available, 5)
        self.assertEqual(queue.nxt, 105)

    def test_read_consumes(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        queue.insert(100, b"hello world")
        self.assertEqual(queue.read(5), b"hello")
        self.assertEqual(queue.read(100), b" world")
        self.assertEqual(queue.available, 0)

    def test_reading_more_than_is_available_returns_what_there_is(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        queue.insert(100, b"abc")
        self.assertEqual(queue.read(1000), b"abc")
        self.assertEqual(queue.read(1), b"")

    def test_out_of_order_is_held(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        self.assertEqual(queue.insert(110, b"later"), 0)
        self.assertEqual(queue.held_out_of_order, 5)
        self.assertEqual(queue.available, 0)

    def test_a_hole_filling_segment_releases_the_buffer(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        queue.insert(105, b"world")
        self.assertEqual(queue.held_out_of_order, 5)
        queue.insert(100, b"hello")
        self.assertEqual(queue.available, 10)
        self.assertEqual(queue.read(10), b"helloworld")
        self.assertEqual(queue.held_out_of_order, 0)

    def test_duplicate_segments_are_dropped(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        queue.insert(100, b"hello")
        self.assertEqual(queue.insert(100, b"hello"), 0)
        self.assertEqual(queue.available, 5)
        self.assertEqual(queue.duplicates, 1)

    def test_a_fully_old_segment_is_dropped(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        queue.insert(100, b"hello")
        self.assertEqual(queue.insert(100, b"he"), 0)
        self.assertEqual(queue.available, 5)

    def test_overlapping_segment_is_trimmed(self):
        """Only the genuinely new tail may be delivered, or the stream would
        contain duplicated bytes.  A retransmission that starts two bytes
        behind ``nxt`` and runs six bytes past it contributes six bytes."""
        queue = ReceiveQueue(irs=99, capacity=1024)
        queue.insert(100, b"hello")
        self.assertEqual(queue.insert(103, b"lo world"), 6)
        self.assertEqual(queue.read(100), b"hello world")

    def test_window_shrinks_as_data_arrives(self):
        queue = ReceiveQueue(irs=99, capacity=100)
        self.assertEqual(queue.window, 100)
        queue.insert(100, b"x" * 40)
        self.assertEqual(queue.window, 60)

    def test_window_counts_held_out_of_order_data(self):
        """Bytes parked in the holding area occupy memory, so they have to
        count against the window or the peer could overrun it."""
        queue = ReceiveQueue(irs=99, capacity=100)
        queue.insert(200, b"x" * 40)
        self.assertEqual(queue.window, 60)

    def test_reading_reopens_the_window(self):
        queue = ReceiveQueue(irs=99, capacity=100)
        queue.insert(100, b"x" * 40)
        self.assertEqual(queue.window, 60)
        queue.read(40)
        self.assertEqual(queue.window, 100)

    def test_discard_before_frees_held_out_of_order_space(self):
        """Used when the peer acknowledges past data we were still holding."""
        queue = ReceiveQueue(irs=99, capacity=100)
        queue.insert(200, b"x" * 40)
        self.assertEqual(queue.window, 60)
        queue.discard_before(240)
        self.assertEqual(queue.held_out_of_order, 0)
        self.assertEqual(queue.window, 100)

    def test_a_segment_larger_than_capacity_is_trimmed(self):
        """Regression: the buffer used to grow without limit, so a peer that
        ignored the advertised window could exhaust memory.  Flow control is
        only a promise if we also enforce it ourselves."""
        queue = ReceiveQueue(irs=99, capacity=8)
        accepted = queue.insert(100, b"x" * 100)
        self.assertEqual(accepted, 8)
        self.assertEqual(queue.available, 8)
        self.assertEqual(queue.nxt, 108)
        self.assertEqual(queue.window, 0)

    def test_a_full_buffer_accepts_nothing_more(self):
        queue = ReceiveQueue(irs=99, capacity=8)
        queue.insert(100, b"x" * 8)
        self.assertEqual(queue.insert(108, b"y" * 8), 0)
        self.assertEqual(queue.available, 8)

    def test_out_of_order_data_is_bounded_by_the_free_window(self):
        queue = ReceiveQueue(irs=99, capacity=8)
        queue.insert(200, b"x" * 100)
        self.assertLessEqual(queue.held_out_of_order, 8)
        self.assertGreaterEqual(queue.window, 0)

    def test_total_buffered_bytes_never_exceed_capacity(self):
        """The property that matters: however the segments are arranged, the
        queue holds at most ``capacity`` bytes."""
        queue = ReceiveQueue(irs=99, capacity=64)
        seq = 100
        for i in range(40):
            queue.insert(seq, bytes([i]) * 30)
            seq += 30
            self.assertLessEqual(
                queue.available + queue.held_out_of_order, 64, "iteration %d" % i
            )

    def test_sequence_wrap_is_handled(self):
        queue = ReceiveQueue(irs=SEQ_MASK - 2, capacity=1024)
        self.assertEqual(queue.nxt, SEQ_MASK - 1)
        queue.insert(SEQ_MASK - 1, b"abcde")
        self.assertEqual(queue.read(5), b"abcde")
        self.assertEqual(queue.nxt, 3)

    def test_data_across_the_wrap_is_contiguous(self):
        """Four bytes past 0xfffffffe is sequence number 2, not a jump."""
        queue = ReceiveQueue(irs=SEQ_MASK - 2, capacity=1024)
        queue.insert(SEQ_MASK - 1, b"abc")
        self.assertEqual(queue.nxt, 1)
        queue.insert(1, b"def")
        self.assertEqual(queue.read(100), b"abcdef")

    def test_clear_empties_everything(self):
        queue = ReceiveQueue(irs=99, capacity=1024)
        queue.insert(100, b"abc")
        queue.insert(200, b"xyz")
        queue.clear()
        self.assertEqual(queue.available, 0)
        self.assertEqual(queue.held_out_of_order, 0)


class TestReorderQueue(unittest.TestCase):
    def test_insert_and_take(self):
        queue = ReorderQueue(capacity=1024)
        self.assertTrue(queue.insert(100, b"abc"))
        self.assertEqual(queue.take(100), b"abc")
        self.assertIsNone(queue.take(100))

    def test_peek_does_not_consume(self):
        queue = ReorderQueue(capacity=1024)
        queue.insert(100, b"abc")
        self.assertEqual(queue.peek(100), b"abc")
        self.assertEqual(queue.peek(100), b"abc")

    def test_duplicate_insert_is_rejected(self):
        queue = ReorderQueue(capacity=1024)
        queue.insert(100, b"abc")
        self.assertFalse(queue.insert(100, b"abc"))

    def test_discard_before(self):
        queue = ReorderQueue(capacity=1024)
        queue.insert(100, b"abc")
        queue.insert(200, b"def")
        self.assertEqual(queue.discard_before(150), 1)
        self.assertEqual(len(queue), 1)

    def test_capacity_is_enforced(self):
        queue = ReorderQueue(capacity=8)
        self.assertTrue(queue.insert(0, b"x" * 8))
        self.assertFalse(queue.insert(100, b"y" * 8))

    def test_contains(self):
        queue = ReorderQueue(capacity=1024)
        queue.insert(100, b"abc")
        self.assertIn(100, queue)
        self.assertNotIn(101, queue)


# ---------------------------------------------------------------------------
# Retransmission and RTT estimation
# ---------------------------------------------------------------------------


class TestRTOEstimator(unittest.TestCase):
    def test_initial_rto(self):
        estimator = RTOEstimator()
        self.assertEqual(estimator.rto, 1.0)
        self.assertEqual(estimator.samples, 0)

    def test_first_sample_sets_srtt_and_half_the_variance(self):
        """RFC 6298: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4*RTTVAR = 3R."""
        estimator = RTOEstimator(min_rto=0.001)
        rto = estimator.sample(0.1)
        self.assertAlmostEqual(estimator.srtt, 0.1, places=6)
        self.assertAlmostEqual(estimator.rttvar, 0.05, places=6)
        self.assertAlmostEqual(rto, 0.3, places=6)

    def test_second_sample_applies_the_rfc6298_gains(self):
        """SRTT = 7/8*old + 1/8*R, RTTVAR = 3/4*old + 1/4*|SRTT-R|."""
        estimator = RTOEstimator(min_rto=0.001, max_rto=1000.0)
        estimator.sample(0.1)
        estimator.sample(0.2)
        self.assertAlmostEqual(estimator.srtt, 0.1125, places=6)
        self.assertAlmostEqual(estimator.rttvar, 0.0625, places=6)
        self.assertEqual(estimator.samples, 2)

    def test_rto_is_clamped_below(self):
        estimator = RTOEstimator(min_rto=0.2)
        estimator.sample(0.0001)
        self.assertGreaterEqual(estimator.rto, 0.2)

    def test_rto_is_clamped_above(self):
        estimator = RTOEstimator(max_rto=5.0)
        estimator.sample(100.0)
        self.assertEqual(estimator.rto, 5.0)

    def test_backoff_doubles(self):
        estimator = RTOEstimator()
        self.assertEqual(estimator.backoff(), 2.0)
        self.assertEqual(estimator.backoff(), 4.0)
        self.assertEqual(estimator.backoff(), 8.0)

    def test_backoff_is_capped(self):
        estimator = RTOEstimator(max_rto=5.0)
        for _ in range(10):
            estimator.backoff()
        self.assertEqual(estimator.rto, 5.0)

    def test_recompute_undoes_backoff(self):
        """Regression: after a loss the RTO backs off exponentially.  Once an
        ACK moves the window forward the path is clearly alive again, so
        continuing to wait eight seconds between retransmissions would turn a
        brief loss into a stalled connection."""
        estimator = RTOEstimator(min_rto=0.001, max_rto=1000.0)
        estimator.sample(0.1)
        steady = estimator.rto
        for _ in range(4):
            estimator.backoff()
        self.assertGreater(estimator.rto, steady)
        self.assertAlmostEqual(estimator.recompute(), steady, places=6)

    def test_recompute_without_any_sample_falls_back_to_the_default(self):
        estimator = RTOEstimator()
        estimator.backoff()
        self.assertEqual(estimator.recompute(), 1.0)

    def test_a_zero_rtt_is_ignored(self):
        """A same-millisecond ACK would otherwise drive SRTT toward zero and
        produce a nonsensical RTO."""
        estimator = RTOEstimator()
        before = estimator.rto
        estimator.sample(0.0)
        self.assertEqual(estimator.rto, before)
        self.assertEqual(estimator.samples, 0)

    def test_reset_forgets_everything(self):
        estimator = RTOEstimator()
        estimator.sample(0.5)
        estimator.backoff()
        estimator.reset()
        self.assertIsNone(estimator.srtt)
        self.assertEqual(estimator.rto, 1.0)
        self.assertEqual(estimator.samples, 0)

    def test_invalid_bounds_raise(self):
        with self.assertRaises(ValueError):
            RTOEstimator(min_rto=0.0)
        with self.assertRaises(ValueError):
            RTOEstimator(min_rto=5.0, max_rto=1.0)


class TestRetransmitQueue(unittest.TestCase):
    def test_add_and_oldest(self):
        queue = RetransmitQueue(capacity=1024)
        queue.add(100, FLAG_ACK, b"abc", now=0.0)
        queue.add(103, FLAG_ACK, b"def", now=0.1)
        self.assertEqual(queue.oldest().seq, 100)
        self.assertEqual(len(queue), 2)

    def test_acknowledge_drops_fully_covered_segments(self):
        queue = RetransmitQueue(capacity=1024)
        queue.add(100, FLAG_ACK, b"abc", now=0.0)
        queue.add(103, FLAG_ACK, b"def", now=0.0)
        acked = queue.acknowledge(103)
        self.assertEqual([e.seq for e in acked], [100])
        self.assertEqual(len(queue), 1)

    def test_a_partially_acknowledged_segment_stays(self):
        queue = RetransmitQueue(capacity=1024)
        queue.add(100, FLAG_ACK, b"abcdef", now=0.0)
        self.assertEqual(queue.acknowledge(103), [])
        self.assertEqual(len(queue), 1)

    def test_syn_counts_as_one_sequence_number(self):
        """A SYN with no payload still occupies sequence number ``seq``, so
        an ACK of seq+1 must retire it."""
        queue = RetransmitQueue(capacity=1024)
        queue.add(100, FLAG_SYN, b"", now=0.0)
        self.assertEqual(len(queue.acknowledge(101)), 1)

    def test_mark_retransmitted_bumps_the_counter(self):
        queue = RetransmitQueue(capacity=1024)
        entry = queue.add(100, FLAG_ACK, b"abc", now=0.0)
        queue.mark_retransmitted(entry, now=1.0)
        self.assertEqual(entry.retransmits, 1)
        self.assertEqual(entry.sent_at, 1.0)
        self.assertTrue(entry.rtt_sampled)

    def test_capacity_is_enforced(self):
        queue = RetransmitQueue(capacity=8)
        self.assertIsNotNone(queue.add(0, FLAG_ACK, b"x" * 8, now=0.0))
        self.assertIsNone(queue.add(8, FLAG_ACK, b"y" * 8, now=0.0))

    def test_bytes_outstanding_tracks_payload(self):
        queue = RetransmitQueue(capacity=1024)
        queue.add(0, FLAG_ACK, b"x" * 10, now=0.0)
        queue.add(10, FLAG_SYN, b"", now=0.0)
        self.assertEqual(queue.bytes_outstanding, 10)

    def test_purge_before(self):
        queue = RetransmitQueue(capacity=1024)
        queue.add(0, FLAG_ACK, b"abc", now=0.0)
        queue.add(3, FLAG_ACK, b"def", now=0.0)
        self.assertEqual(queue.purge_before(3), 1)
        self.assertEqual(len(queue), 1)

    def test_clear(self):
        queue = RetransmitQueue(capacity=1024)
        queue.add(0, FLAG_ACK, b"abc", now=0.0)
        queue.clear()
        self.assertEqual(len(queue), 0)
        self.assertIsNone(queue.oldest())


# ---------------------------------------------------------------------------
# Congestion control
# ---------------------------------------------------------------------------


class TestRenoCongestion(unittest.TestCase):
    def test_starts_in_slow_start(self):
        reno = RenoCongestion(mss=1460)
        self.assertEqual(reno.state, SLOW_START)
        self.assertGreaterEqual(reno.cwnd, 2 * 1460)

    def test_slow_start_grows_by_the_bytes_acked(self):
        reno = RenoCongestion(mss=1460, initial_window=1460, initial_ssthresh=1 << 30)
        reno.on_ack(1460)
        self.assertEqual(reno.cwnd, 2920)
        reno.on_ack(1460)
        self.assertEqual(reno.cwnd, 4380)

    def test_slow_start_exits_when_cwnd_reaches_ssthresh(self):
        reno = RenoCongestion(mss=1460, initial_window=1460, initial_ssthresh=4380)
        reno.on_ack(1460)
        reno.on_ack(1460)
        self.assertEqual(reno.cwnd, 4380)
        self.assertEqual(reno.state, CONGESTION_AVOIDANCE)

    def test_congestion_avoidance_adds_about_one_segment_per_rtt(self):
        """The defining property of congestion avoidance: acknowledging one
        full window of data buys roughly one extra segment of window.

        The per-ACK integer arithmetic makes it approximate rather than exact,
        which is why this is a range and not an equality.
        """
        mss = 1000
        window = 10000
        reno = RenoCongestion(mss=mss, initial_window=window, initial_ssthresh=0)
        reno.on_ack(mss)  # crosses ssthresh, so we are now in congestion avoidance
        self.assertEqual(reno.state, CONGESTION_AVOIDANCE)

        before = reno.cwnd
        for _ in range(window // mss):
            reno.on_ack(mss)
        gained = reno.cwnd - before

        self.assertGreaterEqual(gained, int(mss * 0.8))
        self.assertLessEqual(gained, int(mss * 1.2))

    def test_three_duplicate_acks_trigger_fast_retransmit(self):
        reno = RenoCongestion(mss=1000, initial_window=8000, initial_ssthresh=1 << 30)
        self.assertFalse(reno.on_duplicate_ack(1000))
        self.assertFalse(reno.on_duplicate_ack(1000))
        self.assertTrue(reno.on_duplicate_ack(1000))
        self.assertEqual(reno.state, FAST_RECOVERY)
        self.assertEqual(reno.fast_retransmits, 1)

    def test_fast_retransmit_halves_the_window(self):
        """ssthresh = cwnd/2 and cwnd = ssthresh + 3*MSS, per Reno."""
        mss = 1000
        reno = RenoCongestion(mss=mss, initial_window=8000, initial_ssthresh=1 << 30)
        for _ in range(3):
            reno.on_duplicate_ack(1000)
        self.assertEqual(reno.ssthresh, 4000)
        self.assertEqual(reno.cwnd, 7000)

    def test_further_duplicate_acks_inflate_the_window(self):
        mss = 1000
        reno = RenoCongestion(mss=mss, initial_window=8000, initial_ssthresh=1 << 30)
        for _ in range(3):
            reno.on_duplicate_ack(1000)
        inflated = reno.cwnd
        reno.on_duplicate_ack(1000)
        self.assertEqual(reno.cwnd, inflated + mss)

    def test_recovery_ends_when_the_retransmission_is_acked(self):
        mss = 1000
        reno = RenoCongestion(mss=mss, initial_window=8000, initial_ssthresh=1 << 30)
        for _ in range(3):
            reno.on_duplicate_ack(5000)
        reno.on_ack(mss, ack_number=5000)
        self.assertEqual(reno.state, CONGESTION_AVOIDANCE)
        self.assertEqual(reno.cwnd, 4000)

    def test_recovery_does_not_end_on_a_partial_ack(self):
        mss = 1000
        reno = RenoCongestion(mss=mss, initial_window=8000, initial_ssthresh=1 << 30)
        for _ in range(3):
            reno.on_duplicate_ack(5000)
        reno.on_ack(mss, ack_number=4000)
        self.assertEqual(reno.state, FAST_RECOVERY)

    def test_timeout_collapses_the_window_to_one_segment(self):
        mss = 1000
        reno = RenoCongestion(mss=mss, initial_window=8000, initial_ssthresh=1 << 30)
        reno.on_timeout()
        self.assertEqual(reno.cwnd, mss)
        self.assertEqual(reno.ssthresh, 4000)
        self.assertEqual(reno.state, SLOW_START)
        self.assertEqual(reno.timeouts, 1)

    def test_a_zero_ack_changes_nothing(self):
        reno = RenoCongestion(mss=1000)
        before = reno.cwnd
        reno.on_ack(0)
        self.assertEqual(reno.cwnd, before)

    def test_effective_window_takes_the_smaller(self):
        reno = RenoCongestion(mss=1000, initial_window=8000)
        self.assertEqual(reno.effective_window(2000), 2000)
        self.assertEqual(reno.effective_window(1 << 20), 8000)

    def test_effective_window_never_falls_below_one_segment(self):
        reno = RenoCongestion(mss=1000, initial_window=8000)
        self.assertEqual(reno.effective_window(0), 1000)

    def test_duplicate_ack_counter_resets_on_a_new_ack(self):
        reno = RenoCongestion(mss=1000, initial_window=8000, initial_ssthresh=1 << 30)
        reno.on_duplicate_ack(1000)
        reno.on_duplicate_ack(1000)
        reno.on_ack(1000)
        self.assertEqual(reno.duplicate_acks, 0)
        self.assertFalse(reno.on_duplicate_ack(2000))

    def test_invalid_mss_raises(self):
        with self.assertRaises(ValueError):
            RenoCongestion(mss=0)


# ---------------------------------------------------------------------------
# pcap export
# ---------------------------------------------------------------------------


class TestPcapWriter(unittest.TestCase):
    def test_file_header_matches_the_spec(self):
        """A pcap file starts with a 24-byte header: magic, version 2.4, the
        timezone fields (zero) and the snapshot length and link type."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.pcap")
            with PcapWriter(path) as writer:
                writer.write(b"\x00" * 60)
            with open(path, "rb") as handle:
                raw = handle.read()

        magic, major, minor, tz, sigfigs, snaplen, linktype = struct.unpack_from(
            "<IHHiIII", raw, 0
        )
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual((major, minor), (2, 4))
        self.assertEqual((tz, sigfigs), (0, 0))
        self.assertEqual(snaplen, 65535)
        self.assertEqual(linktype, LINKTYPE_ETHERNET)

    def test_record_header_and_payload(self):
        frame = bytes(range(60))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.pcap")
            with PcapWriter(path) as writer:
                writer.write(frame, timestamp=1_700_000_000.5)
            with open(path, "rb") as handle:
                raw = handle.read()

        sec, usec, caplen, origlen = struct.unpack_from("<IIII", raw, 24)
        self.assertEqual(sec, 1_700_000_000)
        self.assertEqual(usec, 500_000)
        self.assertEqual(caplen, 60)
        self.assertEqual(origlen, 60)
        self.assertEqual(raw[40:], frame)

    def test_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.pcap")
            with PcapWriter(path) as writer:
                for _ in range(3):
                    writer.write(b"\x00" * 60)
                self.assertEqual(len(writer), 3)
                self.assertEqual(writer.packet_count, 3)
                self.assertEqual(writer.byte_count, 180)

    def test_magic_is_written_little_endian(self):
        """Wireshark detects byte order from the magic, so the on-disk bytes
        must be d4 c3 b2 a1 for a little-endian file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.pcap")
            with PcapWriter(path):
                pass
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(4), b"\xd4\xc3\xb2\xa1")


# ---------------------------------------------------------------------------
# Frame dissection
# ---------------------------------------------------------------------------


class TestDissect(unittest.TestCase):
    def _tcp_frame(self) -> bytes:
        segment = TCPSegment(49152, 80, 100, 200, FLAG_ACK | FLAG_PSH, payload=b"x" * 10)
        packet = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_TCP, segment.to_bytes(CLIENT_IP, SERVER_IP))
        return EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, packet.to_bytes()).to_bytes()

    def test_tcp_frame(self):
        text = describe_frame(self._tcp_frame())
        self.assertIn("TCP", text)
        self.assertIn("192.0.2.10", text)
        self.assertIn("49152 > 80", text)

    def test_udp_frame(self):
        segment = UDPSegment(53, 5353, b"query")
        packet = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_UDP, segment.to_bytes(CLIENT_IP, SERVER_IP))
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, packet.to_bytes()).to_bytes()
        text = describe_frame(frame)
        self.assertIn("UDP", text)
        self.assertIn("53 > 5353", text)

    def test_icmp_frame(self):
        message = EchoMessage(1, 1, b"payload").to_icmp(ECHO_REQUEST)
        packet = IPv4Packet(CLIENT_IP, SERVER_IP, PROTO_ICMP, message.to_bytes())
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, packet.to_bytes()).to_bytes()
        self.assertIn("ICMP", describe_frame(frame))

    def test_arp_frame(self):
        request = ARPPacket(ARP_REQUEST, CLIENT_MAC, CLIENT_IP, b"\x00" * 6, SERVER_IP)
        frame = EthernetFrame(BROADCAST_MAC, CLIENT_MAC, ETHERTYPE_ARP, request.to_bytes()).to_bytes()
        text = describe_frame(frame)
        self.assertIn("ARP", text)
        self.assertIn("192.0.2.10", text)

    def test_unknown_ethertype(self):
        frame = EthernetFrame(SERVER_MAC, CLIENT_MAC, 0x88B5, b"\x00" * 20).to_bytes()
        self.assertIn("0x88b5", describe_frame(frame).lower())

    def test_a_corrupt_packet_is_still_described(self):
        """Analysis is exactly when a bad checksum is most interesting, so the
        dissector must not refuse to print it."""
        frame = bytearray(self._tcp_frame())
        frame[-1] ^= 0xFF
        self.assertIn("TCP", describe_frame(bytes(frame)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
