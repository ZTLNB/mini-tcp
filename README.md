# mini-tcp

**English** | [简体中文](README.zh-CN.md)

A TCP/IP stack written from scratch in pure Python — no dependencies, no
`socket` module, no `asyncio`, no C extensions. Ethernet, ARP, IPv4, ICMP, UDP
and TCP are all implemented in this repository, byte by byte, and the result
runs real applications: the examples open HTTP connections, serve echo
requests, and survive 35% packet loss.

The point is not to replace the operating system's stack. The point is that
every layer is visible, testable and explainable — the checksum arithmetic, the
sequence-number wraparound rules, the state machine, the congestion window, the
timers. If you have ever wanted to read TCP rather than take it on faith, this
is that.

```
                    ┌──────────────────────────────────────┐
   your code  ────► │  socket   bind listen accept connect │   BSD-style API
                    │           send recv sendto recvfrom │
                    └───────────────────┬──────────────────┘
                                        │
                    ┌───────────────────▼──────────────────┐
                    │  Stack   demultiplexing, routing,    │   one object per
                    │          ARP cache, reassembly,      │   interface
                    │          background reader + timers  │
                    └───────────────────┬──────────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬──────────────┐
        │               │               │               │              │
   ┌────▼────┐    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐  ┌─────▼─────┐
   │  TCP    │    │    UDP    │   │   ICMP    │   │    ARP    │  │   IPv4    │
   │ conn.   │    │ datagrams │   │   echo    │   │  request  │  │  routing  │
   │ state   │    │           │   │           │   │  /reply   │  │  fragment │
   │ machine │    │           │   │           │   │  + cache  │  │  /reassem │
   └────┬────┘    └─────┬─────┘   └─────┬─────┘   └─────┬─────┘  └─────┬─────┘
        └───────────────┴───────────────┴───────────────┴──────────────┘
                                        │
                    ┌───────────────────▼──────────────────┐
                    │  Ethernet II   framing, padding      │   link layer
                    └───────────────────┬──────────────────┘
                                        │
                    ┌───────────────────▼──────────────────┐
                    │  Link   SimulatedLink │ TunLink      │   pluggable
                    └──────────────────────────────────────┘
```

## What is implemented

**Link layer**

- Ethernet II framing: 14-byte header, minimum 60-byte frame padding on
  transmit, padding deliberately preserved on receive so upper layers trust
  their own length fields rather than the frame size
- Broadcast and multicast detection
- A pluggable `Link` abstraction with two implementations:
  - `SimulatedLink` — an in-process virtual wire that runs anywhere, including
    Windows, and can inject loss, duplication, reordering, corruption and delay
    from a seeded, reproducible profile
  - `TunLink` — a real Linux TAP device via `/dev/net/tun`

**ARP**

- Request/reply, with a cache that learns from *any* ARP traffic rather than
  only replies — the sender of a request has told you where it lives
- Expiring entries with bounded size and eviction of the entry closest to expiry
- Unresolved packets are parked and flushed automatically when the reply lands,
  so a caller never sees a "not yet resolved" failure

**IPv4**

- Header parsing and construction with full validation: version, IHL, header
  checksum, and `total_length` honoured over the buffer (which is what stops an
  Ethernet pad from becoming payload)
- Fragmentation to an arbitrary MTU with 8-byte-aligned offsets and DF/MF flags
- Reassembly from out-of-order, overlapping or interleaved fragments, with a
  timeout and a pending-set cap so a flood of first-fragments-only cannot
  exhaust memory
- Address arithmetic: prefix/mask conversion, subnet comparison

**ICMP**

- Echo request/reply, which makes the stack pingable

**UDP**

- Datagrams with the IPv4 pseudo-header checksum, including the "zero means not
  computed" convention

**TCP**

- The full 11-state machine: `CLOSED`, `LISTEN`, `SYN-SENT`, `SYN-RECEIVED`,
  `ESTABLISHED`, `FIN-WAIT-1/2`, `CLOSE-WAIT`, `CLOSING`, `LAST-ACK`, `TIME-WAIT`
- Three-way handshake, simultaneous open, passive open, four-way close, and
  `TIME-WAIT` with a 2×MSL expiry
- Option parsing and negotiation: MSS, window scale, SACK-permitted, timestamps,
  NOP/EOL padding
- **Wraparound-safe sequence arithmetic** (RFC 1982), with the 2³¹ ambiguity
  reported honestly rather than silently resolved in one direction
- **RTT estimation** (RFC 6298): SRTT/RTTVAR, `RTO = SRTT + 4×RTTVAR`, clamped,
  with exponential backoff
- **Karn's algorithm**: a retransmitted segment never provides an RTT sample,
  because its acknowledgement is ambiguous
- **Reno congestion control**: slow start, congestion avoidance, fast
  retransmit on the third duplicate ACK, fast recovery, timeout collapse
- **Flow control**: advertised window, window scaling, a receive buffer that is
  a hard memory bound no matter what the peer sends
- **Delayed acknowledgement**, **persist timer** for a shut window,
  **retransmission timer** with backoff that recovers when the path does
- Retransmission, duplicate detection, overlap trimming, and out-of-order
  reassembly at the byte-stream level
- Reset handling on both the sending and receiving side

**Around the edges**

- `pcap` writer, so captures open in Wireshark
- A frame dissector that prints tcpdump-style one-line summaries, and prints
  corrupt packets rather than refusing them — analysis is exactly when a bad
  checksum is most interesting

## Quick start

No installation, no dependencies. Python 3.10 or newer.

```bash
git clone https://github.com/ZTLNB/mini-tcp.git
cd mini-tcp
```

### See a whole TCP conversation, packet by packet

```bash
python examples/loopback_demo.py
```

This builds two complete stacks, connects them over a virtual wire, performs an
HTTP exchange, and prints every packet as it crosses. It ends by verifying the
payload arrived intact and dumping the connection statistics.

### Serve and stress a real connection

```bash
python examples/echo_server.py                    # in-process, lossless
python examples/echo_server.py --loss 0.35        # 35% of packets thrown away
python examples/echo_server.py --duplicate 0.1 --reorder 0.05
```

### Use the socket API directly

```python
from minitcp import socket, AF_INET, SOCK_STREAM
from minitcp.link import SimulatedLink, VirtualWire
from minitcp.stack import Stack

wire = VirtualWire()
client_stack = Stack(SimulatedLink(b"\x02\x00\x00\x00\x00\x01", wire), "10.0.0.1", 24)
server_stack = Stack(SimulatedLink(b"\x02\x00\x00\x00\x00\x02", wire), "10.0.0.2", 24)
client_stack.start()
server_stack.start()

server = socket(server_stack, AF_INET, SOCK_STREAM)
server.bind(("0.0.0.0", 8080))
server.listen()

conn = socket(client_stack, AF_INET, SOCK_STREAM)
conn.connect(("10.0.0.2", 8080))
conn.sendall(b"hello")
```

### Over a real interface (Linux only)

`TunLink` needs `CAP_NET_ADMIN`:

```bash
sudo python examples/http_get.py --iface tap0 --host 93.184.216.34 --pcap capture.pcap
```

Then open `capture.pcap` in Wireshark and compare it against what the stack
thinks it did.

## Testing

```bash
python -m unittest discover -s tests -v
```

279 tests, roughly 30 seconds, no third-party test runner — plain `unittest`,
so the "no dependencies" claim holds all the way down.

| File | What it covers |
| --- | --- |
| `tests/test_units.py` | 217 tests over every codec and algorithm, with expected values taken from RFCs and published worked examples rather than from the code |
| `tests/test_loopback.py` | 27 tests driving two real `TCPConnection` objects against each other over a programmable wire, on a clock the test controls — so timing is never a race |
| `tests/test_stack.py` | 10 tests through the socket API and two complete stacks, including a 20 kB transfer over a link dropping 10% of packets |
| `tests/test_fuzz.py` | 25 tests throwing random bytes, every truncated prefix of valid packets, and bit-flipped mutations at all six parsers and at a live connection |

Three things worth calling out:

- **The checksum tests are not self-referential.** They assert RFC 1071's worked
  example (`00 01 f2 03 f4 f5 f6 f7` → `0x220d`) and the canonical IPv4 header
  vector (`0xb861`), then verify that 500 single-bit flips are *all* caught.
- **The loss tests are deterministic.** `FaultProfile` takes a seed, so a
  failure reproduces exactly instead of once every forty runs.
- **The fuzz tests assert an exception *type*, not just "does not crash".** A
  parser may reject bad input with `ValueError` and nothing else, because a
  caller cannot distinguish an unexpected exception from a bug.

## Implementation notes

Things that are easy to get wrong, and how they are handled here.

### Checksums

The Internet checksum is a 16-bit one's complement sum with the carries folded
back in, and the folding has to be a loop rather than a single shift: a sum of
`0xffff` words carries more than once. An odd trailing byte is padded with a
zero byte, not shifted.

TCP and UDP are checksummed over a **pseudo-header** covering the source and
destination addresses, the protocol number and the length. That is what makes a
segment delivered to the wrong host fail its checksum, and it is why the
transport codecs need the IP addresses to serialise at all.

### Sequence numbers are not integers

`0xffffffff` and `0` are adjacent. Every comparison in
`minitcp/net/tcp/seqno.py` is done in modular arithmetic, and the case RFC 1982
declares undefined — two numbers exactly 2³¹ apart, where the distance is the
same in both directions — answers `False` to *all four* of `<`, `<=`, `>`, `>=`
rather than silently picking a direction and being wrong half the time.

### `snd_nxt` must never fall behind `snd_una`

An early version rewound `snd_nxt` when retransmitting, which looks tidy and is
a trap: once the retransmitted segment is acknowledged, `snd_una` moves past
`snd_nxt`, the in-flight count goes negative, and the send path stalls forever
with no error anywhere. `SendQueue.acknowledge` now clamps `snd_nxt` forward,
and the retransmission paths never rewind it.

### A retransmitted segment must not be sampled for RTT

Karn's algorithm. If a segment was sent twice, its acknowledgement might be for
either copy, so the measurement is worthless. The subtlety is what happens
next: suppressing the sample is correct, but leaving the *backoff* in place is
not. After four retransmissions the RTO is 16 seconds, and a connection that is
demonstrably working again would sit idle waiting for it. `RTOEstimator.recompute()`
drops the backoff whenever an ACK moves the window forward.

### A zero window needs a timer, not a probe storm

When the peer's window is shut, the sender must not push new data: those bytes
can be refused outright, consuming sequence numbers and leaving a hole that
only a timeout repairs. It also must not go silent, because if the ACK that
re-opens the window is lost, the sender holds data and the receiver holds room
and neither has any reason to speak — a deadlock with no error in it.

So `_flush` sends nothing while the window is shut and arms a **persist timer**
instead. On expiry it probes from `snd_una`, backing off from 0.5 s to 60 s,
and never giving up. The sender also resends from the head of the outstanding
queue the moment the window re-opens, rather than waiting out the RTO.

### A window update arrives as a duplicate ACK

The ACK that re-opens a shut window acknowledges nothing new — it cannot, since
there was nothing to acknowledge. It is therefore indistinguishable from a
duplicate ACK except for its window field. Discarding it because the ACK number
did not advance is a deadlock; this stack treats the window field as
authoritative on every segment and counts the duplicate ACK for congestion
control at the same time.

### Flow control is only a promise if you enforce it

The advertised window tells the peer how much room exists. A correct peer
respects it. A buggy or hostile one does not, and the receive buffer used to
grow without limit, which is exactly the failure flow control exists to
prevent. `ReceiveQueue._accept` now trims whatever will not fit — the tail was
never acknowledged, so the peer will retransmit it, and the buffer is a hard
bound regardless of what arrives.

### Malformed input is routine, not exceptional

Every parser raises `ValueError` and nothing else, so a caller can tell
"this packet is broken" from "I have a bug". `Stack.handle_frame` catches
exactly that and counts the frame as malformed; anything else propagates,
because a blanket `except Exception` around packet handling will happily hide a
broken implementation behind a plausible-looking packet loss statistic. (It
did, once. The reader thread now records unexpected exceptions separately and
keeps the message.)

## Known limitations

Honest list. These are deliberate scope boundaries, not oversights.

- **No SACK.** SACK-permitted is negotiated and the option is parsed, but
  selective acknowledgement is not acted on: a loss retransmits from `snd_una`
  rather than only the missing range.
- **No timestamps (RFC 7323) RTTM.** The option is parsed; RTT is measured from
  segment send times, which is what a real stack does when timestamps are off.
- **No congestion control beyond Reno.** No CUBIC, no BBR, no ECN handling
  beyond parsing the flags.
- **`TunLink` is Linux-only.** It needs `/dev/net/tun` and `fcntl`. The module
  imports safely on Windows and raises only if you actually try to open a
  device, which is why the whole test suite runs anywhere.
- **IPv4 only.** No IPv6, no IP options, no routing protocols.
- **The simulated link is not a network.** `SimulatedLink` runs in one process
  and hands frames over directly; it reproduces the *behaviour* of a lossy link,
  not its throughput characteristics.

## Layout

```
minitcp/
  util/
    checksum.py      RFC 1071, plus the transport pseudo-header
    byteio.py        big-endian sequential readers and writers
  link/
    base.py          the Link interface
    simulated.py     virtual wire, fault injection
    tun.py           Linux TAP device
  net/
    ethernet.py      Ethernet II framing
    arp.py           ARP packets and cache
    ipv4.py          IPv4 header, fragmentation, reassembly
    icmp.py          echo request/reply
    udp.py           datagrams
    tcp/
      seqno.py       RFC 1982 sequence arithmetic
      segment.py     segment codec and options
      state.py       the 11 states
      buffer.py      send and receive byte streams
      reorder.py     out-of-order holding area
      retransmit.py  RTO estimation, outstanding-segment queue
      congestion.py  Reno
      connection.py  the state machine that ties it together
  stack.py           demultiplexing, routing, timers
  socket.py          BSD-style socket API
  pcap.py            capture file writer
  dissect.py         tcpdump-style frame summaries
```

## License

MIT. See [LICENSE](LICENSE).
