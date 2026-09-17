#!/usr/bin/env python3
"""Fetch a URL using minitcp's own TCP stack.

This is the "real network" mode: the stack is bound to a Linux TAP interface,
so the HTTP request leaves through the kernel's driver and the reply comes back
the same way.  It is the closest thing to proving the stack works against the
outside world.

Setup::

    sudo ip tuntap add dev tap0 mode tap user $USER
    sudo ip link set tap0 up
    sudo ip addr add 10.0.0.1/24 dev tap0

Run::

    sudo python examples/http_get.py --tap tap0 --ip 10.0.0.1 --url http://10.0.0.2:8080/

Name resolution is deliberately out of scope: give the address directly.  A DNS
client would be a reasonable next step, and the UDP layer it needs is already
here.
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitcp.socket import AF_INET, SOCK_STREAM, socket  # noqa: E402
from minitcp.stack import Stack  # noqa: E402


def build_request(host: str, port: int, path: str, user_agent: str) -> bytes:
    return (
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n" % (path, host, port, user_agent)
    ).encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch a URL with minitcp")
    parser.add_argument("--tap", metavar="DEVICE", help="TAP device to bind to")
    parser.add_argument("--ip", help="address to claim on that device")
    parser.add_argument("--netmask", default="24")
    parser.add_argument("--gateway", default=None)
    parser.add_argument("--url", required=True, help="e.g. http://10.0.0.2:8080/")
    parser.add_argument("--user-agent", default="minitcp/0.1")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="also write every frame to a capture file for Wireshark",
    )
    args = parser.parse_args()

    if not args.tap or not args.ip:
        print("this example needs --tap DEVICE and --ip ADDRESS", file=sys.stderr)
        print("see the module docstring for the setup commands", file=sys.stderr)
        return 2

    try:
        from minitcp.link.tun import TunLink, TUN_AVAILABLE
    except ImportError as exc:
        print("cannot import the TAP backend: %s" % exc, file=sys.stderr)
        return 2

    if not TUN_AVAILABLE():
        print(
            "no TAP device available. This needs Linux and root, or WSL2.\n"
            "On Windows or macOS run examples/loopback_demo.py instead.",
            file=sys.stderr,
        )
        return 2

    parsed = urlparse(args.url)
    if parsed.scheme != "http":
        print("only http:// URLs are supported, got %r" % parsed.scheme, file=sys.stderr)
        return 2

    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    capture = None
    if args.pcap:
        from minitcp.pcap import PcapWriter

        capture = PcapWriter(args.pcap)

    link = TunLink(args.tap)
    stack = Stack(link, args.ip, args.netmask, args.gateway)

    # Tap the link so the capture file sees exactly what crosses the wire.
    if capture is not None:
        original_send = link.send_frame

        def recording_send(frame: bytes) -> None:
            capture.write(frame)
            original_send(frame)

        link.send_frame = recording_send

    stack.start()
    print("minitcp: %s/%s via %s" % (args.ip, args.netmask, args.tap))
    print("GET %s" % args.url)

    try:
        client = socket(stack, AF_INET, SOCK_STREAM)
        client.settimeout(args.timeout)
        client.connect((host, port))
        print("connected to %s:%d" % (host, port))

        client.sendall(build_request(host, port, path, args.user_agent))
        response = client.recv_all()
        client.close()

        print()
        print("--- response (%d bytes) ---" % len(response))
        sys.stdout.write(response.decode("utf-8", errors="replace"))
        if response and not response.endswith(b"\n"):
            print()
        print("--- end ---")

        if capture is not None:
            capture.close()
            print("capture written to %s (%d packets)" % (args.pcap, len(capture)))

        return 0 if response else 1
    except Exception as exc:
        print("request failed: %r" % (exc,), file=sys.stderr)
        return 1
    finally:
        stack.stop()
        if capture is not None:
            capture.close()


if __name__ == "__main__":
    raise SystemExit(main())
