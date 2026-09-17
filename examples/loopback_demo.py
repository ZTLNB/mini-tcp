#!/usr/bin/env python3
"""A complete TCP conversation between two stacks, with every packet visible.

Running this shows ARP resolution, the three-way handshake, an HTTP request and
response, and the four-way close -- all produced by this project's own code,
with no kernel networking involved and no privileges required.

    python examples/loopback_demo.py

Two independent stacks are created in one process and joined by a virtual wire.
Every frame that crosses the wire is summarised, so the protocol is visible
rather than implied.
"""

from __future__ import annotations

import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitcp.dissect import describe_frame  # noqa: E402
from minitcp.link import SimulatedLink, VirtualWire  # noqa: E402
from minitcp.socket import AF_INET, SOCK_STREAM, socket  # noqa: E402
from minitcp.stack import Stack  # noqa: E402

CLIENT_MAC = bytes([0x02, 0, 0, 0, 0, 0x01])
SERVER_MAC = bytes([0x02, 0, 0, 0, 0, 0x02])
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
PORT = 8080

BODY = b"<html><body><h1>Hello from minitcp</h1></body></html>\n"


def banner(text: str) -> None:
    print()
    print("=" * 74)
    print(text)
    print("=" * 74)


def serve_one_request(server_stack: Stack, ready: threading.Event) -> None:
    """Answer exactly one HTTP request, then stop."""
    listener = socket(server_stack, AF_INET, SOCK_STREAM)
    listener.bind(("0.0.0.0", PORT))
    listener.listen()
    listener.settimeout(15.0)
    ready.set()

    connection, address = listener.accept()
    request = connection.recv_all()

    banner("the server received this request")
    for line in request.decode(errors="replace").splitlines():
        print("  | " + line)

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + BODY
    )
    connection.sendall(response)
    connection.close()
    listener.close()


def main() -> int:
    banner("minitcp loopback demo")

    packets: list[str] = []

    def on_frame(sender: SimulatedLink, frame: bytes) -> None:
        line = describe_frame(frame)
        packets.append(line)
        print("  %-7s %s" % (sender.name, line))

    wire = VirtualWire(on_frame=on_frame)
    link_client = SimulatedLink(CLIENT_MAC, wire, name="client")
    link_server = SimulatedLink(SERVER_MAC, wire, name="server")

    client_stack = Stack(link_client, CLIENT_IP, 24)
    server_stack = Stack(link_server, SERVER_IP, 24)

    client_stack.start()
    server_stack.start()

    try:
        ready = threading.Event()
        thread = threading.Thread(
            target=serve_one_request, args=(server_stack, ready), daemon=True
        )
        thread.start()
        ready.wait(5.0)

        banner("the client sends a request")
        client = socket(client_stack, AF_INET, SOCK_STREAM)
        client.settimeout(15.0)
        client.connect((SERVER_IP, PORT))

        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: 10.0.0.2\r\n"
            b"User-Agent: minitcp/0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        client.sendall(request)
        # Half-close: the request is complete, but we still expect a reply.
        # Without this the server cannot tell where the request ends.
        client.shutdown()
        response = client.recv_all()

        # Grab the numbers before close() releases the connection.
        connection = client.connection
        stats = (
            connection.segments_sent,
            connection.segments_received,
            connection.bytes_sent,
            connection.retransmissions,
        )
        client.close()
        thread.join(timeout=5.0)

        banner("the client received this response")
        for line in response.decode(errors="replace").splitlines():
            print("  | " + line)

        banner("what happened on the wire")
        print("  packets exchanged: %d" % len(packets))
        print("  client stack:      %s" % client_stack)
        print("  server stack:      %s" % server_stack)
        print("  client ARP cache:  %d entries" % len(client_stack.arp_cache))
        print()
        print("  client connection statistics")
        print("    segments sent      %d" % stats[0])
        print("    segments received  %d" % stats[1])
        print("    bytes sent         %d" % stats[2])
        print("    retransmissions    %d" % stats[3])
        print()
        print("  payload integrity: %s" % ("OK" if BODY in response else "FAILED"))
        return 0 if BODY in response else 1
    finally:
        client_stack.stop()
        server_stack.stop()


if __name__ == "__main__":
    raise SystemExit(main())
