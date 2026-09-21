#!/usr/bin/env python3
"""A TCP echo server on top of minitcp.

Two ways to run it.

Simulated, which works anywhere and needs no privileges::

    python examples/echo_server.py

Real, which binds to a Linux TAP interface so ordinary tools can connect::

    sudo ip tuntap add dev tap0 mode tap user $USER
    sudo ip link set tap0 up
    sudo ip addr add 10.0.0.2/24 dev tap0
    sudo python examples/echo_server.py --tap tap0 --ip 10.0.0.2

    # then, from another terminal:
    nc 10.0.0.2 7

The simulated mode is the more useful one day to day: it runs the same
protocol code, and it can be told to lose packets so you can watch TCP recover.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitcp.dissect import describe_frame  # noqa: E402
from minitcp.link import FaultProfile, SimulatedLink, VirtualWire  # noqa: E402
from minitcp.socket import AF_INET, SOCK_STREAM, socket  # noqa: E402
from minitcp.stack import Stack  # noqa: E402

PORT = 7  # the traditional echo port


def handle_connection(connection, address) -> None:
    """Echo everything back until the peer stops talking."""
    connection.settimeout(10.0)
    total = 0
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            total += len(data)
            connection.sendall(data)
    except TimeoutError:
        pass
    finally:
        print("  server: connection from %s:%d closed after %d bytes"
              % (address[0], address[1], total))
        connection.close()


def serve(stack: Stack, count: int) -> None:
    """Accept *count* connections, each handled on its own thread."""
    listener = socket(stack, AF_INET, SOCK_STREAM)
    listener.bind(("0.0.0.0", PORT))
    listener.listen()
    listener.settimeout(15.0)

    for _ in range(count):
        try:
            connection, address = listener.accept()
        except TimeoutError:
            break
        print("  server: accepted connection from %s:%d" % address)
        threading.Thread(
            target=handle_connection, args=(connection, address), daemon=True
        ).start()

    listener.close()


def run_simulated(loss: float) -> int:
    print("simulated mode: two stacks joined by a virtual wire")
    if loss:
        print("packet loss: %.0f%% (watch TCP retransmit)" % (loss * 100))

    wire = VirtualWire(
        FaultProfile(loss=loss, seed=7) if loss else None,
        on_frame=lambda sender, frame: print("    %-7s %s" % (sender.name, describe_frame(frame))),
    )
    link_a = SimulatedLink(bytes([0x02, 0, 0, 0, 0, 0x01]), wire, name="client")
    link_b = SimulatedLink(bytes([0x02, 0, 0, 0, 0, 0x02]), wire, name="server")

    client_stack = Stack(link_a, "10.0.0.1", 24).start()
    server_stack = Stack(link_b, "10.0.0.2", 24).start()

    messages = [
        b"hello echo server",
        b"a slightly longer message, to exercise segmentation" * 8,
        bytes(range(256)) * 4,
    ]

    try:
        server_thread = threading.Thread(
            target=serve, args=(server_stack, len(messages)), daemon=True
        )
        server_thread.start()

        ok = True
        for index, message in enumerate(messages):
            client = socket(client_stack, AF_INET, SOCK_STREAM)
            client.settimeout(15.0)
            client.connect(("10.0.0.2", PORT))
            client.sendall(message)
            client.shutdown()
            echoed = client.recv_all()
            client.close()

            match = echoed == message
            ok = ok and match
            print("  message %d: sent %d bytes, echoed %d bytes -- %s"
                  % (index + 1, len(message), len(echoed),
                     "match" if match else "MISMATCH"))

        server_thread.join(timeout=10.0)
        print()
        print("  wire: %s" % wire.stats())
        return 0 if ok else 1
    finally:
        client_stack.stop()
        server_stack.stop()


def run_real(device: str, ip: str, netmask: str) -> int:
    try:
        from minitcp.link.tun import TUN_AVAILABLE, TunLink
    except ImportError as exc:
        print("cannot import the TAP backend: %s" % exc, file=sys.stderr)
        return 2

    if not TUN_AVAILABLE():
        print(
            "no TAP device available. This mode needs Linux and root, or WSL2.\n"
            "On Windows or macOS use the simulated mode instead.",
            file=sys.stderr,
        )
        return 2

    link = TunLink(device)
    stack = Stack(link, ip, netmask).start()
    print("listening on %s:%d via %s (mac %s)" % (ip, PORT, device, link.mac.hex(":")))
    print("try:  nc %s %d" % (ip, PORT))
    print("press Ctrl-C to stop")

    try:
        serve(stack, count=1_000_000)
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        stack.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tap", metavar="DEVICE", help="use a real TAP device")
    parser.add_argument("--ip", default="10.0.0.2", help="address to claim")
    parser.add_argument("--netmask", default="24", help="prefix length")
    parser.add_argument(
        "--loss",
        type=float,
        default=0.0,
        help="simulated packet loss, 0.0 to 1.0",
    )
    args = parser.parse_args()

    if args.tap:
        return run_real(args.tap, args.ip, args.netmask)
    return run_simulated(args.loss)


if __name__ == "__main__":
    raise SystemExit(main())
