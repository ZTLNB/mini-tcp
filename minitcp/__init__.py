"""minitcp -- a user-space TCP/IP stack written from scratch in pure Python.

The package is layered so that each piece can be read and tested on its own::

    minitcp.link    Ethernet frames in and out; a simulated wire or a TUN device
    minitcp.net     Ethernet, ARP, IPv4, ICMP, UDP and TCP
    minitcp.stack   Protocol demultiplexing, routing and the background reader
    minitcp.socket  A BSD-style socket API on top of the stack

Nothing outside the standard library is imported, anywhere.

The names re-exported here are the ones needed to get a connection running:
a :class:`~minitcp.stack.Stack`, a link to attach it to, and the socket API.
Everything else stays in its submodule, where it is easier to find.
"""

from .link import FaultProfile, Link, LinkError, SimulatedLink, VirtualWire
from .net.ipv4 import ip_to_bytes, ip_to_str
from .socket import (
    AF_INET,
    SHUT_RD,
    SHUT_RDWR,
    SHUT_WR,
    SOCK_DGRAM,
    SOCK_STREAM,
    create_connection,
)
from .socket import socket as socket
from .stack import Stack, StackError

__version__ = "0.1.0"

__all__ = [
    "AF_INET",
    "FaultProfile",
    "Link",
    "LinkError",
    "SHUT_RD",
    "SHUT_RDWR",
    "SHUT_WR",
    "SOCK_DGRAM",
    "SOCK_STREAM",
    "SimulatedLink",
    "Stack",
    "StackError",
    "VirtualWire",
    "__version__",
    "create_connection",
    "ip_to_bytes",
    "ip_to_str",
    "socket",
]
