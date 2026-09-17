"""A TAP device on Linux, giving the stack a real Ethernet interface.

Everything else in this project runs anywhere.  This module does not: it needs
``/dev/net/tun`` and the ``fcntl`` module, both of which are Linux-only.  The
imports are therefore deferred so that simply importing :mod:`minitcp` never
fails on Windows or macOS.

A *TAP* device is the right choice over a *TUN* device here.  A TUN device
exchanges bare IP packets and has no link layer, which would leave the Ethernet
code unused.  A TAP device exchanges full Ethernet frames, so the stack sees
exactly the same thing it sees on a simulated wire.

Bringing the interface up still needs privileges, and is not done for you::

    sudo ip tuntap add dev tap0 mode tap user $USER
    sudo ip link set tap0 up
    sudo ip addr add 10.0.0.1/24 dev tap0

After that, ordinary tools can talk to the stack::

    ping 10.0.0.2
    curl http://10.0.0.2:8080/

``IFF_NO_PI`` suppresses the 4-byte packet-info prefix the kernel would
otherwise prepend, so reads return exactly the frame and nothing else.
"""

from __future__ import annotations

import os
import select
import struct
import threading

from .base import Link, LinkError

__all__ = ["TunLink", "TUN_AVAILABLE"]

#: ioctl request and flags from <linux/if_tun.h>.
TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
IFNAMSIZ = 16

DEFAULT_DEVICE = "/dev/net/tun"


def _load_platform_modules():
    """Import the Linux-only modules, or explain why we cannot."""
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - depends on platform
        raise LinkError(
            "TAP devices need the fcntl module, which only exists on Linux. "
            "Use SimulatedLink instead, or run inside WSL2."
        ) from exc
    return fcntl


def TUN_AVAILABLE() -> bool:  # noqa: N802 - reads as a constant at call sites
    """Whether this interpreter could open a TAP device at all."""
    if not os.path.exists(DEFAULT_DEVICE):
        return False
    try:
        _load_platform_modules()
    except LinkError:
        return False
    return True


class TunLink(Link):
    """An Ethernet interface backed by a Linux TAP device."""

    def __init__(
        self,
        name: str = "tap0",
        mtu: int = 1500,
        device: str = DEFAULT_DEVICE,
    ) -> None:
        fcntl = _load_platform_modules()

        if len(name) >= IFNAMSIZ:
            raise LinkError("interface name %r is too long" % name)

        self.name = name
        self.mtu = mtu
        self._device = device
        self._lock = threading.Lock()

        try:
            self._fd = os.open(device, os.O_RDWR)
        except OSError as exc:
            raise LinkError(
                "cannot open %s (%s). Creating a TAP device needs CAP_NET_ADMIN."
                % (device, exc.strerror)
            ) from exc

        try:
            # struct ifreq { char name[16]; short flags; ... }
            request = struct.pack("16sH", name.encode("utf-8"), IFF_TAP | IFF_NO_PI)
            fcntl.ioctl(self._fd, TUNSETIFF, request)
        except OSError as exc:
            os.close(self._fd)
            raise LinkError(
                "cannot attach to %s (%s). Does the interface exist?"
                % (name, exc.strerror)
            ) from exc

        # The kernel reports the interface's own MAC address once it is up.
        self._mac = self._read_hardware_address(name) or bytes([0x02, 0, 0, 0, 0, 1])

    @property
    def mac(self) -> bytes:
        return self._mac

    @property
    def fileno(self) -> int:
        return self._fd

    def send_frame(self, frame: bytes) -> None:
        with self._lock:
            try:
                os.write(self._fd, frame)
            except OSError as exc:
                raise LinkError("write to %s failed: %s" % (self.name, exc)) from exc

    def recv_frame(self, timeout: float | None = None) -> bytes | None:
        with self._lock:
            fd = self._fd
        if fd < 0:
            return None

        if timeout is None:
            try:
                return os.read(fd, self.mtu + 18)
            except OSError:
                return None

        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            return None
        try:
            return os.read(fd, self.mtu + 18)
        except OSError:
            return None

    def close(self) -> None:
        with self._lock:
            fd, self._fd = getattr(self, "_fd", -1), -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    @staticmethod
    def _read_hardware_address(name: str) -> bytes | None:
        """Read ``/sys/class/net/<name>/address`` if the kernel exposes it."""
        path = "/sys/class/net/%s/address" % name
        try:
            with open(path, "r") as handle:
                text = handle.read().strip()
        except OSError:
            return None
        try:
            return bytes(int(part, 16) for part in text.split(":"))
        except ValueError:
            return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<TunLink %s mac=%s>" % (self.name, self._mac.hex(":"))
