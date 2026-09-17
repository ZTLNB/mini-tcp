"""An in-process virtual wire with deterministic fault injection.

The interesting failures in a network stack are not the ones that happen on a
clean link.  They are the ones that happen when a segment is lost, arrives out
of order, shows up twice, or has a bit flipped by a bad cable.  Reproducing
those against real hardware is painful and non-deterministic.

So the test wire is programmable.  Give it a :class:`FaultProfile` and a seed,
and it will misbehave in exactly the same way on every run.  That turns "TCP
seems flaky under load" into a reproducible test case.

Timing note: delayed frames are held in a pending queue rather than handed to a
timer thread.  :meth:`VirtualWire.pump` flushes whatever is due, and
:meth:`SimulatedLink.recv_frame` calls it while it waits.  No extra threads, no
sleep loops, and shutdown stays trivial.
"""

from __future__ import annotations

import queue
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .base import Link, LinkError

__all__ = ["FaultProfile", "VirtualWire", "SimulatedLink"]


@dataclass
class FaultProfile:
    """Probability knobs describing how badly a wire misbehaves.

    Every probability is in ``[0, 1]``.  ``delay_ms`` is an inclusive range in
    milliseconds; ``reorder`` adds a small extra delay on top of it, which is
    what makes a later frame overtake an earlier one.
    """

    loss: float = 0.0
    duplicate: float = 0.0
    reorder: float = 0.0
    corrupt: float = 0.0
    delay_ms: tuple[float, float] = (0.0, 0.0)
    seed: int | None = None

    def __post_init__(self) -> None:
        for name in ("loss", "duplicate", "reorder", "corrupt"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError("%s must be between 0 and 1, got %r" % (name, value))
        low, high = self.delay_ms
        if low < 0 or high < low:
            raise ValueError("delay_ms must be an ascending non-negative range")


class VirtualWire:
    """A shared medium connecting several simulated endpoints.

    Frames sent by one endpoint are delivered to every *other* attached
    endpoint, which is how a hub works.  Endpoints with ``is_up`` set to
    ``False`` neither send nor receive, which is how a partition is simulated.
    """

    def __init__(
        self,
        fault: FaultProfile | None = None,
        on_frame: Callable[[SimulatedLink, bytes], None] | None = None,
    ) -> None:
        self.fault = fault or FaultProfile()
        self.on_frame = on_frame
        self._rng = random.Random(self.fault.seed)
        self._links: list[SimulatedLink] = []
        self._pending: list[tuple[float, SimulatedLink, bytes]] = []
        self._lock = threading.Lock()

        self.transmitted = 0
        self.dropped = 0
        self.duplicated = 0
        self.corrupted = 0

    # -- membership ------------------------------------------------------

    def attach(self, link: "SimulatedLink") -> "SimulatedLink":
        """Connect *link* to this wire and return it for chaining."""
        link._wire = self
        with self._lock:
            self._links.append(link)
        return link

    def detach(self, link: "SimulatedLink") -> None:
        with self._lock:
            if link in self._links:
                self._links.remove(link)

    @property
    def endpoints(self) -> list["SimulatedLink"]:
        with self._lock:
            return list(self._links)

    # -- data path -------------------------------------------------------

    def transmit(self, sender: "SimulatedLink", frame: bytes) -> None:
        """Carry *frame* from *sender* to every other live endpoint."""
        if self.on_frame is not None:
            self.on_frame(sender, frame)

        with self._lock:
            self.transmitted += 1
            peers = [l for l in self._links if l is not sender and l.is_up]

        if not peers:
            return

        fault = self.fault

        if fault.loss and self._rng.random() < fault.loss:
            with self._lock:
                self.dropped += 1
            return

        if fault.corrupt and self._rng.random() < fault.corrupt:
            frame = self._flip_one_bit(frame)
            with self._lock:
                self.corrupted += 1

        delay = 0.0
        low, high = fault.delay_ms
        if high > 0:
            delay = self._rng.uniform(low, high) / 1000.0
        if fault.reorder and self._rng.random() < fault.reorder:
            # Push this frame behind whatever arrives in the next 2 ms.
            delay += 0.002

        copies = 1
        if fault.duplicate and self._rng.random() < fault.duplicate:
            copies = 2
            with self._lock:
                self.duplicated += 1

        for _ in range(copies):
            for peer in peers:
                if delay <= 0.0:
                    peer._enqueue(frame)
                else:
                    with self._lock:
                        self._pending.append((time.monotonic() + delay, peer, frame))

    def pump(self) -> None:
        """Deliver every frame whose scheduled arrival time has passed."""
        with self._lock:
            if not self._pending:
                return
            now = time.monotonic()
            due = [item for item in self._pending if item[0] <= now]
            if due:
                self._pending = [item for item in self._pending if item[0] > now]
        for _, peer, frame in due:
            peer._enqueue(frame)

    # -- helpers ---------------------------------------------------------

    def _flip_one_bit(self, frame: bytes) -> bytes:
        if not frame:
            return frame
        buf = bytearray(frame)
        index = self._rng.randrange(len(buf))
        buf[index] ^= 1 << self._rng.randrange(8)
        return bytes(buf)

    def stats(self) -> dict[str, int]:
        """Snapshot of what the wire has done so far."""
        with self._lock:
            return {
                "transmitted": self.transmitted,
                "dropped": self.dropped,
                "duplicated": self.duplicated,
                "corrupted": self.corrupted,
                "in_flight": len(self._pending),
            }

    def reset_stats(self) -> None:
        with self._lock:
            self.transmitted = 0
            self.dropped = 0
            self.duplicated = 0
            self.corrupted = 0


class SimulatedLink(Link):
    """One endpoint on a :class:`VirtualWire`."""

    def __init__(
        self,
        mac: bytes,
        wire: VirtualWire | None = None,
        mtu: int = 1500,
        name: str = "",
    ) -> None:
        if len(mac) != 6:
            raise ValueError("a MAC address is 6 bytes, got %d" % len(mac))
        self._mac = bytes(mac)
        self._wire = wire
        self.mtu = mtu
        self.name = name or self._mac.hex(":")
        self.is_up = True
        self._queue: queue.Queue[bytes] = queue.Queue()
        if wire is not None:
            wire.attach(self)

    @property
    def mac(self) -> bytes:
        return self._mac

    @property
    def wire(self) -> VirtualWire | None:
        return self._wire

    def send_frame(self, frame: bytes) -> None:
        if self._wire is None:
            raise LinkError("link %s is not attached to a wire" % self.name)
        if not self.is_up:
            raise LinkError("link %s is down" % self.name)
        self._wire.transmit(self, frame)

    def recv_frame(self, timeout: float | None = None) -> bytes | None:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self._wire is not None:
                self._wire.pump()

            wait = 0.001
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    try:
                        return self._queue.get_nowait()
                    except queue.Empty:
                        return None
                wait = min(wait, left)

            try:
                return self._queue.get(timeout=wait)
            except queue.Empty:
                continue

    def _enqueue(self, frame: bytes) -> None:
        self._queue.put(frame)

    def pending(self) -> int:
        """Number of frames received but not yet consumed."""
        return self._queue.qsize()

    def drain(self) -> list[bytes]:
        """Remove and return every queued frame."""
        out = []
        while True:
            try:
                out.append(self._queue.get_nowait())
            except queue.Empty:
                return out

    def close(self) -> None:
        self.is_up = False
        if self._wire is not None:
            self._wire.detach(self)
