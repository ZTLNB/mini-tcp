"""Wraparound-safe arithmetic on 32-bit TCP sequence numbers.

Sequence numbers are 32-bit and they *do* wrap.  A long-lived connection at
1 Gbit/s consumes the whole space in about 34 seconds, so this is not a
theoretical concern.  Plain integer comparison is therefore wrong: after the
wrap, 0x00000010 is *after* 0xFFFFFFF0, not before it.

RFC 1982 defines the fix.  Comparing a and b, take ``(a - b) mod 2**32``.
If the result is less than ``2**31`` then a is ahead of b; if it is greater
than ``2**31`` then a is behind.  Exactly ``2**31`` is ambiguous and must be
rejected rather than guessed at.

This module is small but it is load-bearing: every window calculation, every
retransmission decision and every "is this ACK new?" check depends on it being
right.
"""

from __future__ import annotations

__all__ = [
    "SEQ_MASK",
    "SEQ_HALF",
    "seq_add",
    "seq_lt",
    "seq_le",
    "seq_gt",
    "seq_ge",
    "seq_between",
    "seq_diff",
    "seq_min",
    "seq_max",
]

SEQ_MASK = 0xFFFFFFFF
SEQ_HALF = 0x80000000


def seq_add(seq: int, offset: int) -> int:
    """Advance *seq* by *offset*, wrapping at 2**32."""
    return (seq + offset) & SEQ_MASK


def seq_diff(a: int, b: int) -> int:
    """Signed distance from *b* to *a*, in ``[-2**31, 2**31)``.

    A positive result means *a* is ahead of *b*.
    """
    diff = (a - b) & SEQ_MASK
    return diff - 0x100000000 if diff >= SEQ_HALF else diff


def seq_lt(a: int, b: int) -> bool:
    """True if *a* precedes *b*."""
    return 0 < ((b - a) & SEQ_MASK) < SEQ_HALF


def seq_le(a: int, b: int) -> bool:
    """True if *a* precedes or equals *b*."""
    return a == b or seq_lt(a, b)


def seq_gt(a: int, b: int) -> bool:
    """True if *a* follows *b*."""
    return seq_lt(b, a)


def seq_ge(a: int, b: int) -> bool:
    """True if *a* follows or equals *b*."""
    return a == b or seq_lt(b, a)


def seq_between(seq: int, low: int, high: int) -> bool:
    """True if ``low <= seq < high`` in sequence space.

    This is the test for "does this sequence number fall inside the receive
    window", so the half-open interval matters.
    """
    return seq_ge(seq, low) and seq_lt(seq, high)


def seq_min(a: int, b: int) -> int:
    """The earlier of two sequence numbers."""
    return a if seq_le(a, b) else b


def seq_max(a: int, b: int) -> int:
    """The later of two sequence numbers."""
    return a if seq_ge(a, b) else b
