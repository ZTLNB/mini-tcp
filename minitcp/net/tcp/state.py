"""The eleven TCP states.

    CLOSED ------+---------------------------> LISTEN
                 |                              |
                 | passive open                 | recv SYN, send SYN+ACK
                 v                              v
            SYN-SENT --------------------> SYN-RECEIVED
                 | recv SYN+ACK                 | recv ACK
                 |                              |
                 +------------------------------+
                                |
                                v
                          ESTABLISHED
                           /          \\
            close(), send FIN          recv FIN, send ACK
                 |                          |
                 v                          v
           FIN-WAIT-1                   CLOSE-WAIT
            /        \\                       | close(), send FIN
   recv ACK      recv FIN                   v
       |              |                  LAST-ACK
       v              v                       | recv ACK
  FIN-WAIT-2      CLOSING                     v
       |              |                    CLOSED
  recv FIN       recv ACK
       |              |
       +------+-------+
              v
         TIME-WAIT ---- 2*MSL elapses ----> CLOSED

Each side closes independently, which is why a graceful shutdown needs four
segments rather than two: one side's FIN only means *it* has nothing more to
send, not that it has stopped listening.
"""

from __future__ import annotations

__all__ = [
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECEIVED",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "ALL_STATES",
    "is_closed",
    "is_synchronised",
]

CLOSED = "CLOSED"
LISTEN = "LISTEN"
SYN_SENT = "SYN-SENT"
SYN_RECEIVED = "SYN-RECEIVED"
ESTABLISHED = "ESTABLISHED"
FIN_WAIT_1 = "FIN-WAIT-1"
FIN_WAIT_2 = "FIN-WAIT-2"
CLOSE_WAIT = "CLOSE-WAIT"
CLOSING = "CLOSING"
LAST_ACK = "LAST-ACK"
TIME_WAIT = "TIME-WAIT"

ALL_STATES = (
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
)

#: States in which a connection is gone and may be reclaimed.
_TERMINAL = frozenset({CLOSED})

#: States in which sequence numbers are meaningful and an RST is not expected
#: to arrive spontaneously.
_SYNCED = frozenset(
    {
        ESTABLISHED,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSE_WAIT,
        CLOSING,
        LAST_ACK,
        TIME_WAIT,
    }
)


def is_closed(state: str) -> bool:
    """True once the connection is fully torn down."""
    return state in _TERMINAL


def is_synchronised(state: str) -> bool:
    """True once both sides have exchanged initial sequence numbers."""
    return state in _SYNCED
