"""Link layer backends.

``SimulatedLink`` is the default and runs anywhere.  ``TunLink`` requires Linux
and is imported lazily so that merely importing this package never fails on
Windows.
"""

from .base import Link, LinkError
from .simulated import FaultProfile, SimulatedLink, VirtualWire

__all__ = [
    "Link",
    "LinkError",
    "FaultProfile",
    "SimulatedLink",
    "VirtualWire",
]
