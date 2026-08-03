"""Clock port.

D-100 — three clocks exist and only one is authoritative for detection. Making
the clock a port rather than a call to ``datetime.now()`` keeps that
distinction explicit: code states which clock it is reading, and L1 domain
never reads one at all.

This is also what makes the evidence path testable. A use case that calls
``datetime.now()`` internally cannot be tested for its behaviour at a specific
instant without patching the standard library.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """The collector's wall clock. Never the authority for detection timing.

    For evidence specifically, this records *when we observed something*. It is
    not proof of when anything happened — that is the RFC 3161 token's job
    (D-22), and no amount of local clock precision substitutes for it.
    """

    def now(self) -> datetime:
        """Current time, timezone-aware and UTC."""
        ...
