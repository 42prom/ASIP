"""Reading stored captures back (D-13).

Reprocessing is the reason this port exists. A capture is fetched **once** and
may be parsed many times: bump the extractor, re-run it over what is already
stored, and no source is contacted again. That is not an optimisation — D-13
calls refetching instead of reprocessing an error that costs real money, and
the walking skeleton exists partly to prove the path works.

WHY A PORT AND NOT A CROSS-SCHEMA READ
--------------------------------------
Extraction needs the bytes; evidence owns them. The tempting shortcut is to
publish ``object_prefix`` in a read view and let extraction fetch from the
object store itself. That would make extraction depend on evidence's storage
layout — where bundles live, what they are called, how they are packed — and a
change to any of it would break a module that has no business knowing.

So extraction asks for *a capture's bytes* and receives them. Evidence keeps
its layout private, the object store stays reachable from one module only, and
either side can be replaced without the other noticing (D-99).
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID


class CaptureBytes(Protocol):
    """Retrieve the raw bytes of a stored capture."""

    def read_capture(self, tenant_id: UUID, capture_id: UUID) -> bytes | None:
        """The captured document, or None if it cannot be produced.

        None rather than an exception: a capture whose bytes have been expired
        by retention (D-54) is an ordinary condition during a reprocess of old
        material, and the caller reports it as a skipped item rather than
        aborting a batch of thousands.
        """
        ...
