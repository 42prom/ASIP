"""The composition root (D-98).

This is the only module in the codebase permitted to import a concrete
adapter. Every other module depends on the port Protocols in
``asip.contracts.ports``; import-linter's composition-root contract forbids
any ``application/`` package from importing an ``adapters/`` package, and
this file is the single documented exception.

Keeping construction in one place is what makes an adapter swappable. A
module that reaches for ``PostgresContentRepo`` directly is bound to
Postgres regardless of what its type hints claim.
"""

from __future__ import annotations

from typing import NoReturn


def build_container() -> NoReturn:
    """Construct the adapter graph for a runtime profile.

    Unimplemented: no adapters exist yet. The first ones - the evidence
    store, the content repository and the fetch queue - are wired in Phase 1,
    which builds one vertical slice end to end (docs/WALKING_SKELETON.md).

    The return type is ``NoReturn`` only while this raises. It becomes the
    container type once there is a container to return.
    """
    raise NotImplementedError(
        "No adapters exist yet. The composition root is wired in Phase 1; "
        "see docs/WALKING_SKELETON.md."
    )
