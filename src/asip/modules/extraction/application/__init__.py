"""L2 - extraction application. Orchestration and transaction boundaries.

Coordinates ports and owns the transaction. Depends only on the
Protocols in asip.contracts.ports, never on a concrete adapter
(D-98) - adapters are wired in entrypoints/composition.py.
"""
