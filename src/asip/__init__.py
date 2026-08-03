"""ASIP - AI Social Intelligence Platform.

One question, answered with evidence: is this activity organic or
coordinated? See docs/PRODUCT.md.

Code layers L0-L4, innermost first. Imports run inward only, and the
direction is enforced by .importlinter rather than by convention:

    L0  contracts/               types, enums, Protocols, event schemas
    L1  modules/<m>/domain/      pure computation
    L2  modules/<m>/application/ orchestration, transactions, ports
    L3  modules/<m>/adapters/    Postgres, object store, browsers, HTTP
    L4  entrypoints/             routes, workers, CLI, composition root

Note that code layers L0-L4 and authority layers A1-A5 are unrelated
concepts that share a word. CLAUDE.md §0 disambiguates them.
"""
