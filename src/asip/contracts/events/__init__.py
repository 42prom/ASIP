"""Versioned inter-module event schemas (D-94).

One module per event version - <name>.v<n>.py - with a matching JSON
Schema fixture. Events are how a module changes another module's state,
because a cross-schema write is prohibited (D-93).

Compatibility (D-95): within a version, fields may be added optional.
Never removed, never retyped, never made required. Anything else is a
new version.

Migration (D-96): when a version is introduced, producers emit both and
consumers migrate. The old version retires only once every consumer is
confirmed migrated. There is no flag day.

Every event carries event_id (idempotency), occurred_at, trace_id and
tenant_id. Consumers keep a fixture of the shape they depend on in
tests/contracts/<producer>/, and the producer's own suite validates its
output against every one of them (D-97).
"""
