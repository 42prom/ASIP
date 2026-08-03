"""L3 - extraction adapters. The only layer where I/O happens.

Postgres, object store, browsers, Temporal, HTTP. Writes only to
sch_extraction (D-91). Reads another module's state only through that
module's published v_* view (D-92), never from its tables. A write
to another schema is prohibited without exception - emit an event
instead (D-93).
"""
