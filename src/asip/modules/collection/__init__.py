"""collection module - owns sch_collection (D-91).

Tables: fetch_jobs, budgets, source_health

This file is the module's published interface (L-05). Other modules
import what they need from here and never reach into domain/,
application/ or adapters/.

V-3: the Fetch zone holds no database credentials and cannot reach
the core database. It takes jobs from a queue and writes bundles to
object storage (D-11).

V-6: reliability work stops at retries, backoff, session reuse and
honest rate limiting.
"""
