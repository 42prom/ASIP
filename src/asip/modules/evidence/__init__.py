"""evidence module - owns sch_evidence (D-91).

Tables: captures, evidence_bundles, hash_chain

This file is the module's published interface (L-05). Other modules
import what they need from here and never reach into domain/,
application/ or adapters/.

V-5: no grouping, incident or sighting exists without at least one
evidence_bundle reference. Enforced by CHECK constraint.
"""
