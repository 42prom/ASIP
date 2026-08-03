"""detection module - owns sch_detection (D-91).

Tables: rules, findings, clusters

This file is the module's published interface (L-05). Other modules
import what they need from here and never reach into domain/,
application/ or adapters/.

V-2: the authenticity scoring path must not read text content or
stance. That isolation is a module boundary, not a convention -
check_authenticity_isolation.py enforces it on every edit.

V-1: no structure here may carry a verdict, score or label attached
to a named natural person. The unit of analysis is a cluster.

V-4: a rule with measured_precision IS NULL cannot be enabled, and
that is a database CHECK constraint rather than application logic.
"""
