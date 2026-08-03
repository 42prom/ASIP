"""identity module - owns sch_identity (D-91).

Tables: tenants, users, roles, audit

This file is the module's published interface (L-05). Other modules
import what they need from here and never reach into domain/,
application/ or adapters/.

V-7: RLS is never disabled, tenant_id is never bypassed, and no
"see everything" permission exists at any privilege level.
"""
