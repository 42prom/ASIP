"""L1 - review domain. Pure computation only.

No I/O, no clock, no randomness, no logging. If a function needs the
current time or a fresh UUID, it takes them as arguments. Anything
testable only with a mock belongs in application/ instead (L-04).

Enforced by the domain-purity contract in .importlinter and by
check_domain_purity.py on every edit.
"""
