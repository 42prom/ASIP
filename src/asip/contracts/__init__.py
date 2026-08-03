"""L0 - contracts. Types, enums, Protocols and event schemas.

The innermost layer. It imports nothing else from asip, and every other
layer may import it. This is what makes the modules separable: two
modules that share a contract are coupled to the contract, not to each
other.
"""
