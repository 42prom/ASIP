"""Port Protocols (D-98).

L2 application code depends on these Protocols and never on a concrete
adapter. Concrete adapters are constructed in exactly one place,
entrypoints/composition.py, which is the single documented exception to
the composition-root contract in .importlinter.

    class EvidenceStore(Protocol):
        def write_bundle(self, bundle: BundleDraft) -> BundleRef: ...
        def verify(self, ref: BundleRef) -> VerificationResult: ...
"""
