"""L1 — manifest construction and verification.

Invariant 1 of the evidence subsystem: **the manifest covers everything.**
SHA-256 of every artifact. If a file is in the bundle and not in the manifest,
the bundle is invalid — an unlisted file is exactly where tampered content
would go, so an extra file is as fatal as a wrong hash.

Pure: values in, values out. No filesystem, no object store. The caller hashes
the bytes it holds and passes the result in.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from asip.contracts.evidence import HASH_ALGORITHM, Artifact, Manifest

from .hashing import digest_of, is_hash_hex


class ManifestError(ValueError):
    """A manifest could not be built from the artifacts given."""


def build_manifest(artifacts: Iterable[Artifact]) -> Manifest:
    """Build a manifest, rejecting anything that would make it ambiguous.

    Artifacts are sorted by name so that the manifest digest depends on the set
    of artifacts and not on the order they happened to be collected in.
    """
    ordered = sorted(artifacts, key=lambda a: a.name)

    if not ordered:
        raise ManifestError("a bundle with no artifacts has nothing to attest to")

    seen: set[str] = set()
    for artifact in ordered:
        if artifact.name in seen:
            raise ManifestError(
                f"duplicate artifact name {artifact.name!r}: "
                "one name must identify exactly one file in the bundle"
            )
        seen.add(artifact.name)

        if not is_hash_hex(artifact.sha256):
            raise ManifestError(
                f"artifact {artifact.name!r} has a malformed sha256: {artifact.sha256!r}"
            )
        if artifact.size_bytes < 0:
            raise ManifestError(f"artifact {artifact.name!r} has a negative size")

    return Manifest(algorithm=HASH_ALGORITHM, artifacts=tuple(ordered))


def manifest_digest(manifest: Manifest) -> str:
    """The digest that is written to the hash chain (D-21).

    Covers the algorithm as well as the artifacts: a manifest recomputed under
    a different algorithm must not collide with the original.
    """
    return digest_of(
        {
            "algorithm": manifest.algorithm,
            "artifacts": [
                {
                    "kind": str(a.kind),
                    "media_type": a.media_type,
                    "name": a.name,
                    "sha256": a.sha256,
                    "size_bytes": a.size_bytes,
                }
                for a in manifest.artifacts
            ],
        }
    )


def verify_manifest(manifest: Manifest, observed: Mapping[str, str]) -> tuple[str, ...]:
    """Compare a manifest against the artifacts actually present.

    ``observed`` maps artifact name to the SHA-256 of the bytes found in the
    bundle. Returns the problems found, empty if the bundle is intact.

    All three directions are checked, and the third is the one that matters:
    a missing file and a changed file are visible failures, but an *extra*
    file is the one an attacker would add, and only the manifest's
    completeness catches it.
    """
    problems: list[str] = []

    if manifest.algorithm != HASH_ALGORITHM:
        problems.append(
            f"manifest algorithm is {manifest.algorithm!r}, expected {HASH_ALGORITHM!r}"
        )

    listed = {a.name: a.sha256 for a in manifest.artifacts}

    for name in sorted(set(listed) - set(observed)):
        problems.append(f"artifact listed in manifest but missing from bundle: {name}")

    for name in sorted(set(observed) - set(listed)):
        problems.append(f"artifact present in bundle but absent from manifest: {name}")

    for name in sorted(set(listed) & set(observed)):
        if listed[name] != observed[name]:
            problems.append(
                f"artifact {name} hash mismatch: manifest {listed[name]}, bundle {observed[name]}"
            )

    return tuple(problems)
