"""L1 — manifest construction and verification.

Invariant 1 of the evidence subsystem: **the manifest covers everything.**
SHA-256 of every artifact, plus the capture metadata that says what those
artifacts are. If a file is in the bundle and not in the manifest, the bundle
is invalid — an unlisted file is exactly where tampered content would go.

The manifest is a **document**, not a structure. ``build_manifest_document``
produces bytes once, at write time; those bytes are what goes into the archive
and what gets hashed. Verification hashes the bytes it reads. Nothing in the
verification path re-serialises anything, so nothing depends on reproducing
this module's JSON conventions years later.

Pure: values in, values out. No filesystem, no object store. The caller hashes
the bytes it holds and passes the result in.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from asip.contracts.evidence import (
    HASH_ALGORITHM,
    Artifact,
    ArtifactKind,
    CaptureBinding,
    Manifest,
    ManifestDocument,
    RenderParams,
)

from .canonical import decimal_string, deterministic_json
from .hashing import is_hash_hex, sha256_hex

#: Identifies the manifest schema inside the document itself, so a reader can
#: tell which rules applied without consulting anything external.
MANIFEST_SPEC = "asip-manifest-v1"


class ManifestError(ValueError):
    """A manifest could not be built from the artifacts given."""


def build_manifest(
    artifacts: Iterable[Artifact],
    capture: CaptureBinding,
    render_params: RenderParams | None = None,
) -> Manifest:
    """Build a manifest, rejecting anything that would make it ambiguous.

    Artifacts are sorted by name so that the document depends on the set of
    artifacts and not on the order they happened to be collected in.
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

    return Manifest(
        algorithm=HASH_ALGORITHM,
        capture=capture,
        artifacts=tuple(ordered),
        render_params=render_params,
    )


def build_manifest_document(manifest: Manifest) -> ManifestDocument:
    """Serialise a manifest to the exact bytes that will be archived.

    Called once, at seal time. The returned bytes are stored verbatim in the
    WARC and in the database; every later check hashes those stored bytes.
    """
    payload: dict[str, Any] = {
        "spec": MANIFEST_SPEC,
        "hash_algorithm": manifest.algorithm,
        "capture": {
            "bundle_id": str(manifest.capture.bundle_id),
            "tenant_id": str(manifest.capture.tenant_id),
            "capture_id": str(manifest.capture.capture_id),
            "source_url": manifest.capture.source_url,
            "captured_at": manifest.capture.captured_at.isoformat(),
            "trace_id": manifest.capture.trace_id,
        },
        "render_params": _render_to_document(manifest.render_params),
        "artifacts": [
            {
                "name": a.name,
                "kind": str(a.kind),
                "media_type": a.media_type,
                "size_bytes": a.size_bytes,
                "sha256": a.sha256,
            }
            for a in manifest.artifacts
        ],
    }
    raw = deterministic_json(payload)
    return ManifestDocument(raw=raw, sha256=sha256_hex(raw))


def parse_manifest_document(raw: bytes) -> Manifest:
    """Read a manifest document back into a structure.

    Used for display and for cross-checking the archive against the database.
    Never used to recompute a digest — the digest belongs to ``raw``.
    """
    data = json.loads(raw.decode("utf-8"))
    if data.get("spec") != MANIFEST_SPEC:
        raise ManifestError(f"unknown manifest spec: {data.get('spec')!r}")

    capture = data["capture"]
    return Manifest(
        algorithm=data["hash_algorithm"],
        capture=CaptureBinding(
            bundle_id=UUID(capture["bundle_id"]),
            tenant_id=UUID(capture["tenant_id"]),
            capture_id=UUID(capture["capture_id"]),
            source_url=capture["source_url"],
            captured_at=datetime.fromisoformat(capture["captured_at"]),
            trace_id=capture["trace_id"],
        ),
        artifacts=tuple(
            Artifact(
                name=a["name"],
                kind=ArtifactKind(a["kind"]),
                media_type=a["media_type"],
                size_bytes=a["size_bytes"],
                sha256=a["sha256"],
            )
            for a in data["artifacts"]
        ),
        render_params=_render_from_document(data.get("render_params")),
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


def _render_to_document(render: RenderParams | None) -> dict[str, Any] | None:
    """Render params for the manifest, with the float rendered as text.

    D-23's claim is that two captures of an unchanged page produce identical
    pixels, which is only checkable if the parameters compare exactly. A float
    in a hashed document is the one field whose textual form implementations
    disagree about, so it is stored as its decimal string.
    """
    if render is None:
        return None
    return {
        "viewport_width": render.viewport_width,
        "viewport_height": render.viewport_height,
        "device_pixel_ratio": decimal_string(render.device_pixel_ratio),
        "locale": render.locale,
        "timezone": render.timezone,
        "animations_disabled": render.animations_disabled,
        "network_idle_ms": render.network_idle_ms,
        "settle_delay_ms": render.settle_delay_ms,
        "scroll_sequence": list(render.scroll_sequence),
    }


def _render_from_document(document: dict[str, Any] | None) -> RenderParams | None:
    if document is None:
        return None
    return RenderParams(
        viewport_width=int(document["viewport_width"]),
        viewport_height=int(document["viewport_height"]),
        device_pixel_ratio=float(document["device_pixel_ratio"]),
        locale=str(document["locale"]),
        timezone=str(document["timezone"]),
        animations_disabled=bool(document["animations_disabled"]),
        network_idle_ms=int(document["network_idle_ms"]),
        settle_delay_ms=int(document["settle_delay_ms"]),
        scroll_sequence=tuple(int(x) for x in document["scroll_sequence"]),
    )
