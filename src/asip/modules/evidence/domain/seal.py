"""L1 — the seal: what makes a bundle verifiable without ASIP.

A bundle used to consist of artifacts and a manifest, with its chain entry and
RFC 3161 token held only in PostgreSQL. That made the evidence dependent on our
database: hand someone the WARC in 2045 and they could confirm the manifest
covered the artifacts, but nothing about *when* it existed or where it sat in
the chain. The most valuable claim — "this content existed on this date" —
was the one claim the artifact could not carry on its own.

The seal fixes that. It is a small JSON document written into the archive
alongside the manifest, containing everything a stranger needs:

    manifest digest        what is being attested
    chain entry            tenant, index, prev_hash, entry_hash, algorithm
    chain preimage recipe  how to recompute entry_hash from those fields
    RFC 3161 token         the external attestation, DER, base64
    authority              which TSA issued it

With the seal in the archive, the database becomes an index — fast lookup,
tenant scoping, queries — rather than the source of truth. Losing it entirely
would cost searchability, not evidence. That is the correct relationship
between a forensic artifact and the system that happens to manage it.

Written as a separate record from the manifest, and appended after the token
arrives, because the token cannot exist before the manifest digest does. WARC
files concatenate, so appending a sealed segment produces a longer, still-valid
WARC rather than a modified one — the archive stays append-only at the byte
level, not merely by convention.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from asip.contracts.evidence import ChainEntry, TimestampRecord

from .canonical import deterministic_json

SEAL_SPEC = "asip-seal-v1"

#: A plain-language statement of the chain preimage, carried inside every seal.
#: The point is that a verifier never has to find our source code: the recipe
#: for recomputing entry_hash travels with the evidence it protects.
CHAIN_PREIMAGE_RECIPE = (
    "entry_hash = SHA256( LP(preimage_version) || LP(algorithm) || LP(tenant_id) "
    "|| LP(chain_index) || LP(prev_hash) || LP(manifest_sha256) || LP(bundle_id) ) "
    "where LP(s) = big-endian uint64 byte-length of UTF-8 s, followed by those bytes; "
    "chain_index is decimal; hashes are lowercase hex; UUIDs are canonical lowercase."
)

MANIFEST_DIGEST_RECIPE = (
    "manifest_sha256 = SHA256(the exact bytes of the manifest record in this archive). "
    "Do not re-serialise the manifest before hashing it."
)


def build_seal_document(
    entry: ChainEntry,
    preimage_version: str,
    timestamps: tuple[TimestampRecord, ...] = (),
) -> bytes:
    """Serialise a seal to the bytes stored in the archive.

    Tokens are base64 DER: RFC 3161 tokens are binary, and base64 is the form
    every tool and every human transcription path handles without loss.
    """
    payload: dict[str, Any] = {
        "spec": SEAL_SPEC,
        "manifest_sha256": entry.manifest_sha256,
        "manifest_digest_recipe": MANIFEST_DIGEST_RECIPE,
        "chain": {
            "preimage_version": preimage_version,
            "algorithm": entry.algorithm,
            "tenant_id": str(entry.tenant_id),
            "chain_index": entry.chain_index,
            "prev_hash": entry.prev_hash,
            "bundle_id": str(entry.bundle_id),
            "entry_hash": entry.entry_hash,
        },
        "chain_preimage_recipe": CHAIN_PREIMAGE_RECIPE,
        "timestamps": [
            {
                "authority_url": stamp.authority_url,
                "manifest_sha256": stamp.manifest_sha256,
                "obtained_at": stamp.obtained_at.isoformat(),
                "token_base64": base64.b64encode(stamp.token).decode("ascii"),
                "token_format": "RFC3161 TimeStampToken, DER",
            }
            for stamp in timestamps
        ],
        "verification": (
            "1. Hash each resource record's payload with SHA-256 and compare against "
            "the artifacts listed in the manifest record; an unlisted record invalidates "
            "the bundle. "
            "2. Hash the manifest record's bytes and compare against manifest_sha256. "
            "3. Recompute entry_hash using chain_preimage_recipe. "
            "4. Verify each RFC 3161 token against manifest_sha256 using the issuing "
            "authority's certificate. "
            "No ASIP software is required for any step."
        ),
    }
    return deterministic_json(payload)


def parse_seal_document(raw: bytes) -> dict[str, Any]:
    """Read a seal document. Returns the parsed structure as stored."""
    data: dict[str, Any] = json.loads(raw.decode("utf-8"))
    if data.get("spec") != SEAL_SPEC:
        raise ValueError(f"unknown seal spec: {data.get('spec')!r}")
    return data
