"""L1 — hashing primitives for the evidence path.

Pure: bytes in, hex out. No clock, no randomness, no I/O.

The canonical JSON encoding here is load-bearing. Manifest and chain digests
are computed over serialised structures, so two runs that disagree about key
order or whitespace produce different hashes for identical content and the
chain appears broken. Every digest in this subsystem goes through
``canonical_json``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from asip.contracts.evidence import HASH_HEX_LENGTH

_HEX_DIGITS = frozenset("0123456789abcdef")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256. The only digest function in the evidence path."""
    return hashlib.sha256(data).hexdigest()


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Deterministic JSON encoding used as digest input.

    Sorted keys, no insignificant whitespace, UTF-8, and non-ASCII preserved
    rather than escaped. Fixed here so that a future formatting preference
    cannot silently invalidate existing chains.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest_of(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical encoding of a structure."""
    return sha256_hex(canonical_json(payload))


def is_hash_hex(value: str) -> bool:
    """Whether a string is a well-formed lowercase SHA-256 hex digest.

    Used to reject malformed hashes at the boundary. Uppercase hex is rejected
    deliberately: accepting both would mean the same hash has two spellings,
    and equality comparisons across the chain would depend on which one was
    stored.
    """
    return len(value) == HASH_HEX_LENGTH and _HEX_DIGITS.issuperset(value)
