"""L1 — canonical byte encodings for everything that gets hashed.

Two encodings, both chosen so that someone reimplementing them in 2045 needs
nothing but their language's standard library.

**Length-prefixed fields** for the hash chain. No JSON, no canonicalisation
rules, no encoding subtleties — a list of UTF-8 strings, each preceded by its
length as an 8-byte big-endian integer. Fifteen lines in any language, and the
values themselves are human-readable ASCII so a verifier can reconstruct the
preimage by hand from a printed record if it ever comes to that.

**Deterministic JSON** for the manifest document. Note carefully what this is
*not* used for: the manifest's digest is the hash of the bytes as they are
stored in the archive, never a hash recomputed from a re-serialised structure.
That distinction is the whole point. A verifier hashes what it reads; it never
has to reproduce our serialiser, our key ordering, our float formatting, or our
choice of separators. This function exists to produce the bytes once, at write
time — not to be part of any verification path.

Why that matters: canonical-JSON schemes are a well-known source of long-term
verification failure. Two implementations disagree about number formatting or
Unicode escaping and a valid document stops verifying. Hashing stored bytes
removes the entire class.
"""

from __future__ import annotations

import json
from typing import Any

#: Width of the length prefix. Eight bytes is far more than any field needs and
#: removes any question about overflow or width negotiation.
LENGTH_PREFIX_BYTES = 8


def length_prefixed(*fields: str) -> bytes:
    """Encode fields unambiguously as ``len||bytes`` pairs, in the order given.

    Length prefixing is what makes the encoding injective: without it,
    ``("ab", "c")`` and ``("a", "bc")`` would produce identical bytes and two
    different chain entries could collide. Order is fixed by the caller and is
    part of the specification.
    """
    out = bytearray()
    for field in fields:
        data = field.encode("utf-8")
        out += len(data).to_bytes(LENGTH_PREFIX_BYTES, "big")
        out += data
    return bytes(out)


def deterministic_json(payload: dict[str, Any]) -> bytes:
    """Serialise a document to stable bytes. Write path only.

    Sorted keys, no insignificant whitespace, UTF-8, non-ASCII preserved rather
    than escaped so that Georgian text stays readable in the stored artifact.

    Callers must persist the returned bytes and hash *those*. Re-serialising an
    equivalent structure later and hashing the result is not equivalent and is
    not supported.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def decimal_string(value: float) -> str:
    """Render a float for inclusion in a hashed document.

    Floats are the hardest part of every canonical-JSON scheme: the same value
    has several valid textual forms and implementations disagree about which to
    emit. Rather than depend on any of them agreeing, numeric render parameters
    are stored as strings in their exact decimal form. `1.0` is written "1.0"
    and read back as "1.0" by everyone.
    """
    return repr(float(value))
