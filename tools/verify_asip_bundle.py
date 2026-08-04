#!/usr/bin/env python3
"""Verify an ASIP evidence bundle. Standalone.

    python verify_asip_bundle.py bundle.warc.gz [--tsa-cert authority.pem]

This file imports **nothing from ASIP**. It uses the Python standard library
only. That is not a stylistic preference — it is the property being
demonstrated. An evidence bundle whose verification requires the software that
produced it is not independently verifiable, and a forensic artifact that
depends on a vendor's code has a shelf life equal to that vendor's.

Copy this file alongside the bundles. It is under 200 lines and can be
reimplemented in any language from the recipes carried inside each bundle.

What is checked
    1. Every resource record's payload hashes to what the manifest says.
    2. No resource record is absent from the manifest (a planted record).
    3. The manifest record's bytes hash to the digest the seal attests to.
    4. The chain entry hash recomputes from its own fields.
    5. The RFC 3161 token, if a certificate is supplied, covers that digest.

Step 5 needs a certificate and an ASN.1 parser, neither of which the standard
library provides, so it shells out to `openssl` when available and reports
honestly when it cannot. Steps 1-4 always run and need nothing at all.

Exit code 0 means every check that could run passed.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

WARC_VERSION = re.compile(rb"^WARC/1\.\d\r\n")
ARTIFACT_URI_PREFIX = "urn:asip:artifact:"
MANIFEST_URI = "urn:asip:manifest"
SEAL_URI = "urn:asip:seal"
LENGTH_PREFIX_BYTES = 8


# ── minimal WARC reader ─────────────────────────────────────────────────────
#
# WARC is a simple format on purpose: a header block of CRLF-terminated lines,
# a blank line, then exactly Content-Length payload bytes, then two CRLFs.
# Parsing it in forty lines is precisely why D-20 chose it over a container
# that would need a library.


def read_records(raw: bytes) -> list[tuple[dict[str, str], bytes]]:
    """Yield (headers, payload) for every record in a WARC byte stream."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    if not WARC_VERSION.match(raw):
        raise ValueError("not a WARC file: missing WARC/1.x version line")

    records = []
    offset = 0
    while offset < len(raw):
        end_of_headers = raw.find(b"\r\n\r\n", offset)
        if end_of_headers == -1:
            break
        header_block = raw[offset:end_of_headers].decode("utf-8", "replace")

        headers: dict[str, str] = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()

        length = int(headers.get("content-length", "0"))
        payload_start = end_of_headers + 4
        payload = raw[payload_start : payload_start + length]
        records.append((headers, payload))

        offset = payload_start + length
        while raw[offset : offset + 2] == b"\r\n":
            offset += 2
    return records


# ── the two recipes, reimplemented from the bundle's own description ────────


def length_prefixed(*fields: str) -> bytes:
    out = bytearray()
    for field in fields:
        data = field.encode("utf-8")
        out += len(data).to_bytes(LENGTH_PREFIX_BYTES, "big")
        out += data
    return bytes(out)


def chain_entry_hash(chain: dict[str, object]) -> str:
    return hashlib.sha256(
        length_prefixed(
            str(chain["preimage_version"]),
            str(chain["algorithm"]),
            str(chain["tenant_id"]),
            str(chain["chain_index"]),
            str(chain["prev_hash"]),
            str(chain["manifest_sha256"]),
            str(chain["bundle_id"]),
        )
    ).hexdigest()


# ── checks ──────────────────────────────────────────────────────────────────


def verify(path: Path, tsa_cert: Path | None) -> list[str]:
    problems: list[str] = []
    records = read_records(path.read_bytes())

    artifacts: dict[str, bytes] = {}
    manifest_raw: bytes | None = None
    seal_raw: bytes | None = None

    for headers, payload in records:
        uri = headers.get("warc-target-uri", "")
        if uri.startswith(ARTIFACT_URI_PREFIX):
            artifacts[uri[len(ARTIFACT_URI_PREFIX) :]] = payload
        elif uri == MANIFEST_URI:
            manifest_raw = payload
        elif uri == SEAL_URI:
            seal_raw = payload

    if manifest_raw is None:
        return ["no manifest record in the archive — cannot verify anything"]

    manifest = json.loads(manifest_raw.decode("utf-8"))
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()

    # 1 + 2 — artifacts against the manifest, both directions.
    listed = {a["name"]: a["sha256"] for a in manifest["artifacts"]}
    for name in sorted(set(listed) - set(artifacts)):
        problems.append(f"artifact in manifest but missing from archive: {name}")
    for name in sorted(set(artifacts) - set(listed)):
        problems.append(f"record in archive but absent from manifest: {name}")
    for name in sorted(set(listed) & set(artifacts)):
        actual = hashlib.sha256(artifacts[name]).hexdigest()
        if actual != listed[name]:
            problems.append(f"{name}: manifest says {listed[name]}, archive contains {actual}")

    print(f"  manifest covers {len(listed)} artifact(s); archive holds {len(artifacts)}")
    print(f"  manifest sha256 {manifest_digest}")

    if seal_raw is None:
        problems.append(
            "no seal record — the bundle carries no chain entry and no timestamp, "
            "so its position and date cannot be verified from the archive alone"
        )
        return problems

    seal = json.loads(seal_raw.decode("utf-8"))

    # 3 — the seal attests to this manifest.
    if seal["manifest_sha256"] != manifest_digest:
        problems.append(
            f"seal attests to {seal['manifest_sha256']} "
            f"but the manifest record hashes to {manifest_digest}"
        )

    # 4 — the chain entry recomputes.
    chain = dict(seal["chain"])
    chain["manifest_sha256"] = seal["manifest_sha256"]
    recomputed = chain_entry_hash(chain)
    if recomputed != chain["entry_hash"]:
        problems.append(
            f"chain entry hash does not recompute "
            f"(stored {chain['entry_hash']}, recomputed {recomputed})"
        )
    else:
        print(f"  chain entry {chain['chain_index']} recomputes correctly")

    # 5 — the external timestamp.
    problems.extend(verify_timestamps(seal, manifest_digest, tsa_cert))
    return problems


def verify_timestamps(
    seal: dict[str, object], manifest_digest: str, tsa_cert: Path | None
) -> list[str]:
    stamps = list(seal.get("timestamps") or [])
    if not stamps:
        return [
            "no RFC 3161 token in the seal — the bundle's contents are intact "
            "but nothing external attests to when they existed"
        ]

    if shutil.which("openssl") is None or tsa_cert is None:
        for stamp in stamps:
            print(
                f"  timestamp present from {stamp['authority_url']} "
                f"({len(base64.b64decode(stamp['token_base64']))} bytes) — "
                "not validated: needs openssl and --tsa-cert"
            )
        return []

    problems = []
    for stamp in stamps:
        if stamp["manifest_sha256"] != manifest_digest:
            problems.append("a timestamp attests to a different digest than this manifest")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "token.tsr"
            token.write_bytes(base64.b64decode(stamp["token_base64"]))
            data = Path(tmp) / "digest.txt"
            data.write_text(manifest_digest)
            result = subprocess.run(
                [
                    "openssl",
                    "ts",
                    "-verify",
                    "-in",
                    str(token),
                    "-token_in",
                    "-digest",
                    manifest_digest,
                    "-CAfile",
                    str(tsa_cert),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"  RFC 3161 token from {stamp['authority_url']} verifies")
            else:
                problems.append(
                    f"RFC 3161 token from {stamp['authority_url']} failed to verify: "
                    f"{result.stderr.strip()}"
                )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("bundle", type=Path)
    parser.add_argument(
        "--tsa-cert", type=Path, default=None, help="the timestamping authority's certificate, PEM"
    )
    args = parser.parse_args()

    print(f"Verifying {args.bundle}")
    try:
        problems = verify(args.bundle, args.tsa_cert)
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 2

    if problems:
        print("\nFAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("\nOK - every check that could run passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
