"""L3 — RFC 3161 timestamping against an external authority (D-22).

This is the adapter that turns a capture into evidence. Everything else in the
subsystem proves internal consistency: the manifest matches the artifacts, the
chain matches the manifests. All of that would still hold if the whole database
were fabricated this morning. Only a third party's signature over the manifest
digest establishes that this content existed at a date, and only because the
third party is not us.

Which is why there is no local fallback anywhere in this file. If the authority
is unreachable, ``stamp`` raises and the application layer records the bundle
as ``tsa_pending`` and retries. A self-issued token would satisfy every type in
the system and prove nothing at all.

WHAT IS STORED: the complete TimeStampResp, as received
-------------------------------------------------------
Not the TimeStampToken extracted from it. Two reasons, the second mattering
most in twenty years:

1. It is what the authority actually sent. Storing a fragment we chose to
   extract means storing our interpretation of the evidence rather than the
   evidence, and a later disagreement about that extraction is unresolvable.
2. It is what standard tooling expects. ``openssl ts -verify`` and every RFC
   3161 library take a response; a bare token needs an extra flag and a
   footnote explaining itself.

TWO LIBRARIES, DELIBERATELY
---------------------------
``rfc3161ng`` obtains responses — it speaks the HTTP transport well.
``rfc3161-client`` verifies them, because rfc3161ng 2.1.3 calls
``ECPublicKey.verify()`` with four positional arguments where current
``cryptography`` accepts three. Any authority signing with an EC key — FreeTSA
among them — cannot be verified by it at all.

Splitting the two is not a workaround; it is the correct shape. Obtaining an
attestation and checking one are different operations with different failure
modes, and a library that couples them turns a verification failure into
"could not stamp", discarding a token we successfully received.

PROVIDER-AGNOSTIC
-----------------
URL and certificates are configuration. There is no per-provider branch here
or anywhere else, because the moment one exists, switching authority becomes a
code change and the choice stops being reversible.
"""

from __future__ import annotations

from typing import Any

import rfc3161ng
from cryptography import x509
from pyasn1.codec.der import encoder
from rfc3161_client import VerifierBuilder, decode_timestamp_response

#: Development default. FreeTSA is a public RFC 3161 authority, used here only
#: because a default has to be something.
#:
#: Stamping with two independent authorities is supported by the same design:
#: tokens are appended records, so one bundle can carry several. Worth doing
#: for evidence expected to matter in a decade — an authority that ceases
#: operating, or has its key compromised, must not take the evidence with it.
FREETSA_URL = "https://freetsa.org/tsr"
FREETSA_CERTIFICATE_URL = "https://freetsa.org/files/tsa.crt"
FREETSA_CA_URL = "https://freetsa.org/files/cacert.pem"


class TimestampUnavailable(RuntimeError):
    """The authority could not be reached or refused the request.

    Distinct from a token that fails verification: this means we have no
    external attestation yet, not that an attestation disagrees.
    """


class Rfc3161TimestampAuthority:
    """Timestamping against one external TSA."""

    def __init__(
        self,
        url: str,
        certificate: bytes | None = None,
        roots: bytes | None = None,
        hashname: str = "sha256",
        timeout: int = 15,
    ) -> None:
        self._url = url
        self._hashname = hashname
        self._tsa_certificate = self._load_one(certificate)
        self._roots = self._load_many(roots)

        # Constructed WITHOUT the certificate on purpose — see the module
        # docstring. Acquisition must not fail because verification would.
        self._timestamper: Any = rfc3161ng.RemoteTimestamper(
            url, hashname=hashname, timeout=timeout
        )

    @property
    def url(self) -> str:
        return self._url

    def can_verify(self) -> bool:
        """Whether this adapter holds what it needs to check a response.

        Not "is the token good" — "are we in a position to ask". A caller that
        conflates the two reports an unconfigured verifier as tampered
        evidence, which is the most misleading error this subsystem can emit.
        """
        return self._tsa_certificate is not None

    def stamp(self, digest_hex: str) -> bytes:
        """Obtain a timestamp response over the manifest digest.

        The digest is sent, never the content. The authority learns that
        something with this hash existed and nothing about what it was — which
        matters when the content is a captured page full of personal data.
        """
        try:
            response = self._timestamper(digest=bytes.fromhex(digest_hex), return_tsr=True)
            der: bytes = encoder.encode(response)
        except Exception as exc:
            raise TimestampUnavailable(f"{self._url}: {exc}") from exc

        if not der:
            raise TimestampUnavailable(f"{self._url} returned an empty response")
        return der

    def verify(self, digest_hex: str, token: bytes) -> bool:
        """Check a stored response against the authority's certificate chain.

        Returns False rather than raising: a response that does not verify is
        an answer, and the caller reports it alongside the other checks rather
        than aborting. Callers separate "false because rejected" from "false
        because we could not ask" using ``can_verify``.
        """
        if self._tsa_certificate is None:
            # Nothing to check the signature against. Returning True here would
            # turn "verified" into "we received some bytes", which is exactly
            # the failure this module exists to prevent.
            return False
        try:
            response = decode_timestamp_response(token)
            builder = VerifierBuilder(tsa_certificate=self._tsa_certificate)
            for root in self._roots:
                builder = builder.add_root_certificate(root)
            return bool(builder.build().verify(response, bytes.fromhex(digest_hex)))
        except Exception:
            return False

    @staticmethod
    def _load_one(pem: bytes | None) -> x509.Certificate | None:
        if not pem:
            return None
        try:
            return x509.load_pem_x509_certificate(pem)
        except ValueError:
            return x509.load_der_x509_certificate(pem)

    @staticmethod
    def _load_many(pem: bytes | None) -> list[x509.Certificate]:
        if not pem:
            return []
        return list(x509.load_pem_x509_certificates(pem))
