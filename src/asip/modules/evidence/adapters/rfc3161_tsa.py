"""L3 — RFC 3161 timestamping against an external authority (D-22).

This is the adapter that turns a capture into evidence. Everything else in the
subsystem proves internal consistency: the manifest matches the artifacts, the
chain matches the manifests. All of that would still hold if the whole database
were fabricated this morning. Only a third party's signature over the manifest
digest establishes that this content existed at a date, and only because the
third party is not us.

Which is why there is no local fallback anywhere in this file. If the authority
is unreachable, `stamp` raises and the application layer records the bundle as
`tsa_pending` and retries. A self-issued token would satisfy every type in the
system and prove nothing at all.

Provider is configuration, not code. D-22 notes that free TSAs exist without
naming one; the URL and the authority's certificate are supplied by the caller
so that switching provider, or stamping with two of them, needs no change here.
"""

from __future__ import annotations

import binascii
from typing import Any

import rfc3161ng

#: Development default. FreeTSA is a public RFC 3161 authority and is used here
#: only because a default has to be something — nothing in this module knows or
#: cares which authority it is talking to.
#:
#: Production switches provider through configuration alone: point ASIP_TSA_URL
#: at DigiCert, Sectigo, a national timestamping service, or an in-house TSA,
#: supply that authority's certificate, and nothing in this file changes. There
#: is deliberately no per-provider branch anywhere in the codebase, because the
#: moment one exists, switching authority becomes a code change and the choice
#: stops being reversible.
#:
#: Stamping with two independent authorities is supported by the same design:
#: tokens are appended records, so a bundle can carry several. That is worth
#: doing for evidence expected to matter in a decade — an authority that ceases
#: operating or has its key compromised does not take the evidence with it.
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
        hashname: str = "sha256",
        timeout: int = 10,
    ) -> None:
        self._url = url
        self._certificate = certificate
        self._hashname = hashname
        # Constructed WITHOUT the certificate on purpose. rfc3161ng verifies
        # automatically inside __call__ when it holds one, which couples
        # obtaining a token to checking it — and a verification failure then
        # surfaces as "could not stamp", losing a token we successfully got.
        # Acquisition and verification are separate concerns and separate
        # methods here.
        self._timestamper: Any = rfc3161ng.RemoteTimestamper(
            url, hashname=hashname, timeout=timeout
        )
        self._verification_works: bool | None = None

    @property
    def url(self) -> str:
        return self._url

    def can_verify(self) -> bool:
        """Whether this adapter can actually check a token right now.

        Two conditions, and both are about capability rather than validity:
        the authority's certificate must be configured, and the installed
        library must be able to check that certificate's signature algorithm.

        The second is not hypothetical. rfc3161ng 2.1.3 calls
        ``ECPublicKey.verify()`` with four positional arguments; current
        ``cryptography`` accepts three. Any authority signing with an EC key —
        FreeTSA among them — cannot be verified by this library. Probing for it
        rather than assuming means a bundle carrying a genuine token is
        recorded as pending, not as failed. Calling it failed would read as
        evidence of tampering caused by a dependency's version skew.
        """
        return self._certificate is not None and self._verification_works is not False

    def stamp(self, digest_hex: str) -> bytes:
        """Obtain a token over the manifest digest.

        The digest is sent, never the content. The authority learns that
        something with this hash existed and nothing about what it was — which
        matters when the content is a captured page containing personal data.
        """
        try:
            token = self._timestamper(digest=binascii.unhexlify(digest_hex), return_tsr=False)
        except Exception as exc:
            raise TimestampUnavailable(f"{self._url}: {exc}") from exc

        if not token:
            raise TimestampUnavailable(f"{self._url} returned an empty token")
        return bytes(token)

    def verify(self, digest_hex: str, token: bytes) -> bool:
        """Check a token against the authority's certificate.

        Returns False rather than raising on a bad token: a token that does not
        verify is an answer, and the caller reports it as a failed check
        alongside the others rather than aborting verification.
        """
        if self._certificate is None:
            # Without the authority's certificate there is nothing to check the
            # signature against. Claiming success here would turn "verified" into
            # "we received some bytes", which is the failure this whole module
            # exists to prevent.
            return False
        try:
            result = rfc3161ng.check_timestamp(
                token,
                certificate=self._certificate,
                digest=binascii.unhexlify(digest_hex),
                hashname=self._hashname,
            )
        except TypeError:
            # The library cannot check this certificate's signature algorithm
            # at all — see can_verify. Records the incapacity so the caller
            # reports the bundle as pending rather than as a failed check, and
            # returns False because we have emphatically not verified anything.
            self._verification_works = False
            return False
        except Exception:
            return False
        self._verification_works = True
        return bool(result)
