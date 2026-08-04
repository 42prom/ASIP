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
        self._timestamper: Any = rfc3161ng.RemoteTimestamper(
            url,
            certificate=certificate,
            hashname=hashname,
            timeout=timeout,
        )

    @property
    def url(self) -> str:
        return self._url

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
        except Exception:
            return False
        return bool(result)
