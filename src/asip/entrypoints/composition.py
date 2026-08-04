"""The composition root (D-98).

This is the only module in the codebase permitted to import a concrete
adapter. Every other module depends on the port Protocols in
``asip.contracts.ports``; import-linter's composition-root contract forbids
any ``application/`` package from importing an ``adapters/`` package, and
this file is the single documented exception.

Keeping construction in one place is what makes an adapter swappable. A
module that reaches for ``PostgresEvidenceRepository`` directly is bound to
Postgres regardless of what its type hints claim.

The settings object holds names, never secrets read from the repository —
values come from the environment, which is populated by the secrets manager
(docs/COMMANDS.md).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import psycopg

from asip.modules.evidence.adapters.postgres_repository import PostgresEvidenceRepository
from asip.modules.evidence.adapters.rfc3161_tsa import Rfc3161TimestampAuthority
from asip.modules.evidence.adapters.s3_object_store import S3ObjectStore
from asip.modules.evidence.adapters.warc_archive import WarcBundleArchive
from asip.modules.evidence.application.anchor_chain import AnchorChain
from asip.modules.evidence.application.verify_bundle import VerifyBundle
from asip.modules.evidence.application.write_bundle import WriteBundle

#: Shipped certificates for the development authority. Public artifacts, so
#: they live in the repository rather than the secrets manager — anyone
#: verifying our evidence needs exactly these.
_CONFIG = Path(__file__).resolve().parents[3] / "config" / "tsa"
DEFAULT_TSA_CERT = str(_CONFIG / "freetsa-tsa.crt")
DEFAULT_TSA_ROOTS = str(_CONFIG / "freetsa-cacert.pem")


def _read_optional(path: str | None) -> bytes | None:
    """Read a certificate if it is there. A missing one is not an error.

    A deployment pointed at another authority supplies its own; one that has
    not configured verification yet still runs, and reports its bundles as
    unconfirmed rather than pretending or crashing.
    """
    if not path:
        return None
    candidate = Path(path)
    return candidate.read_bytes() if candidate.is_file() else None


@dataclass(frozen=True)
class Settings:
    """Runtime configuration. Names here, values in the environment."""

    profile: str
    db_url: str
    object_store_url: str
    object_store_key: str
    object_store_secret: str
    object_store_bucket: str
    tsa_url: str
    #: The authority's own certificate, and the roots it chains to. Both are
    #: public artifacts, not secrets — they are what lets anyone else check the
    #: same token, which is the point of using an external authority at all.
    tsa_certificate: bytes | None = None
    tsa_roots: bytes | None = None

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            profile=os.environ.get("ASIP_PROFILE", "dev"),
            db_url=os.environ["ASIP_DB_URL"],
            object_store_url=os.environ["ASIP_OBJECT_STORE_URL"],
            object_store_key=os.environ["ASIP_OBJECT_STORE_KEY"],
            object_store_secret=os.environ["ASIP_OBJECT_STORE_SECRET"],
            object_store_bucket=os.environ.get("ASIP_OBJECT_STORE_BUCKET", "asip-evidence"),
            tsa_url=os.environ["ASIP_TSA_URL"],
            tsa_certificate=_read_optional(os.environ.get("ASIP_TSA_CERT", DEFAULT_TSA_CERT)),
            tsa_roots=_read_optional(os.environ.get("ASIP_TSA_ROOTS", DEFAULT_TSA_ROOTS)),
        )


@dataclass(frozen=True)
class EvidenceContainer:
    """The evidence module's use cases, wired to real adapters."""

    write_bundle: WriteBundle
    verify_bundle: VerifyBundle
    anchor_chain: AnchorChain


class SystemClock:
    """The collector's wall clock (D-100). Never authoritative for detection.

    Timezone-aware UTC, always. A naive datetime reaching the evidence path
    would be a timestamp whose meaning depends on where the process happened
    to be running.
    """

    def now(self) -> datetime:
        return datetime.now(UTC)


def build_evidence(settings: Settings, connection: psycopg.Connection) -> EvidenceContainer:
    """Construct the evidence module.

    The connection is passed in rather than opened here: the transaction
    boundary belongs to whoever is handling the request, and an adapter that
    owns its own connection cannot participate in one.
    """
    object_store = S3ObjectStore(
        bucket=settings.object_store_bucket,
        endpoint_url=settings.object_store_url,
        access_key=settings.object_store_key,
        secret_key=settings.object_store_secret,
    )
    archive = WarcBundleArchive(object_store)
    repository = PostgresEvidenceRepository(connection)
    tsa = Rfc3161TimestampAuthority(
        settings.tsa_url,
        certificate=settings.tsa_certificate,
        roots=settings.tsa_roots,
    )

    return EvidenceContainer(
        write_bundle=WriteBundle(archive, repository, tsa, SystemClock(), settings.tsa_url),
        verify_bundle=VerifyBundle(archive, repository, tsa),
        anchor_chain=AnchorChain(repository, tsa, SystemClock(), settings.tsa_url),
    )


def build_container(settings: Settings, connection: psycopg.Connection) -> EvidenceContainer:
    """Construct the adapter graph for a runtime profile.

    Only evidence exists so far. The remaining eight modules are wired here as
    they land (docs/WALKING_SKELETON.md).
    """
    return build_evidence(settings, connection)
