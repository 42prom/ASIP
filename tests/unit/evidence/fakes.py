"""In-memory stand-ins for the evidence ports.

Fakes rather than mocks: they behave like the real thing, including enforcing
the invariants the real adapters must enforce. A fake repository that happily
writes a chain entry without its bundle would let the use-case tests pass while
the property they exist to protect is broken.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from asip.contracts.evidence import (
    BundleRecord,
    ChainEntry,
    StoredBundle,
    TimestampRecord,
)


class FakeObjectStore:
    """Blob storage that records writes in order."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.media_types: dict[str, str] = {}
        self.put_order: list[str] = []
        self.fail_on: str | None = None

    def put(self, key: str, data: bytes, media_type: str) -> None:
        if self.fail_on is not None and key.endswith(self.fail_on):
            raise OSError(f"object store unavailable for {key}")
        self.blobs[key] = data
        self.media_types[key] = media_type
        self.put_order.append(key)

    def get(self, key: str) -> bytes:
        return self.blobs[key]

    def exists(self, key: str) -> bool:
        return key in self.blobs

    def list_prefix(self, prefix: str) -> tuple[str, ...]:
        return tuple(sorted(k for k in self.blobs if k.startswith(prefix)))

    def corrupt(self, key: str, data: bytes) -> None:
        """Simulate tampering after the fact."""
        self.blobs[key] = data


@dataclass
class FakeRepository:
    """Append-only store. Enforces atomicity of the bundle/chain pair."""

    bundles: dict[tuple[UUID, UUID], BundleRecord] = field(default_factory=dict)
    chains: dict[UUID, list[ChainEntry]] = field(default_factory=dict)
    stamps: dict[tuple[UUID, UUID], list[TimestampRecord]] = field(default_factory=dict)
    commit_calls: int = 0
    fail_commit: bool = False

    def commit_bundle(self, record: BundleRecord, entry: ChainEntry) -> None:
        self.commit_calls += 1
        if self.fail_commit:
            # Neither write lands. This is what "atomic" has to mean.
            raise RuntimeError("transaction rolled back")
        self.bundles[(record.tenant_id, record.bundle_id)] = record
        self.chains.setdefault(entry.tenant_id, []).append(entry)

    def append_timestamp(self, stamp: TimestampRecord) -> None:
        self.stamps.setdefault((stamp.tenant_id, stamp.bundle_id), []).append(stamp)

    def head(self, tenant_id: UUID) -> ChainEntry | None:
        entries = self.chains.get(tenant_id)
        return entries[-1] if entries else None

    def segment(self, tenant_id: UUID, start: int, end: int) -> tuple[ChainEntry, ...]:
        return tuple(e for e in self.chains.get(tenant_id, []) if start <= e.chain_index <= end)

    def load_bundle(self, tenant_id: UUID, bundle_id: UUID) -> StoredBundle | None:
        record = self.bundles.get((tenant_id, bundle_id))
        if record is None:
            return None
        entry = next(e for e in self.chains[tenant_id] if e.bundle_id == bundle_id)
        return StoredBundle(
            record=record,
            chain_entry=entry,
            timestamps=tuple(self.stamps.get((tenant_id, bundle_id), ())),
        )

    def replace_chain_entry(self, tenant_id: UUID, index: int, entry: ChainEntry) -> None:
        """Tamper hook. No production path may do this."""
        self.chains[tenant_id][index] = entry


class FakeTimestampAuthority:
    """A cooperative TSA. Tokens are the digest, tagged."""

    def __init__(self) -> None:
        self.unreachable = False
        self.issue_invalid = False
        self.stamp_calls = 0

    def stamp(self, digest_hex: str) -> bytes:
        self.stamp_calls += 1
        if self.unreachable:
            raise ConnectionError("TSA unreachable")
        if self.issue_invalid:
            return b"tsa:" + b"0" * 64
        return b"tsa:" + digest_hex.encode()

    def verify(self, digest_hex: str, token: bytes) -> bool:
        return token == b"tsa:" + digest_hex.encode()


class FixedClock:
    def __init__(self, moment: datetime | None = None) -> None:
        self._moment = moment or datetime(2026, 8, 4, 9, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self._moment
