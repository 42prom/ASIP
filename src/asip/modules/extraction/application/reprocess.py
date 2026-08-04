"""L2 — re-parse stored captures with a newer extractor (D-13).

THIS CLASS CANNOT FETCH ANYTHING
--------------------------------
Read the constructor. It takes a source of stored capture bytes and a
repository. There is no fetcher, no HTTP client, no queue — so "reprocessing
accidentally refetched" is not a bug that can occur here, it is a shape the
code does not have. ``tests/unit/extraction/test_reprocess.py`` asserts it
against the real signature.

D-13 calls refetching instead of reprocessing an error that costs real money,
and docs/WALKING_SKELETON.md names it the most expensive directive to get
wrong. The protection is structural for that reason: a comment would not
survive the first person in a hurry who has a fetcher in scope.

WHAT A REPROCESS MAY AND MAY NOT CHANGE
---------------------------------------
It may improve how an item was *read*: its text, its script, the precision of
its timestamp. It may not change *which capture it came from* or *when it was
posted*. Those are the item's identity — a reprocess that rewrote them would be
inventing a different observation rather than re-reading the same one, and the
database refuses it by withholding the grant.

That distinction has a sharp edge, and this module reports rather than hides it:
if a newer extractor derives a different authoritative timestamp, the row cannot
be updated in place at all, because ``posted_at_authoritative`` is the partition
key and part of the primary key. Such items are counted and named, not silently
duplicated into a second row.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from uuid import UUID

from asip.contracts.ports.captures import CaptureBytes

from ..domain.parser import EXTRACTOR_VERSION, parse_capture


@dataclass
class ReprocessReport:
    """What a reprocess did, in terms that can be checked against D-13."""

    captures_examined: int = 0
    captures_reprocessed: int = 0
    items_updated: int = 0
    items_unchanged: int = 0
    captures_unavailable: int = 0
    #: Items whose newly derived timestamp differs from the stored one. These
    #: cannot be updated in place and are reported for a migration path rather
    #: than written as duplicates.
    items_needing_migration: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    #: The number that matters. A reprocess that fetched anything has failed its
    #: purpose, and this is always zero because the code cannot fetch.
    fetches_performed: int = 0

    @property
    def summary(self) -> str:
        parts = [
            f"{self.captures_reprocessed}/{self.captures_examined} captures reprocessed",
            f"{self.items_updated} item(s) updated",
            f"{self.fetches_performed} refetches",
        ]
        if self.captures_unavailable:
            parts.append(f"{self.captures_unavailable} capture(s) unavailable")
        if self.items_needing_migration:
            parts.append(f"{len(self.items_needing_migration)} need a migration path")
        return ", ".join(parts)


class ReprocessCaptures:
    """Re-parse what is already stored. Contacts no source, ever."""

    def __init__(self, captures: CaptureBytes, repository: object) -> None:
        # Two dependencies, neither of which can reach the network. The
        # repository is typed loosely here only to avoid a circular import;
        # the composition root supplies PostgresExtractionRepository.
        self._captures = captures
        self._repository = repository

    def execute(self, tenant_id: UUID, platform: str = "canary") -> ReprocessReport:
        report = ReprocessReport()

        backlog = self._repository.reprocessing_backlog(  # type: ignore[attr-defined]
            tenant_id, EXTRACTOR_VERSION
        )
        report.captures_examined = len(backlog)

        for entry in backlog:
            capture_id = entry["capture_id"]
            raw = self._captures.read_capture(tenant_id, capture_id)

            if raw is None:
                # Retention may have expired the bytes while the rows survive
                # until their own expiry. Ordinary during a reprocess of old
                # material — counted, and the batch continues.
                report.captures_unavailable += 1
                continue

            result = parse_capture(raw, minimum_expected_items=1)
            report.problems.extend(result.problems)

            stored = {
                str(row["content_id"]): row
                for row in self._repository.content_for_capture(  # type: ignore[attr-defined]
                    tenant_id, capture_id
                )
            }

            for item in result.items:
                content_id = self._repository.content_id_for(  # type: ignore[attr-defined]
                    platform, item.external_id
                )
                existing = stored.get(str(content_id))
                if existing is None:
                    # An item the old extractor missed entirely. Inserting it is
                    # the point of reprocessing, and it is a new row rather than
                    # a correction.
                    continue

                if existing["posted_at_authoritative"] != item.posted_at:
                    report.items_needing_migration.append(str(content_id))
                    continue

                updated = self._repository.update_extracted(  # type: ignore[attr-defined]
                    tenant_id=tenant_id,
                    content_id=content_id,
                    posted_at=item.posted_at,
                    text=item.text,
                    text_sha256=hashlib.sha256(item.text.encode("utf-8")).hexdigest(),
                    script=item.script,
                    precision=item.timestamp_precision,
                    extractor_version=result.extractor_version,
                )
                if updated:
                    report.items_updated += 1
                else:
                    report.items_unchanged += 1

            report.captures_reprocessed += 1

        return report
