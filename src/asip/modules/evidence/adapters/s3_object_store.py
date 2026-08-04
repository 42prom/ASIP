"""L3 — S3-compatible object storage.

MinIO in development, S3 with Object Lock in production (§10.1). One client
either way: the only difference is the endpoint and whether the bucket has a
retention policy, and having development speak the same protocol as production
is what stops "works against MinIO" from being a surprise at deploy time.

Object Lock is what makes WORM real. Without it, whoever holds the storage
credentials can rewrite a sealed bundle and the manifest hash in the database
would be the only thing that noticed — which is a detection, not a prevention.
Enabling it is a bucket-creation-time property and therefore an operational
step, not something this adapter can assert; `make evidence-roundtrip` against
a production-shaped bucket is where that gets checked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from collections.abc import Iterator


class S3ObjectStore:
    """Blob storage over any S3-compatible endpoint."""

    def __init__(
        self,
        bucket: str,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str = "us-east-1",
    ) -> None:
        self._bucket = bucket
        self._client: Any = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            # Path addressing: MinIO does not do virtual-host style buckets.
            config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 3}),
        )

    def put(self, key: str, data: bytes, media_type: str) -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data, ContentType=media_type)

    def get(self, key: str) -> bytes:
        response = self._client.get_object(Bucket=self._bucket, Key=key)
        body: bytes = response["Body"].read()
        return body

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise
        return True

    def list_prefix(self, prefix: str) -> tuple[str, ...]:
        keys: list[str] = []
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            keys.extend(item["Key"] for item in page.get("Contents", ()))
        return tuple(sorted(keys))

    def ensure_bucket(self) -> None:
        """Create the bucket if absent. Development convenience only.

        Production buckets are created by infrastructure with Object Lock
        enabled at creation time — it cannot be turned on afterwards, and a
        bucket this method created would silently not be WORM.
        """
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except ClientError:
            self._client.create_bucket(Bucket=self._bucket)


def iter_keys(store: S3ObjectStore, prefix: str) -> Iterator[str]:
    yield from store.list_prefix(prefix)
