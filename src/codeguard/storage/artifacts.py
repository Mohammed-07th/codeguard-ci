"""Review reports as artifacts in S3-compatible object storage (MinIO).

A review report is the durable output of the system. Writing it only to the
container's filesystem would lose it on the next deploy, so reports go to object
storage keyed by PR and timestamp.

MinIO speaks the S3 API, so this is ``boto3`` against a custom endpoint — the
same code runs against AWS S3 in production by changing two environment
variables and nothing else.

Storage is deliberately **not on the critical path**: if the bucket is
unreachable the review still completes and the report is still on local disk.
Losing an artifact upload is an operational problem, not a reason to fail a
security review that already ran.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError

from codeguard.config import Settings, get_settings

log = logging.getLogger(__name__)


class ArtifactStoreUnavailable(RuntimeError):
    """Raised only by callers that explicitly require storage to be up."""


def get_client(settings: Settings | None = None):
    """An S3 client pointed at MinIO (or real S3, if the endpoint says so)."""
    s = settings or get_settings()
    return boto3.client(
        "s3",
        endpoint_url=s.minio_endpoint,
        aws_access_key_id=s.minio_access_key,
        aws_secret_access_key=s.minio_secret_key,
        # MinIO requires path-style addressing; virtual-host style assumes DNS
        # per bucket, which a single container does not provide.
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=3,
            read_timeout=5,
            retries={"max_attempts": 2},
        ),
        region_name="us-east-1",
    )


def is_available(settings: Settings | None = None) -> bool:
    """Cheap reachability probe, used by the health endpoint."""
    try:
        get_client(settings).list_buckets()
        return True
    except (BotoCoreError, ClientError, OSError):
        return False


def ensure_bucket(settings: Settings | None = None) -> bool:
    """Create the reports bucket if it does not exist."""
    s = settings or get_settings()
    client = get_client(s)
    try:
        client.head_bucket(Bucket=s.minio_bucket)
        return True
    except ClientError:
        try:
            client.create_bucket(Bucket=s.minio_bucket)
            log.info("created bucket %s", s.minio_bucket)
            return True
        except (BotoCoreError, ClientError) as exc:
            log.warning("could not create bucket %s: %s", s.minio_bucket, exc)
            return False
    except (BotoCoreError, OSError) as exc:
        log.warning("artifact store unreachable: %s", exc)
        return False


def object_key(pr_id: str, when: datetime | None = None) -> str:
    """Date-partitioned key, so a bucket stays browsable after a few thousand reviews."""
    ts = when or datetime.now(timezone.utc)
    return f"reports/{ts:%Y/%m/%d}/{pr_id}-{ts:%H%M%S}.json"


def upload_report(path: Path, report: dict[str, Any], settings: Settings | None = None) -> str | None:
    """Upload a report. Returns the object URI, or ``None`` if storage is down."""
    s = settings or get_settings()
    if not ensure_bucket(s):
        return None
    key = object_key(report.get("pr_id", "unknown"))
    body = json.dumps(report, indent=2, default=str).encode("utf-8")
    try:
        get_client(s).put_object(
            Bucket=s.minio_bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            Metadata={
                "pr-id": str(report.get("pr_id", "")),
                "decision": str(report.get("decision", "")),
                "findings": str(len(report.get("findings", []))),
            },
        )
    except (BotoCoreError, ClientError, OSError) as exc:
        log.warning("report upload failed (review is unaffected): %s", exc)
        return None
    uri = f"s3://{s.minio_bucket}/{key}"
    log.info("report uploaded: %s", uri)
    return uri


def list_reports(limit: int = 50, settings: Settings | None = None) -> list[dict[str, Any]]:
    """List stored reports — used by the evidence notebook to show the objects."""
    s = settings or get_settings()
    try:
        resp = get_client(s).list_objects_v2(
            Bucket=s.minio_bucket, Prefix="reports/", MaxKeys=limit
        )
    except (BotoCoreError, ClientError, OSError):
        return []
    return [
        {
            "key": o["Key"],
            "size": o["Size"],
            "last_modified": o["LastModified"].isoformat(),
            "uri": f"s3://{s.minio_bucket}/{o['Key']}",
        }
        for o in resp.get("Contents", [])
    ]


def fetch_report(key: str, settings: Settings | None = None) -> dict[str, Any] | None:
    """Read one report back out of storage."""
    s = settings or get_settings()
    try:
        obj = get_client(s).get_object(Bucket=s.minio_bucket, Key=key)
        return json.loads(obj["Body"].read())
    except (BotoCoreError, ClientError, OSError, json.JSONDecodeError):
        return None
