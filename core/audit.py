"""Audit artifact persistence for TRACE.

Stores session logs/outputs in Parquet using Hive-style partitioning and keeps
an immutable SHA-256 pointer in SQLite. PyArrow is intentionally an optional
runtime dependency: installations that want the audit feature must install
it from requirements.txt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def _safe_partition(value: str) -> str:
    value = str(value)
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return value[:120] or "unknown"


def _target_hash(target: str) -> str:
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]


def write_session_artifact(
    *,
    root: str | Path,
    target: str,
    session_id: str,
    started_at: str,
    records: Iterable[dict],
) -> dict:
    """Write session records to one Hive-partitioned Parquet file.

    Returns a dict suitable for `audit_artifacts` persistence.
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError(
            "Auditoria Parquet requer pyarrow. Instale as dependências do TRACE (requirements.txt)."
        ) from exc

    rows = []
    now = datetime.now(timezone.utc).isoformat()
    for record in records:
        rows.append({
            "timestamp": str(record.get("timestamp") or now),
            "target": target,
            "session_id": session_id,
            "kind": str(record.get("kind", "event")),
            "event": str(record.get("event", "")),
            "payload_json": json.dumps(record.get("payload", {}), ensure_ascii=False, default=str),
        })

    if not rows:
        rows.append({
            "timestamp": now,
            "target": target,
            "session_id": session_id,
            "kind": "session",
            "event": "session_summary",
            "payload_json": json.dumps({}, ensure_ascii=False),
        })

    start_date = str(started_at)[:10] or datetime.now(timezone.utc).date().isoformat()
    partition_dir = (
        Path(root)
        / f"target_hash={_target_hash(target)}"
        / f"session_date={_safe_partition(start_date)}"
        / f"session_id={_safe_partition(session_id)}"
    )
    partition_dir.mkdir(parents=True, exist_ok=True)
    path = partition_dir / "session.parquet"

    table = pa.Table.from_pylist(rows)
    pq.write_table(table, path, compression="zstd")

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": str(path),
        "sha256": digest,
        "size_bytes": path.stat().st_size,
        "record_count": len(rows),
        "format": "parquet",
        "partitioning": "hive",
        "created_at": now,
    }
