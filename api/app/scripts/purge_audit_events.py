from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select

from app.db.session import AsyncSessionLocal
from app.models.audit_event import AuditEvent


def _get_retention_days() -> int:
    raw = os.getenv("AUDIT_LOG_RETENTION_DAYS", "90").strip()
    try:
        days = int(raw)
    except ValueError as exc:
        raise ValueError("AUDIT_LOG_RETENTION_DAYS must be an integer") from exc
    if days < 1:
        raise ValueError("AUDIT_LOG_RETENTION_DAYS must be >= 1")
    return days


def _is_dry_run() -> bool:
    raw = os.getenv("AUDIT_LOG_PURGE_DRY_RUN", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


async def main() -> None:
    retention_days = _get_retention_days()
    dry_run = _is_dry_run()
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    async with AsyncSessionLocal() as db:
        count_stmt = select(func.count()).select_from(AuditEvent).where(
            AuditEvent.created_at < cutoff
        )
        to_delete = (await db.execute(count_stmt)).scalar_one()

        if dry_run:
            print(
                f"[audit-retention] dry-run: would delete {to_delete} rows "
                f"older than {cutoff.isoformat()}"
            )
            return

        result = await db.execute(
            delete(AuditEvent).where(AuditEvent.created_at < cutoff)
        )
        await db.commit()

        deleted = result.rowcount if result.rowcount is not None else to_delete
        print(
            f"[audit-retention] deleted {deleted} rows "
            f"older than {cutoff.isoformat()}"
        )


if __name__ == "__main__":
    asyncio.run(main())

