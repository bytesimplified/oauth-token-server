"""Audit-backed per-client volume and hourly trends without exposing secrets."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .admin_auth import require_admin
from .db import AuditEvent, get_db

router = APIRouter(prefix="/admin", tags=["analytics"])


@router.get("/analytics", dependencies=[Depends(require_admin("viewer"))])
def analytics(hours: int = Query(24, ge=1, le=168), db: Session = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    # Both dialects aggregate in SQL to avoid scanning full audit logs into memory.
    if db.bind.dialect.name == "postgresql":
        bucket = func.to_char(func.date_trunc("hour", AuditEvent.created_at), 'YYYY-MM-DD"T"HH24:00:00')
    else:
        bucket = func.strftime("%Y-%m-%dT%H:00:00", AuditEvent.created_at)
    stmt = (
        select(bucket.label("hour"), AuditEvent.client_id, AuditEvent.event, func.count().label("count"))
        .where(AuditEvent.created_at >= since)
        .where(AuditEvent.event.in_(("token.issued", "token.denied")))
        .group_by(bucket, AuditEvent.client_id, AuditEvent.event)
        .order_by(bucket.desc())
        .limit(5000)
    )
    rows = db.execute(stmt).all()
    return {
        "window_hours": hours,
        "hourly": [{"hour": hour, "client_id": client_id, "event": event, "count": count}
                   for hour, client_id, event, count in rows],
        "truncated": len(rows) == 5000,
    }
