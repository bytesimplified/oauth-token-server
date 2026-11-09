"""Retention and expired-token cleanup; call from a trusted scheduled job."""
import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from .db import AuditEvent, RevokedToken, SessionLocal, init_db


def run_retention(days: int) -> dict:
    if not 1 <= days <= 3650:
        raise ValueError("Retention days must be 1..3650")
    init_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with SessionLocal.begin() as session:
        revoked = session.execute(delete(RevokedToken).where(RevokedToken.expires_at < datetime.now(timezone.utc)))
        audit = session.execute(delete(AuditEvent).where(AuditEvent.created_at < cutoff))
    return {"expired_revocations_removed": revoked.rowcount, "audit_events_removed": audit.rowcount}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-retention-days", type=int, default=90)
    args = parser.parse_args()
    print(run_retention(args.audit_retention_days))
