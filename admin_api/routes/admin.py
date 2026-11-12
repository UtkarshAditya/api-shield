"""Audit log and data purge."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..auth import require
from ..db import iso, utcnow
from ..deps import get_ingestor, get_session, upstream_id
from ..models import AuditRow, User

router = APIRouter()


@router.get("/audit-log")
def audit_log(action: str | None = None, limit: int = 100, offset: int = 0,
              session: Session = Depends(get_session), _user=Depends(require("settings.edit"))):
    query = select(AuditRow)
    if action:
        query = query.where(AuditRow.action == action)
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.scalars(query.order_by(AuditRow.ts.desc()).offset(offset).limit(limit))
    return {"items": [audit.audit_view(r) for r in rows], "total": total}


@router.post("/privacy/purge")
def purge(up: str = Depends(upstream_id), session: Session = Depends(get_session),
          user: User = Depends(require("data.purge")), ingestor=Depends(get_ingestor)):
    """Deletes stored traffic aggregates and buffered events. Rules, scans, alerts and the
    audit log are kept (the purge itself is audited)."""
    recent, rows = ingestor.purge(up)
    audit.record(session, user.email, "data.purge", "traffic", up, recent_events=recent, aggregate_rows=rows)
    session.commit()
    return {"purged_at": iso(utcnow()), "recent_events": recent, "aggregate_rows": rows}
