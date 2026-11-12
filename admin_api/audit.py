"""Audit trail: every rule change, mode change, scan start, alert feedback and purge."""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from .db import iso
from .models import AuditRow


def record(session: Session, actor: str, event: str, target_type: str,
           target_id: str | None = None, **details) -> AuditRow:
    """Adds an entry to the session; the caller commits it together with the change."""
    row = AuditRow(id="au_" + uuid.uuid4().hex[:12], actor=actor, action=event,
                   target_type=target_type, target_id=target_id, details=details)
    session.add(row)
    return row


def audit_view(row: AuditRow) -> dict:
    out = {"id": row.id, "ts": iso(row.ts), "actor": row.actor, "action": row.action,
           "target_type": row.target_type, "details": row.details or {}}
    if row.target_id:
        out["target_id"] = row.target_id
    return out
