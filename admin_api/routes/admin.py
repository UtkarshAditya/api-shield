"""Audit log, data purge, and the demo helpers (alert replay, rehearsal reset)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import audit, demo_alerts, seed
from ..auth import require
from ..db import iso, utcnow
from ..deps import get_config, get_ingestor, get_session, upstream_id
from ..errors import APIError
from ..models import AlertFeedback, AlertRow, AuditRow, FindingRow, ScanRow, User

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


@router.post("/demo/alerts/replay")
def demo_alerts_replay(request: Request, up: str = Depends(upstream_id), session: Session = Depends(get_session),
                       user: User = Depends(require("settings.edit")), ingestor=Depends(get_ingestor)):
    """Stand-in for the learner (M3): turns callers that stand out in the recent traffic into
    alerts, marked as demo replay. Idempotent: running it again updates the same alerts."""
    result = demo_alerts.run_once(request.app.state.session_factory, ingestor, up)
    audit.record(session, user.email, "alerts.demo_replay", "alerts", up, created=result["created"],
                 updated=result["updated"])
    session.commit()
    return result


@router.post("/demo/reset")
def demo_reset(up: str = Depends(upstream_id), session: Session = Depends(get_session),
               user: User = Depends(require("settings.edit")), ingestor=Depends(get_ingestor),
               cfg=Depends(get_config)):
    """Rehearsal reset (scripts/demo_reset.py), only with DEMO_SEED=true: deletes scans,
    findings, and every alert of the upstream with its feedback (learner, demo-replay and canned
    alerts), re-seeds the canned demo alerts with fresh times only when ADMIN_SEED_ALERTS=true,
    and forgets buffered events (so the replay does not rebuild the last burst's alerts).
    The learner's baseline (learner_baselines) and learning_state are kept, so warm-up is not
    redone. Users, settings, rules, traffic counts and the audit log are kept too; the script
    switches the mode and deletes rules through the normal routes so the gateway stays in sync."""
    if not cfg.demo_seed:
        raise APIError(409, "demo_only", "Demo reset is only available when DEMO_SEED=true.")
    findings = session.execute(delete(FindingRow).where(FindingRow.upstream_id == up)).rowcount
    scans = session.execute(delete(ScanRow).where(ScanRow.upstream_id == up)).rowcount
    alert_ids = select(AlertRow.id).where(AlertRow.upstream_id == up)
    feedback = session.execute(delete(AlertFeedback).where(AlertFeedback.alert_id.in_(alert_ids))).rowcount
    alerts = session.execute(delete(AlertRow).where(AlertRow.upstream_id == up)).rowcount
    seeded = seed._demo_alerts(up) if cfg.seed_alerts else []
    session.add_all(seeded)
    events = ingestor.forget_recent(up)
    audit.record(session, user.email, "demo.reset", "upstream", up, scans=scans, findings=findings,
                 feedback=feedback, alerts=alerts, buffered_events=events)
    session.commit()
    return {"scans": scans, "findings": findings, "feedback": feedback, "alerts_removed": alerts,
            "alerts_seeded": len(seeded), "buffered_events": events}
