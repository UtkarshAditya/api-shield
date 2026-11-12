"""Alerts and learning. The learner (M3) writes `alerts` and `learning_state`; the Admin API
reads them, records analyst feedback in `alert_feedback`, and promotes alerts to rules."""
from __future__ import annotations

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..auth import current_user, require
from ..db import iso, utcnow
from ..deps import get_config, get_gateway, get_session, upstream_id
from ..errors import APIError, not_found
from ..masking import mask_text, pseudonymize_text, safe_caller
from ..models import AlertFeedback, AlertRow, LearningState, User
from ..rules_service import hits_24h, row_view, save_rule

router = APIRouter()
ALERT_STATUSES = ("new", "acknowledged", "true_positive", "false_positive")
# CONTRACT-TBD (M3, Q14): placeholder until the learner owns threshold math. The learner reads
# alert_feedback rows and applies its own adjustment; this is what the UI shows meanwhile.
FALSE_POSITIVE_DELTA = 0.1


def alert_view(row: AlertRow, salt: str) -> dict:
    """Alerts are written by the learner, so caller ids and free text are checked again here:
    raw `ip_`/`user_` values are pseudonymized, and secrets or PII in text are masked."""
    def text(value) -> str:
        return mask_text(pseudonymize_text(str(value), salt))
    reasons = [{k: (text(v) if isinstance(v, str) else v) for k, v in r.items()} for r in (row.reasons or [])]
    out = {"id": row.id, "ts": iso(row.ts), "caller": safe_caller(row.caller, salt),
           "endpoint": mask_text(row.endpoint), "score": row.score, "rank": row.rank, "severity": row.severity,
           "reasons": reasons, "explanation": text(row.explanation), "status": row.status}
    if row.group_id:
        out["group_id"] = row.group_id
    if row.timeline:
        out["timeline"] = row.timeline
    return out


def _alert(session: Session, alert_id: str, up: str | None = None) -> AlertRow:
    row = session.get(AlertRow, alert_id)
    if row is None or (up is not None and row.upstream_id != up):
        raise not_found("Alert")
    return row


@router.get("/alerts")
def list_alerts(status: str | None = None, severity: str | None = None,
                sort: Literal["rank", "ts", "score"] = "rank", limit: int = 50, offset: int = 0,
                up: str = Depends(upstream_id), session: Session = Depends(get_session), _user=Depends(current_user),
                cfg=Depends(get_config)):
    query = select(AlertRow).where(AlertRow.upstream_id == up)
    if status:
        wanted = ("new", "acknowledged") if status == "active" else tuple(status.split(","))
        query = query.where(AlertRow.status.in_(wanted))
    if severity:
        query = query.where(AlertRow.severity.in_(severity.split(",")))
    order = {"rank": AlertRow.rank.asc(), "ts": AlertRow.ts.desc(), "score": AlertRow.score.desc()}[sort]
    rows = list(session.scalars(query.order_by(order)))
    return {"items": [alert_view(r, cfg.pseudo_salt) for r in rows[offset:offset + limit]], "total": len(rows)}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, session: Session = Depends(get_session), _user=Depends(current_user),
              cfg=Depends(get_config)):
    return alert_view(_alert(session, alert_id), cfg.pseudo_salt)


class AlertPatch(BaseModel):
    status: Literal["new", "acknowledged", "true_positive", "false_positive"]


def _top_feature(row: AlertRow) -> str:
    reasons = row.reasons or []
    if not reasons:
        return "score"
    return max(reasons, key=lambda r: r.get("z") or 0).get("feature", "score")


@router.patch("/alerts/{alert_id}")
def patch_alert(alert_id: str, body: AlertPatch, session: Session = Depends(get_session),
                user: User = Depends(require("alerts.triage")), cfg=Depends(get_config)):
    row = _alert(session, alert_id)
    previous, row.status = row.status, body.status
    adjustment = None
    if body.status in ("true_positive", "false_positive"):
        feedback = AlertFeedback(alert_id=row.id, verdict=body.status, created_by=user.email)
        if body.status == "false_positive":
            adjustment = {"feature": _top_feature(row), "threshold_delta": FALSE_POSITIVE_DELTA}
            feedback.feature, feedback.threshold_delta = adjustment["feature"], adjustment["threshold_delta"]
        session.add(feedback)
    audit.record(session, user.email, "alert.feedback", "alert", row.id, **{"from": previous, "to": body.status})
    session.commit()
    return {"alert": alert_view(row, cfg.pseudo_salt), "adjustment": adjustment}


class PromoteBody(BaseModel):
    action: Literal["log", "block", "throttle", "challenge"] = "throttle"
    limit: int = Field(default=10, ge=1)
    per: int = Field(default=60, ge=1)


@router.post("/alerts/{alert_id}/promote-to-rule", status_code=201)
async def promote_alert(alert_id: str, body: PromoteBody = Body(default_factory=PromoteBody),
                        up: str = Depends(upstream_id), session: Session = Depends(get_session),
                        user: User = Depends(require("rules.edit")), gateway=Depends(get_gateway)):
    """Turns an alert into a gateway rule on its endpoint. Only API-key callers can be targeted
    individually: `ip_`/`user_` ids are pseudonyms, and the raw value is never stored."""
    row = _alert(session, alert_id, up)
    method, _, path = row.endpoint.partition(" ")
    if not path:
        raise APIError(422, "invalid_alert", "This alert has no endpoint to build a rule from.")
    match = {"path": path, "method": method}
    if row.caller.startswith("key_") and safe_caller(row.caller, "") == row.caller:
        match["condition"] = f"caller == '{row.caller}'"
    rule = {"id": f"alert-{row.id}", "name": f"From alert {row.id}: {row.endpoint}", "match": match,
            "action": body.action, "source": "analyst"}
    if body.action == "throttle":
        rule["throttle"] = {"limit": body.limit, "per": body.per}
    saved = await save_rule(session, gateway, up, rule, user.email, "rule.create", from_alert=row.id)
    return row_view(saved, hits_24h(session, up))


# ---- learning --------------------------------------------------------------------------

def learning_view(row: LearningState) -> dict:
    out = {"mode": row.mode, "progress": round(min(max(row.progress, 0.0), 1.0), 3),
           "started_at": iso(row.started_at), "endpoints_learned": row.endpoints_learned,
           "shapes_learned": row.shapes_learned, "sensitivity": row.sensitivity}
    if row.ends_at:
        out["ends_at"] = iso(row.ends_at)
    return out


def _learning(session: Session, up: str) -> LearningState:
    row = session.get(LearningState, up)
    if row is None:
        row = LearningState(upstream_id=up, mode="warmup", progress=0.0, started_at=utcnow())
        session.add(row)
        session.flush()
    return row


@router.get("/learning/status")
def learning_status(up: str = Depends(upstream_id), session: Session = Depends(get_session),
                    _user=Depends(current_user)):
    return learning_view(_learning(session, up))


class LearningPatch(BaseModel):
    mode: Literal["active", "disabled"] | None = None
    sensitivity: float | None = Field(default=None, ge=0, le=1)


@router.patch("/learning")
def patch_learning(body: LearningPatch, up: str = Depends(upstream_id), session: Session = Depends(get_session),
                   user: User = Depends(require("settings.edit"))):
    row = _learning(session, up)
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(row, key, value)
    audit.record(session, user.email, "learning.update", "learning", up, **changes)
    session.commit()
    return learning_view(row)


@router.post("/learning/reset")
def reset_learning(up: str = Depends(upstream_id), session: Session = Depends(get_session),
                   user: User = Depends(require("settings.edit"))):
    """Restarts warm-up. The learner sees reset_requested_at and drops its baselines."""
    row = _learning(session, up)
    now = utcnow()
    row.mode, row.progress, row.started_at, row.ends_at = "warmup", 0.0, now, now + timedelta(days=1)
    row.endpoints_learned = row.shapes_learned = 0
    row.reset_requested_at = now
    audit.record(session, user.email, "learning.reset", "learning", up)
    session.commit()
    return learning_view(row)
