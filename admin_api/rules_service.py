"""Rule validation (with the gateway's own Rule class), gateway push, views, and the
background sync that keeps the gateway in line with the database after restarts.

The database is the source of truth for rules created through the Admin API and for
the monitor/enforce mode. Rules that only exist in the gateway (its rule files, or
runtime rules pushed by someone else) are listed read-only."""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from gateway.apishield_gateway.rules import Rule as GatewayRule

from . import audit, metrics
from .db import iso, utcnow
from .errors import APIError
from .models import RuleRow, SettingsRow

log = logging.getLogger("apishield.admin.rules")
SYNC_SECONDS = 30.0


def normalize(data: dict) -> dict:
    """Validate a rule exactly as the gateway will, and return the gateway's canonical form
    (aliases such as require_auth resolved, unknown match keys dropped, name defaulted to id)."""
    try:
        return GatewayRule.from_dict(data).to_dict()
    except ValueError as exc:
        raise APIError(422, "invalid_rule", str(exc)) from None


def gateway_rule(row: RuleRow) -> dict:
    out = {"id": row.id, "name": row.name, "enabled": row.enabled, "match": row.match,
           "action": row.action, "source": row.source, "priority": row.priority}
    if row.expires_at:
        out["expires_at"] = row.expires_at
    if row.throttle:
        out["throttle"] = row.throttle
    return out


def _throttle_view(throttle: dict | None) -> dict | None:
    if not throttle:
        return None
    return {"limit": throttle.get("limit", 5), "per": throttle.get("per", 60)}


def rule_view(rule: dict, hits_24h: int, created_at=None, created_by: str = "") -> dict:
    out = {k: rule[k] for k in ("id", "name", "enabled", "match", "action", "source") if k in rule}
    out.setdefault("name", rule["id"])
    out.setdefault("enabled", True)
    out["source"] = rule.get("source") if rule.get("source") in ("builtin", "scanner", "analyst", "learner") \
        else "analyst"
    out["priority"] = rule.get("priority", 100)
    if rule.get("expires_at"):
        out["expires_at"] = str(rule["expires_at"])
    if _throttle_view(rule.get("throttle")):
        out["throttle"] = _throttle_view(rule["throttle"])
    out["hits_24h"] = hits_24h
    if created_at is not None:
        out["created_at"] = iso(created_at)
    if created_by:
        out["created_by"] = created_by
    return out


def row_view(row: RuleRow, hits: dict) -> dict:
    return rule_view(gateway_rule(row), hits.get(row.id, 0), row.created_at, row.created_by)


def hits_24h(session: Session, upstream_id: str) -> dict:
    from datetime import timedelta
    return metrics.rule_hits(session, upstream_id, utcnow() - timedelta(hours=24))


async def save_rule(session: Session, gateway, upstream_id: str, data: dict, actor: str,
                    audit_action: str, **audit_details) -> RuleRow:
    """Validate, push to the gateway, then persist and audit. If the gateway refuses or is
    unreachable, nothing is saved."""
    rule = normalize(data)
    row = session.get(RuleRow, rule["id"])
    if row is not None and row.upstream_id != upstream_id:
        raise APIError(409, "rule_exists", "A rule with this id exists on another upstream.")
    await gateway.upsert_rules([rule])
    if row is None:
        row = RuleRow(id=rule["id"], upstream_id=upstream_id, created_at=utcnow(), created_by=actor)
        session.add(row)
    row.name, row.enabled, row.match = rule["name"], rule["enabled"], rule["match"]
    row.action, row.source, row.priority = rule["action"], rule["source"], rule["priority"]
    row.expires_at, row.throttle = rule.get("expires_at"), rule.get("throttle") or None
    audit.record(session, actor, audit_action, "rule", rule["id"], action=rule["action"], **audit_details)
    session.commit()
    return row


async def gateway_only_rules(app, managed_ids: set) -> list:
    """Rules the gateway holds that the database does not (rule files, foreign pushes).
    Falls back to the last good list when the gateway is unreachable."""
    try:
        rules = await app.state.gateway.list_rules()
        app.state.gateway_rules_cache = rules
    except APIError:
        rules = getattr(app.state, "gateway_rules_cache", [])
    return [r for r in rules if r.get("id") not in managed_ids]


# ---- background sync ----------------------------------------------------------------

async def sync_gateway_once(app) -> bool:
    """Push the stored mode and any missing rules to the gateway. Returns True on success."""
    gateway = app.state.gateway
    with app.state.session_factory() as session:
        mode = session.get(SettingsRow, 1).mode
        rows = list(session.scalars(select(RuleRow)))
    try:
        health = await gateway.health()
        if health.get("mode") != mode:
            await gateway.set_mode(mode)
            log.info("gateway mode set to %s (from the Admin API database)", mode)
        live = await gateway.list_rules()
        app.state.gateway_rules_cache = live
        live_ids = {r.get("id") for r in live}
        missing = [gateway_rule(r) for r in rows if r.id not in live_ids]
        if missing:
            await gateway.upsert_rules(missing)
            log.info("pushed %d stored rules to the gateway", len(missing))
        return True
    except APIError as exc:
        log.warning("gateway sync skipped: %s", exc.code)
        return False


async def sync_loop(app) -> None:
    while True:
        await sync_gateway_once(app)
        await asyncio.sleep(SYNC_SECONDS)
