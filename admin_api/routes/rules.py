"""Rules: list, create, update, delete, and the rule tester."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from gateway.apishield_gateway.context import RequestContext
from gateway.apishield_gateway.normalize import NormalizeStage
from gateway.apishield_gateway.rules import Rule as GatewayRule

from .. import audit
from ..auth import current_user, require
from ..deps import get_gateway, get_session, upstream_id
from ..errors import APIError, not_found
from ..models import RuleRow, User
from ..rules_service import gateway_only_rules, hits_24h, normalize, row_view, rule_view, save_rule

router = APIRouter()
RULE_ID = r"^[A-Za-z0-9._-]{1,128}$"


class RuleBody(BaseModel):
    id: str = Field(pattern=RULE_ID)
    name: str | None = None
    enabled: bool = True
    match: dict[str, Any]
    action: str
    source: str = "analyst"
    expires_at: str | None = None
    priority: int | None = None
    throttle: dict[str, float] | None = None


class RulePatch(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    match: dict[str, Any] | None = None
    action: str | None = None
    expires_at: str | None = None
    priority: int | None = None
    throttle: dict[str, float] | None = None


def _rule_dict(body: BaseModel) -> dict:
    data = body.model_dump(exclude_none=True)
    if data.get("throttle"):
        data["throttle"] = {k: int(v) if float(v).is_integer() else v for k, v in data["throttle"].items()}
    return data


@router.get("/rules")
async def list_rules(request: Request, limit: int = 200, offset: int = 0, up: str = Depends(upstream_id),
                     session: Session = Depends(get_session), _user=Depends(current_user)):
    hits = hits_24h(session, up)
    rows = list(session.scalars(select(RuleRow).where(RuleRow.upstream_id == up)))
    items = [row_view(r, hits) for r in rows]
    managed = set(session.scalars(select(RuleRow.id)))
    items += [rule_view(r, hits.get(r.get("id"), 0)) for r in await gateway_only_rules(request.app, managed)]
    items.sort(key=lambda r: (r["priority"], r["id"]))
    return {"items": items[offset:offset + limit], "total": len(items)}


@router.post("/rules", status_code=201)
async def create_rule(body: RuleBody, request: Request, up: str = Depends(upstream_id),
                      session: Session = Depends(get_session), user: User = Depends(require("rules.edit")),
                      gateway=Depends(get_gateway)):
    if session.get(RuleRow, body.id) is not None or any(
            r.get("id") == body.id for r in getattr(request.app.state, "gateway_rules_cache", [])):
        raise APIError(409, "rule_exists", "A rule with this id already exists.")
    data = _rule_dict(body)
    if data.get("source") == "builtin":
        raise APIError(422, "invalid_rule", "Built-in rules live in the gateway's rule files.")
    row = await save_rule(session, gateway, up, data, user.email, "rule.create")
    return row_view(row, hits_24h(session, up))


def _managed_row(request: Request, session: Session, rule_id: str, up: str) -> RuleRow:
    row = session.get(RuleRow, rule_id)
    if row is None or row.upstream_id != up:
        if any(r.get("id") == rule_id for r in getattr(request.app.state, "gateway_rules_cache", [])):
            raise APIError(409, "rule_read_only", "This rule comes from the gateway's rule files. Edit it there.")
        raise not_found("Rule")
    return row


@router.patch("/rules/{rule_id}")
async def update_rule(rule_id: str, body: RulePatch, request: Request, up: str = Depends(upstream_id),
                      session: Session = Depends(get_session), user: User = Depends(require("rules.edit")),
                      gateway=Depends(get_gateway)):
    row = _managed_row(request, session, rule_id, up)
    patch = _rule_dict(body)
    current = {"id": row.id, "name": row.name, "enabled": row.enabled, "match": row.match,
               "action": row.action, "source": row.source, "priority": row.priority,
               "expires_at": row.expires_at, "throttle": row.throttle}
    merged = {k: v for k, v in {**current, **patch}.items() if v is not None}
    row = await save_rule(session, gateway, up, merged, user.email, "rule.update", fields=sorted(patch))
    return row_view(row, hits_24h(session, up))


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, request: Request, up: str = Depends(upstream_id),
                      session: Session = Depends(get_session), user: User = Depends(require("rules.edit")),
                      gateway=Depends(get_gateway)):
    row = _managed_row(request, session, rule_id, up)
    await gateway.delete_rule(rule_id)
    session.delete(row)
    audit.record(session, user.email, "rule.delete", "rule", rule_id)
    session.commit()
    return Response(status_code=204)


# ---- rule tester -----------------------------------------------------------------------

class SampleRequest(BaseModel):
    method: str = "GET"
    path: str = "/"
    query: dict[str, str] | str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    authenticated: bool = False


class RuleTestBody(BaseModel):
    rule: dict[str, Any]
    request: SampleRequest


_FIELD_LABELS = {"path": "path", "method": "method", "ip": "IP range", "header": "headers",
                 "signature": "attack signature", "condition": "condition"}


async def _context(sample: SampleRequest) -> RequestContext:
    query = sample.query if isinstance(sample.query, str) else urlencode(sample.query or {})
    headers = {k.lower(): v for k, v in sample.headers.items()}
    body = b""
    if sample.body is not None:
        body = sample.body.encode() if isinstance(sample.body, str) else json.dumps(sample.body).encode()
        headers.setdefault("content-type", "application/json")
    ctx = RequestContext(method=sample.method, raw_path=sample.path.split("?", 1)[0], query_string=query,
                         headers=headers, ip="198.51.100.10", body=body)
    await NormalizeStage(lambda: None).on_request(ctx)
    ctx.authenticated = sample.authenticated
    return ctx


@router.post("/rules/test")
async def test_rule(body: RuleTestBody, _user=Depends(current_user)):
    """Evaluates the rule against a sample request with the gateway's own matcher.
    Nothing is stored or sent to the gateway."""
    rule_data = {"id": "rule-under-test", **body.rule}
    rule = GatewayRule.from_dict(normalize(rule_data))
    ctx = await _context(body.request)
    matched = rule.matches(ctx)
    failed = []
    for key, value in rule.match.items():
        single = GatewayRule.from_dict({"id": "part", "action": "log", "match": {key: value}})
        if not single.matches(ctx):
            failed.append(_FIELD_LABELS.get(key, key))
    name = rule.name if rule.name != "rule-under-test" else "this rule"
    if not rule.enabled:
        explanation = f"The request matches, but {name} is disabled, so it would not apply." if matched \
            else f"{name.capitalize()} is disabled and the request does not match it anyway."
        return {"matched": matched, "action": None, "explanation": explanation}
    if matched:
        effect = {"allow": "let it through and skip the remaining rules", "log": "record it and let it through",
                  "block": "block it with 403", "throttle": "rate-limit this caller (429 when over the limit)",
                  "challenge": "ask for credentials (401) unless the caller is authenticated"}[rule.action]
        if rule.action == "challenge" and ctx.authenticated:
            effect = "let it through, because the caller is authenticated"
        explanation = f"The request matches every condition of {name}, so the gateway would {effect}."
        return {"matched": True, "action": rule.action, "explanation": explanation}
    return {"matched": False, "action": None,
            "explanation": f"The request does not match {name}: the {', '.join(failed) or 'rule'} "
                           f"did not match, so this rule would not change how it is handled."}
