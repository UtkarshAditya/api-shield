"""Scans, findings, applying suggested rules, and the endpoint inventory (API map)."""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from gateway.apishield_gateway.ratelimit import path_pattern
from scanner.apishield_scanner.spec import load_spec, parse_endpoints

from .. import audit, metrics
from ..auth import current_user, require
from ..db import utcnow
from ..deps import get_gateway, get_session, upstream_id
from ..errors import APIError, not_found
from ..models import FindingRow, RuleRow, ScanRow, Upstream, User
from ..rules_service import save_rule
from ..scans import check_target, finding_view, report_html, scan_view

router = APIRouter()
MAX_SPEC_BYTES = 2_000_000
# Rules that stop the attack. A `log` rule (the scanner's fallback for findings the gateway
# cannot fix, such as missing headers) is still pushed, but the finding stays open.
MITIGATING_ACTIONS = ("block", "throttle", "challenge")


class ScanBody(BaseModel):
    upstream_id: str
    spec: str | None = None  # OpenAPI JSON or YAML text; default: the upstream's configured spec
    safe_mode: bool = True
    consent: bool = False


@router.post("/scans", status_code=202)
def start_scan(body: ScanBody, request: Request, session: Session = Depends(get_session),
               user: User = Depends(require("scans.run"))):
    if body.consent is not True:
        raise APIError(400, "consent_required", "Confirm that you own this API and agree to scan it.")
    if not body.safe_mode:
        raise APIError(422, "safe_mode_required",
                       "The scanner always runs in safe mode for now (run_scan has no safe_mode option).")
    upstream = session.get(Upstream, body.upstream_id)
    if upstream is None:
        raise not_found("Upstream")
    cfg = request.app.state.config
    check_target(upstream.url, cfg)
    if body.spec is not None and len(body.spec.encode()) > MAX_SPEC_BYTES:
        raise APIError(413, "spec_too_large", "The OpenAPI spec is larger than 2 MB.")
    if body.spec is None and not upstream.spec_path:
        raise APIError(422, "spec_required", "No OpenAPI spec is configured for this upstream; upload one.")
    running = session.scalar(select(ScanRow).where(ScanRow.upstream_id == upstream.id,
                                                   ScanRow.status.in_(("queued", "running"))).limit(1))
    if running is not None:
        raise APIError(409, "scan_in_progress", "A scan of this API is already running.")

    scan = ScanRow(id="sc_" + uuid.uuid4().hex[:12], upstream_id=upstream.id, status="queued", progress=0.0,
                   safe_mode=True, started_at=utcnow(), counts={}, endpoint_risk={}, created_by=user.email)
    session.add(scan)
    audit.record(session, user.email, "scan.start", "scan", scan.id, upstream_id=upstream.id, safe_mode=True,
                 consent=True, custom_spec=body.spec is not None)
    session.commit()
    request.app.state.scan_runner.submit(scan.id, upstream.url, upstream.spec_path, body.spec)
    return scan_view(scan)


@router.get("/scans")
def list_scans(limit: int = 50, offset: int = 0, up: str = Depends(upstream_id),
               session: Session = Depends(get_session), _user=Depends(current_user)):
    rows = list(session.scalars(select(ScanRow).where(ScanRow.upstream_id == up)
                                .order_by(ScanRow.started_at.desc())))
    return {"items": [scan_view(r) for r in rows[offset:offset + limit]], "total": len(rows)}


def _scan(session: Session, scan_id: str) -> ScanRow:
    row = session.get(ScanRow, scan_id)
    if row is None:
        raise not_found("Scan")
    return row


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, session: Session = Depends(get_session), _user=Depends(current_user)):
    return scan_view(_scan(session, scan_id))


@router.get("/scans/{scan_id}/findings")
def scan_findings(scan_id: str, limit: int = 100, offset: int = 0, session: Session = Depends(get_session),
                  _user=Depends(current_user)):
    _scan(session, scan_id)
    rows = list(session.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)
                                .order_by(FindingRow.risk_score.desc(), FindingRow.endpoint, FindingRow.scanner_id)))
    return {"items": [finding_view(r) for r in rows[offset:offset + limit]], "total": len(rows)}


@router.get("/scans/{scan_id}/report")
def scan_report(scan_id: str, format: Literal["json", "html"] = "json", session: Session = Depends(get_session),
                _user=Depends(current_user)):
    scan = _scan(session, scan_id)
    if scan.status != "done" or scan.report is None:
        raise APIError(409, "scan_not_finished", "The report is available once the scan is done.")
    if format == "html":
        return HTMLResponse(report_html(scan.report), headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "Content-Disposition": f'inline; filename="apishield-{scan_id}.html"'})
    return {"scan_id": scan.id, **scan.report}


@router.post("/findings/{finding_id}/apply-rule")
async def apply_rule(finding_id: str, session: Session = Depends(get_session),
                     user: User = Depends(require("rules.edit")), gateway=Depends(get_gateway)):
    finding = session.get(FindingRow, finding_id)
    if finding is None:
        raise not_found("Finding")
    if not finding.suggested_rule:
        raise APIError(409, "no_suggested_rule", "This finding has no suggested rule.")
    rule = {**finding.suggested_rule, "enabled": True}
    saved = await save_rule(session, gateway, finding.upstream_id, rule, user.email, "finding.apply_rule",
                            finding_id=finding.id, scan_id=finding.scan_id)
    if saved.action in MITIGATING_ACTIONS:
        finding.status = "mitigated"
    session.commit()
    return finding_view(finding)


# ---- endpoint inventory -------------------------------------------------------------------

def _rate_limited(method: str, path: str, rules: list) -> bool:
    for rule in rules:
        if not rule.enabled or rule.action != "throttle":
            continue
        m = rule.match or {}
        methods = m.get("method")
        if methods and method not in {str(x).upper() for x in ([methods] if isinstance(methods, str) else methods)}:
            continue
        if m.get("path") and not (m["path"] == path or path_pattern(str(m["path"])).match(path)):
            continue
        return True
    return False


@router.get("/endpoints")
def endpoints(up: str = Depends(upstream_id), session: Session = Depends(get_session), _user=Depends(current_user)):
    """API map: the spec's endpoints joined with traffic seen in the last 24 h. Observed but not
    in the spec = shadow. Rate-limited = an enabled throttle rule covers it (the gateway's own
    rate_limits in gateway.yaml are not visible to the Admin API)."""
    upstream = session.get(Upstream, up)
    spec_eps = {}
    try:
        spec_eps = {(e.method, e.path): e for e in parse_endpoints(load_spec(upstream.spec_path))} \
            if upstream.spec_path else {}
    except (OSError, ValueError):
        pass
    observed = metrics.endpoint_requests(session, up, utcnow() - timedelta(hours=24))
    risk = metrics.current_risk(session, up)["endpoint_risk"]
    rules = list(session.scalars(select(RuleRow).where(RuleRow.upstream_id == up)))
    items = []
    for method, path in sorted(set(spec_eps) | set(observed), key=lambda k: (k[1], k[0])):
        in_spec, seen = (method, path) in spec_eps, (method, path) in observed
        items.append({
            "method": method, "path": path,
            "source": "both" if in_spec and seen else ("spec" if in_spec else "observed"),
            "shadow": seen and not in_spec,
            "auth_required": bool(in_spec and spec_eps[(method, path)].requires_auth),
            "rate_limited": _rate_limited(method, path, rules),
            "risk_score": risk.get(path, 0.0),
            "requests_24h": observed.get((method, path), (0, 0))[0],
        })
    return {"items": items, "total": len(items)}
