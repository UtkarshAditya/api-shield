"""A fully populated Admin API (traffic with raw IPs and user subjects, a finished scan, an
applied rule, alerts) plus one call to every endpoint. Used by the privacy sweep and to
generate the frontend contract samples."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient

from admin_api.db import iso
from admin_api.main import create_app
from admin_api.models import AlertRow
from admin_api.routes.traffic import traffic_stream

from .conftest import FakeGateway, event, login, make_config
from .test_scans import FAKE_REPORT

RAW_IP = "203.0.113.77"
RAW_USER = "user_alice.smith"
RAW_VALUES = (RAW_IP, "alice.smith", "198.51.100.23")


def build():
    gateway = FakeGateway()
    app = create_app(make_config(), gateway_transport=httpx.MockTransport(gateway.handler),
                     scan_fn=lambda *a: FAKE_REPORT, run_background=False)
    now = datetime.now(timezone.utc)
    minute = now.replace(second=0, microsecond=0)  # whole minutes keep the row counts stable
    events = []
    for i in range(30):
        events.append(event(iso(minute), caller=RAW_USER, ip=RAW_IP, latency=10 + i))
        events.append(event(iso(minute - timedelta(minutes=70)), caller="ip_198.51.100.23",
                            ip="198.51.100.23", action="block", status=403, rule_hits=["builtin-sqli"]))
    app.state.ingestor.process(events)
    with app.state.session_factory() as s:  # an alert as a careless learner might write it
        s.add(AlertRow(id="al_raw", upstream_id="up_shop", ts=now, caller=f"ip_{RAW_IP}",
                       endpoint="GET /search", score=0.5, rank=6, severity="medium", status="new",
                       reasons=[{"feature": "Request rate", "observed": f"from {RAW_IP}", "baseline": RAW_USER}],
                       explanation=f"{RAW_USER} at {RAW_IP} is unusual"))
        s.commit()
    return app, gateway


def sse_event(app) -> str:
    """One message from /traffic/stream, carrying an event with a raw IP."""
    class FakeRequest:
        def __init__(self):
            self.app = app

        async def is_disconnected(self):
            return False

    async def run():
        resp = await traffic_stream(FakeRequest(), up="up_shop", ingestor=app.state.ingestor, _user=None)
        it = resp.body_iterator
        await it.__anext__()
        ing = app.state.ingestor
        ing.publish(ing.process([event(iso(datetime.now(timezone.utc)), caller=RAW_USER, ip=RAW_IP)]))
        message = await it.__anext__()
        await it.aclose()
        return message
    return asyncio.run(run())


def call_everything(app, gateway) -> dict:
    """name -> (status, parsed body or text). Order matters: later calls depend on earlier ones."""
    out: dict = {}
    q = "?upstream_id=up_shop"
    with TestClient(app) as c:
        def rec(name, resp):
            try:
                out[name] = (resp.status_code, resp.json())
            except ValueError:
                out[name] = (resp.status_code, resp.text)
            return resp

        login_resp = rec("auth_login", c.post("/api/auth/login", json={"email": "admin@demo.local", "password": "demo"}))
        admin = {"Authorization": f"Bearer {login_resp.json()['token']}"}
        analyst, viewer = login(c, "analyst"), login(c, "viewer")

        rec("me", c.get("/api/me", headers=admin))
        rec("upstreams", c.get("/api/upstreams", headers=viewer))
        rec("settings", c.get("/api/settings", headers=viewer))
        for r in ("1h", "24h", "7d"):
            rec(f"metrics_summary_{r}", c.get(f"/api/metrics/summary{q}&range={r}", headers=viewer))
            rec(f"metrics_timeseries_{r}", c.get(f"/api/metrics/timeseries{q}&range={r}", headers=viewer))
        rec("traffic_recent", c.get(f"/api/traffic/recent{q}&limit=20", headers=viewer))

        scan = rec("scan_start", c.post("/api/scans", json={"upstream_id": "up_shop", "consent": True}, headers=analyst))
        app.state.scan_runner.futures[scan.json()["id"]].result(timeout=30)
        sid = scan.json()["id"]
        rec("scans", c.get(f"/api/scans{q}", headers=viewer))
        rec("scan", c.get(f"/api/scans/{sid}", headers=viewer))
        findings = rec("scan_findings", c.get(f"/api/scans/{sid}/findings", headers=viewer)).json()["items"]
        rec("scan_report_json", c.get(f"/api/scans/{sid}/report?format=json", headers=viewer))
        rec("scan_report_html", c.get(f"/api/scans/{sid}/report?format=html", headers=viewer))
        fid = next(f["id"] for f in findings if f.get("suggested_rule"))
        rec("finding_apply_rule", c.post(f"/api/findings/{fid}/apply-rule", headers=analyst))
        rec("endpoints", c.get(f"/api/endpoints{q}", headers=viewer))

        rec("rule_create", c.post(f"/api/rules{q}", headers=analyst, json={
            "id": "block-admin-writes", "match": {"path": "/admin/*", "method": ["POST", "DELETE"],
                                                  "ip": ["10.0.0.0/8"]}, "action": "block"}))
        rec("rule_patch", c.patch(f"/api/rules/block-admin-writes{q}", json={"enabled": False}, headers=analyst))
        rec("rules", c.get(f"/api/rules{q}", headers=viewer))
        rec("rules_test", c.post("/api/rules/test", headers=viewer, json={
            "rule": {"match": {"path": "/search", "signature": "sqli"}, "action": "block"},
            "request": {"method": "GET", "path": "/search", "query": {"q": "1 UNION SELECT password FROM users"}}}))

        rec("alerts", c.get(f"/api/alerts{q}&sort=rank", headers=viewer))
        rec("alert", c.get("/api/alerts/al_raw", headers=viewer))
        rec("alert_patch_acknowledged", c.patch("/api/alerts/al_1002", json={"status": "acknowledged"}, headers=analyst))
        rec("alert_patch_false_positive", c.patch("/api/alerts/al_raw", json={"status": "false_positive"},
                                                  headers=analyst))
        rec("alert_promote", c.post(f"/api/alerts/al_1001/promote-to-rule{q}", headers=analyst))
        rec("learning_status", c.get(f"/api/learning/status{q}", headers=viewer))
        rec("learning_patch", c.patch(f"/api/learning{q}", json={"sensitivity": 0.7}, headers=admin))
        rec("learning_reset", c.post(f"/api/learning/reset{q}", headers=admin))
        rec("settings_patch", c.patch("/api/settings", json={"mode": "enforce"}, headers=admin))
        rec("audit_log", c.get("/api/audit-log", headers=admin))
        rec("privacy_purge", c.post(f"/api/privacy/purge{q}", headers=admin))

        rec("error_401", c.get("/api/me"))
        rec("error_403", c.patch("/api/settings", json={"mode": "monitor"}, headers=viewer))
        rec("error_404", c.get("/api/alerts/nope", headers=viewer))
        rec("error_422", c.get(f"/api/metrics/summary{q}&range=1y", headers=viewer))
        gateway.down = True
        rec("error_502", c.patch("/api/settings", json={"mode": "monitor"}, headers=admin))
        gateway.down = False

        def boom(*a):
            raise RuntimeError(f"target {RAW_IP} unreachable")
        app.state.scan_runner.scan_fn = boom
        failed = c.post("/api/scans", json={"upstream_id": "up_shop", "consent": True}, headers=analyst).json()
        app.state.scan_runner.futures[failed["id"]].result(timeout=30)
        rec("scan_failed", c.get(f"/api/scans/{failed['id']}", headers=viewer))

    out["traffic_stream_event"] = (200, json.loads(sse_event(app).split("data: ", 1)[1]))
    return out
