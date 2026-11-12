import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from admin_api.main import create_app
from admin_api.models import AuditRow

from .conftest import login, make_config

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
FAKE_REPORT = {
    "target": "http://localhost:8001",
    "generated_at": "2026-11-12T10:00:00+00:00",
    "api_risk_score": 7.3,
    "endpoint_risk": {"/search": 8.0, "/login": 3.6, "/debug": 3.6},
    "findings": [
        {"id": "sqli-get-q", "endpoint": "/search", "method": "GET",
         "owasp_cat": "API8:2023 Security Misconfiguration (Injection)", "title": "Possible SQL injection via 'q'",
         "severity": "critical", "risk_score": 8.0, "risk_band": "high",
         "evidence": {"payload": "' OR '1'='1", "status_code": 200, "signal": "result_count_changed",
                      "response_snippet": '{"results":[{"email":"alice@example.com","ip":"203.0.113.7"}]}'},
         "fix": "Use parameterized queries.",
         "suggested_rule": {"id": "rule-block-sqli-q", "match": {"path": "/search", "method": "GET"},
                            "action": "block", "pattern": "sql_injection", "source": "scanner"}},
        {"id": "rate-limit-login", "endpoint": "/login", "method": "POST",
         "owasp_cat": "API4:2023 Unrestricted Resource Consumption", "title": "No rate limit on login",
         "severity": "high", "risk_score": 3.6, "risk_band": "low",
         "evidence": {"requests_sent": 25, "got_429": False}, "fix": "Add a rate limit.",
         "suggested_rule": {"id": "rule-ratelimit-login", "match": {"path": "/login", "method": "POST"},
                            "action": "rate_limit", "limit": "5/min", "source": "scanner"}},
        {"id": "secrets-debug", "endpoint": "/debug", "method": "GET", "owasp_cat": "API8:2023 Security Misconfiguration",
         "title": "Secrets in response", "severity": "high", "risk_score": 3.6, "risk_band": "low",
         "evidence": {"secrets_found": True, "verbose_error": True,
                      "response_snippet": f"token={JWT} <script>alert(1)</script>"},
         "fix": "Remove debug output.", "suggested_rule": None},
    ],
}


def _fake_scan(calls):
    def scan(spec_path, target, username, password, out_prefix):
        calls.append({"spec_path": spec_path, "target": target, "out_prefix": out_prefix})
        return FAKE_REPORT
    return scan


@pytest.fixture
def scan_env(gateway):
    calls: list = []
    app = create_app(make_config(), gateway_transport=httpx.MockTransport(gateway.handler),
                     scan_fn=_fake_scan(calls), run_background=False)
    with TestClient(app) as client:
        yield app, client, calls


def _start(client, headers, **body):
    return client.post("/api/scans", json={"upstream_id": "up_shop", "consent": True, **body}, headers=headers)


def _wait(app, scan_id):
    app.state.scan_runner.futures[scan_id].result(timeout=60)


def test_consent_is_required(scan_env):
    app, client, calls = scan_env
    h = login(client, "analyst")
    resp = client.post("/api/scans", json={"upstream_id": "up_shop"}, headers=h)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "consent_required"
    assert _start(client, h, consent=False).status_code == 400
    assert calls == []


def test_viewer_cannot_scan(scan_env):
    _app, client, _ = scan_env
    assert _start(client, login(client, "viewer")).status_code == 403


def test_non_localhost_target_refused(gateway):
    app = create_app(make_config(upstream_url="http://shop.example.com:8001"),
                     gateway_transport=httpx.MockTransport(gateway.handler), scan_fn=_fake_scan([]),
                     run_background=False)
    with TestClient(app) as client:
        resp = _start(client, login(client, "admin"))
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "scan_refused"
    assert "shop.example.com" in resp.json()["error"]["message"]


def test_extra_allowed_host_from_config(gateway):
    calls = []
    app = create_app(make_config(upstream_url="http://demo-api:8001", scan_allowed_hosts=["demo-api"]),
                     gateway_transport=httpx.MockTransport(gateway.handler), scan_fn=_fake_scan(calls),
                     run_background=False)
    with TestClient(app) as client:
        resp = _start(client, login(client, "admin"))
        _wait(app, resp.json()["id"])
    assert calls[0]["target"] == "http://demo-api:8001"


def test_unsafe_mode_refused(scan_env):
    _app, client, _ = scan_env
    resp = _start(client, login(client, "admin"), safe_mode=False)
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "safe_mode_required"


def test_scan_runs_in_background_and_maps_findings(scan_env):
    app, client, calls = scan_env
    h = login(client, "analyst")
    resp = _start(client, h)
    assert resp.status_code == 202
    scan = resp.json()
    assert scan["status"] in ("queued", "running", "done") and scan["counts"]["critical"] == 0
    _wait(app, scan["id"])
    done = client.get(f"/api/scans/{scan['id']}", headers=h).json()
    assert done["status"] == "done" and done["progress"] == 1 and "finished_at" in done
    assert done["counts"] == {"critical": 0, "high": 1, "medium": 0, "low": 2, "info": 0}
    assert done["api_risk_score"] == 7.3
    assert calls[0]["target"] == "http://localhost:8001" and calls[0]["spec_path"].endswith("openapi.json")

    findings = client.get(f"/api/scans/{scan['id']}/findings", headers=h).json()["items"]
    by_id = {f["endpoint"]: f for f in findings}
    sqli = by_id["/search"]
    assert sqli["severity"] == "high"  # risk_band, not the scanner's own severity
    assert sqli["status"] == "open" and sqli["scan_id"] == scan["id"]
    assert sqli["suggested_rule"]["match"] == {"path": "/search", "method": "GET", "signature": "sqli"}
    assert sqli["suggested_rule"]["hits_24h"] == 0
    assert sqli["evidence"]["request"] == "GET /search with payload ' OR '1'='1"
    login_rule = by_id["/login"]["suggested_rule"]
    assert login_rule["action"] == "throttle" and login_rule["throttle"] == {"limit": 5, "per": 60}
    assert by_id["/login"]["evidence"] == {"request": "POST /login ×25", "response": "never 429"}
    assert "suggested_rule" not in by_id["/debug"]


def test_evidence_and_report_are_masked(scan_env):
    app, client, _ = scan_env
    h = login(client, "analyst")
    scan_id = _start(client, h).json()["id"]
    _wait(app, scan_id)
    texts = [client.get(f"/api/scans/{scan_id}/findings", headers=h).text,
             client.get(f"/api/scans/{scan_id}/report?format=json", headers=h).text]
    html = client.get(f"/api/scans/{scan_id}/report?format=html", headers=h)
    texts.append(html.text)
    for text in texts:
        for raw in ("alice@example.com", "203.0.113.7", JWT):
            assert raw not in text
    assert "<script>" not in html.text
    assert "sandbox" in html.headers["content-security-policy"]


def test_one_scan_at_a_time_and_audit(scan_env):
    app, client, _ = scan_env
    h = login(client, "analyst")
    gate = threading.Event()
    app.state.scan_runner.scan_fn = lambda *a: (gate.wait(5), FAKE_REPORT)[1]
    first = _start(client, h).json()
    second = _start(client, h)
    assert second.status_code == 409 and second.json()["error"]["code"] == "scan_in_progress"
    gate.set()
    _wait(app, first["id"])
    with app.state.session_factory() as s:
        assert s.query(AuditRow).filter_by(action="scan.start").count() == 1


def test_failed_scan_reports_masked_error(scan_env):
    app, client, _ = scan_env
    h = login(client, "analyst")

    def boom(*a):
        raise ConnectionError("cannot reach 127.0.0.1:8001 as alice@example.com")
    app.state.scan_runner.scan_fn = boom
    scan_id = _start(client, h).json()["id"]
    _wait(app, scan_id)
    scan = client.get(f"/api/scans/{scan_id}", headers=h).json()
    assert scan["status"] == "failed" and scan["error"].startswith("ConnectionError")
    assert "alice@example.com" not in scan["error"]
    assert client.get(f"/api/scans/{scan_id}/report", headers=h).status_code == 409


def test_apply_rule_pushes_and_mitigates_and_lowers_risk(scan_env, gateway):
    app, client, _ = scan_env
    h = login(client, "analyst")
    scan_id = _start(client, h).json()["id"]
    _wait(app, scan_id)
    before = client.get("/api/metrics/summary?upstream_id=up_shop&range=1h", headers=h).json()
    assert before["risk_score"] == 5.1 and before["previous"]["risk_score"] == 7.3
    assert [d["endpoint"] for d in before["risk_drivers"]][0] == "GET /search"
    sqli = next(f for f in client.get(f"/api/scans/{scan_id}/findings", headers=h).json()["items"]
                if f["endpoint"] == "/search")
    resp = client.post(f"/api/findings/{sqli['id']}/apply-rule", headers=h)
    assert resp.status_code == 200 and resp.json()["status"] == "mitigated"
    assert gateway.rules["rule-block-sqli-q"]["match"]["signature"] == "sqli"
    after = client.get("/api/metrics/summary?upstream_id=up_shop&range=1h", headers=h).json()
    assert after["risk_score"] == 2.4 < before["risk_score"]
    rules = client.get("/api/rules?upstream_id=up_shop", headers=h).json()["items"]
    assert any(r["id"] == "rule-block-sqli-q" and r["source"] == "scanner" for r in rules)
    with app.state.session_factory() as s:
        assert s.query(AuditRow).filter_by(action="finding.apply_rule").count() == 1


def test_log_only_suggestion_is_not_exported(scan_env, gateway):
    """The scanner's export_rules() drops rules that downgrade to `log` (they would fire on
    every request to the path), so such a finding has no suggested rule and nothing to apply."""
    app, client, _ = scan_env
    h = login(client, "analyst")
    report = {**FAKE_REPORT, "findings": [{**FAKE_REPORT["findings"][2], "suggested_rule": {
        "id": "rule-mask-debug", "match": {"path": "/debug", "method": "GET"}, "action": "mask_response",
        "source": "scanner"}}]}
    app.state.scan_runner.scan_fn = lambda *a: report
    scan_id = _start(client, h).json()["id"]
    _wait(app, scan_id)
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=h).json()["items"][0]
    assert "suggested_rule" not in finding
    resp = client.post(f"/api/findings/{finding['id']}/apply-rule", headers=h)
    assert resp.status_code == 409 and resp.json()["error"]["code"] == "no_suggested_rule"
    assert "rule-mask-debug" not in gateway.rules
    assert client.get(f"/api/scans/{scan_id}/findings", headers=h).json()["items"][0]["status"] == "open"


def test_stored_log_rule_does_not_mitigate(scan_env, gateway):
    """A `log` suggested rule can still exist in the database (findings stored before the
    scanner stopped exporting them, or written directly). MITIGATING_ACTIONS keeps it open."""
    from admin_api.models import FindingRow
    app, client, _ = scan_env
    h = login(client, "analyst")
    scan_id = _start(client, h).json()["id"]
    _wait(app, scan_id)
    with app.state.session_factory() as s:
        s.add(FindingRow(id="fd_legacylog", scan_id=scan_id, upstream_id="up_shop", scanner_id="secrets-debug",
                         endpoint="/debug", method="GET", owasp_cat="API8:2023", title="Secrets in response",
                         severity="low", risk_score=3.6, evidence={"request": "GET /debug", "response": "—"},
                         suggested_rule={"id": "rule-log-debug", "name": "rule log debug", "enabled": True,
                                         "match": {"path": "/debug", "method": "GET"}, "action": "log",
                                         "source": "scanner", "priority": 100}))
        s.commit()
    resp = client.post("/api/findings/fd_legacylog/apply-rule", headers=h)
    assert resp.status_code == 200 and resp.json()["status"] == "open"
    assert gateway.rules["rule-log-debug"]["action"] == "log"


def test_apply_rule_with_gateway_down_keeps_finding_open(scan_env, gateway):
    app, client, _ = scan_env
    h = login(client, "analyst")
    scan_id = _start(client, h).json()["id"]
    _wait(app, scan_id)
    fid = client.get(f"/api/scans/{scan_id}/findings", headers=h).json()["items"][0]["id"]
    gateway.down = True
    assert client.post(f"/api/findings/{fid}/apply-rule", headers=h).status_code == 502
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=h).json()["items"][0]
    assert finding["status"] == "open"


def test_endpoint_inventory(scan_env):
    app, client, _ = scan_env
    h = login(client, "analyst")
    from datetime import datetime, timezone

    from admin_api.db import iso

    from .conftest import event
    now = iso(datetime.now(timezone.utc))
    app.state.ingestor.process([event(now, path="/search"), event(now, path="/internal/export")])
    scan_id = _start(client, h).json()["id"]
    _wait(app, scan_id)
    client.post("/api/rules?upstream_id=up_shop", headers=h,
                json={"id": "rl", "match": {"path": "/login", "method": "POST"}, "action": "throttle",
                      "throttle": {"limit": 5, "per": 60}})
    items = {(e["method"], e["path"]): e for e in
             client.get("/api/endpoints?upstream_id=up_shop", headers=h).json()["items"]}
    assert items[("GET", "/search")]["source"] == "both" and items[("GET", "/search")]["requests_24h"] == 1
    assert items[("GET", "/search")]["risk_score"] == 8.0
    shadow = items[("GET", "/internal/export")]
    assert shadow["shadow"] is True and shadow["source"] == "observed"
    assert items[("POST", "/login")]["rate_limited"] is True
    assert items[("GET", "/profile")]["auth_required"] is True and items[("GET", "/profile")]["source"] == "spec"


# ---- the real scanner against the real demo API ----------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def demo_api_url():
    from demo_api.main import app as demo_app
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(demo_app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(5)


def test_real_scan_against_demo_api(demo_api_url, gateway):
    app = create_app(make_config(upstream_url=demo_api_url),
                     gateway_transport=httpx.MockTransport(gateway.handler), run_background=False)
    with TestClient(app) as client:
        h = login(client, "analyst")
        scan_id = _start(client, h).json()["id"]
        _wait(app, scan_id)
        scan = client.get(f"/api/scans/{scan_id}", headers=h).json()
        assert scan["status"] == "done", scan
        findings = client.get(f"/api/scans/{scan_id}/findings", headers=h).json()["items"]
        endpoints = {f["endpoint"] for f in findings}
        assert {"/search", "/login"} <= endpoints
        rules = {f["suggested_rule"]["id"]: f["suggested_rule"] for f in findings if f.get("suggested_rule")}
        assert rules["rule-ratelimit-login"]["action"] == "throttle"
        assert rules["rule-ratelimit-login"]["throttle"] == {"limit": 5, "per": 60}
        report = client.get(f"/api/scans/{scan_id}/report?format=html", headers=h)
        assert report.status_code == 200 and "<html" in report.text.lower()
