import asyncio
from datetime import datetime, timezone

from admin_api.db import iso
from admin_api.models import AuditRow, RuleRow, SettingsRow
from admin_api.rules_service import sync_gateway_once

from .conftest import ADMIN_TOKEN, event

LOGIN_THROTTLE = {"id": "rule-ratelimit-login", "match": {"path": "/login", "method": "POST"},
                  "action": "throttle", "throttle": {"limit": 5, "per": 60}, "source": "scanner"}
URL = "/api/rules?upstream_id=up_shop"


def test_create_rule_pushes_to_gateway_and_persists_metadata(client, as_analyst, gateway, app):
    resp = client.post(URL, json=LOGIN_THROTTLE, headers=as_analyst)
    assert resp.status_code == 201, resp.text
    rule = resp.json()
    assert rule["name"] == "rule-ratelimit-login"  # defaulted from the id
    assert rule["throttle"] == {"limit": 5, "per": 60} and rule["priority"] == 100
    assert rule["created_by"] == "analyst@demo.local" and rule["hits_24h"] == 0
    (push,) = gateway.calls("POST", "/_apishield/rules")
    assert push.headers["x-apishield-admin-token"] == ADMIN_TOKEN
    assert gateway.rules["rule-ratelimit-login"]["action"] == "throttle"
    with app.state.session_factory() as s:
        assert s.get(RuleRow, "rule-ratelimit-login").created_by == "analyst@demo.local"
        assert s.query(AuditRow).filter_by(action="rule.create").count() == 1


def test_list_valued_method_and_alias(client, as_admin, gateway):
    body = {"id": "admin-auth", "match": {"path": "/admin/*", "method": ["GET", "POST"],
                                          "ip": ["10.0.0.0/8", "192.168.0.0/16"]},
            "action": "require_auth"}
    rule = client.post(URL, json=body, headers=as_admin).json()
    assert rule["action"] == "challenge"
    assert rule["match"]["method"] == ["GET", "POST"]
    assert gateway.rules["admin-auth"]["action"] == "challenge"


def test_invalid_rule_rejected_before_gateway(client, as_admin, gateway):
    bad = {"id": "bad", "match": {"signature": "nope"}, "action": "block"}
    resp = client.post(URL, json=bad, headers=as_admin)
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "invalid_rule"
    assert "unknown signature" in resp.json()["error"]["message"]
    resp = client.post(URL, json={"id": "x", "match": {"path": "/a"}, "action": "explode"}, headers=as_admin)
    assert resp.status_code == 422
    assert gateway.calls("POST", "/_apishield/rules") == []


def test_viewer_cannot_edit_rules(client, as_viewer):
    assert client.post(URL, json=LOGIN_THROTTLE, headers=as_viewer).status_code == 403
    assert client.get(URL, headers=as_viewer).status_code == 200


def test_gateway_down_saves_nothing(client, as_admin, gateway, app):
    gateway.down = True
    resp = client.post(URL, json=LOGIN_THROTTLE, headers=as_admin)
    assert resp.status_code == 502 and resp.json()["error"]["code"] == "gateway_unreachable"
    with app.state.session_factory() as s:
        assert s.get(RuleRow, "rule-ratelimit-login") is None


def test_gateway_rejection_is_clean_error(client, as_admin, gateway):
    gateway.reject_rules = True
    resp = client.post(URL, json=LOGIN_THROTTLE, headers=as_admin)
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "gateway_rejected"


def test_patch_disable_and_delete(client, as_admin, gateway, app):
    client.post(URL, json=LOGIN_THROTTLE, headers=as_admin)
    resp = client.patch("/api/rules/rule-ratelimit-login?upstream_id=up_shop", json={"enabled": False},
                        headers=as_admin)
    assert resp.status_code == 200 and resp.json()["enabled"] is False
    assert gateway.rules["rule-ratelimit-login"]["enabled"] is False
    assert client.delete("/api/rules/rule-ratelimit-login?upstream_id=up_shop", headers=as_admin).status_code == 204
    assert "rule-ratelimit-login" not in gateway.rules
    with app.state.session_factory() as s:
        actions = [a.action for a in s.query(AuditRow).order_by(AuditRow.ts)]
    assert actions == ["rule.create", "rule.update", "rule.delete"]
    assert client.delete("/api/rules/rule-ratelimit-login?upstream_id=up_shop",
                         headers=as_admin).status_code == 404


def test_hits_24h_come_from_traffic_not_gateway(client, as_admin, gateway, app):
    client.post(URL, json=LOGIN_THROTTLE, headers=as_admin)
    now = iso(datetime.now(timezone.utc))
    app.state.ingestor.process([event(now, action="throttle", rule_hits=["rule-ratelimit-login"])] * 3)
    rules = client.get(URL, headers=as_admin).json()["items"]
    rule = next(r for r in rules if r["id"] == "rule-ratelimit-login")
    assert rule["hits_24h"] == 3  # the fake gateway reports hits=999 since start


def test_gateway_only_rules_listed_read_only(client, as_admin, gateway):
    gateway.rules["builtin-sqli"] = {"id": "builtin-sqli", "name": "SQL injection", "enabled": True,
                                     "match": {"signature": "sqli"}, "action": "block", "source": "builtin",
                                     "priority": 100}
    items = client.get(URL, headers=as_admin).json()["items"]
    assert any(r["id"] == "builtin-sqli" and r["source"] == "builtin" for r in items)
    resp = client.patch("/api/rules/builtin-sqli?upstream_id=up_shop", json={"enabled": False}, headers=as_admin)
    assert resp.status_code == 409 and resp.json()["error"]["code"] == "rule_read_only"


def test_rule_tester(client, as_viewer):
    sqli = {"rule": {"name": "SQLi on search", "match": {"path": "/search", "signature": "sqli"}, "action": "block"},
            "request": {"method": "GET", "path": "/search", "query": {"q": "' OR '1'='1"}}}
    resp = client.post("/api/rules/test", json=sqli, headers=as_viewer).json()
    assert resp["matched"] is True and resp["action"] == "block" and "403" in resp["explanation"]
    sqli["request"]["query"] = {"q": "shoes"}
    resp = client.post("/api/rules/test", json=sqli, headers=as_viewer).json()
    assert resp == {"matched": False, "action": None, "explanation": resp["explanation"]}
    assert "attack signature" in resp["explanation"]
    methods = {"rule": {"match": {"path": "/admin/*", "method": ["POST", "DELETE"]}, "action": "block"},
               "request": {"method": "DELETE", "path": "/admin/users/3"}}
    assert client.post("/api/rules/test", json=methods, headers=as_viewer).json()["matched"] is True


def test_sync_restores_mode_and_rules_after_gateway_restart(client, as_admin, gateway, app):
    client.post(URL, json=LOGIN_THROTTLE, headers=as_admin)
    with app.state.session_factory() as s:
        s.get(SettingsRow, 1).mode = "enforce"
        s.commit()
    gateway.rules.clear()  # gateway restarted without dynamic.json
    gateway.mode = "monitor"
    assert asyncio.run(sync_gateway_once(app)) is True
    assert gateway.mode == "enforce" and "rule-ratelimit-login" in gateway.rules
    gateway.down = True
    assert asyncio.run(sync_gateway_once(app)) is False
