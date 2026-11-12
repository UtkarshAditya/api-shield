from datetime import timedelta

import jwt

from admin_api.auth import PERMISSIONS, can
from admin_api.db import utcnow
from admin_api.models import AuditRow

from .conftest import ADMIN_TOKEN, login


def test_login_and_me(client):
    resp = client.post("/api/auth/login", json={"email": "Analyst@Demo.local ", "password": "demo"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"] == {"id": "u_analyst", "email": "analyst@demo.local", "name": "Sam Analyst",
                            "role": "analyst"}
    me = client.get("/api/me", headers={"Authorization": f"Bearer {body['token']}"})
    assert me.json()["role"] == "analyst"


def test_bad_login_uses_error_envelope(client):
    resp = client.post("/api/auth/login", json={"email": "admin@demo.local", "password": "nope"})
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "invalid_credentials"
    assert body["request_id"] == resp.headers["x-request-id"]


def test_passwords_are_hashed(app):
    from admin_api.models import User
    with app.state.session_factory() as s:
        hashes = [u.password_hash for u in s.query(User)]
    assert hashes and all(h.startswith("$2") and h != "demo" for h in hashes)


def test_requires_token(client):
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/upstreams").json()["error"]["code"] == "unauthorized"


def test_expired_and_forged_tokens(client, app):
    secret = app.state.config.jwt_secret
    expired = jwt.encode({"sub": "u_admin", "exp": utcnow() - timedelta(minutes=1)}, secret, algorithm="HS256")
    resp = client.get("/api/me", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401 and resp.json()["error"]["code"] == "token_expired"
    forged = jwt.encode({"sub": "u_admin", "exp": utcnow() + timedelta(hours=1)}, "wrong", algorithm="HS256")
    assert client.get("/api/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_roles_mirror_frontend():
    assert can("admin", "mode.switch") and not can("analyst", "mode.switch")
    assert can("analyst", "rules.edit") and can("analyst", "scans.run")
    assert PERMISSIONS["viewer"] == set() and not can(None, "rules.edit")


def test_upstreams_and_unknown_upstream(client, as_viewer):
    ups = client.get("/api/upstreams", headers=as_viewer).json()
    assert ups == [{"id": "up_shop", "name": "Demo Shop API", "url": "http://localhost:8001"}]
    resp = client.get("/api/metrics/summary?upstream_id=nope", headers=as_viewer)
    assert resp.status_code == 404 and resp.json()["error"]["code"] == "not_found"


def test_validation_error_names_field_not_value(client, as_viewer):
    resp = client.get("/api/metrics/summary?upstream_id=up_shop&range=secret-value-1y", headers=as_viewer)
    assert resp.status_code == 422
    assert "range" in resp.json()["error"]["message"]
    assert "secret-value-1y" not in resp.text


def test_settings_get_and_patch_roles(client, as_viewer, as_analyst, as_admin, gateway):
    s = client.get("/api/settings", headers=as_viewer).json()
    assert s["mode"] == "monitor" and s["upstreams"][0]["id"] == "up_shop"
    assert client.patch("/api/settings", json={"retention_days": 7}, headers=as_viewer).status_code == 403
    assert client.patch("/api/settings", json={"mode": "enforce"}, headers=as_analyst).status_code == 403
    assert gateway.calls("PUT", "/_apishield/mode") == []
    resp = client.patch("/api/settings", json={"retention_days": 7}, headers=as_admin)
    assert resp.status_code == 200 and resp.json()["retention_days"] == 7


def test_mode_switch_calls_gateway_and_audits(client, as_admin, gateway, app):
    resp = client.patch("/api/settings", json={"mode": "enforce"}, headers=as_admin)
    assert resp.status_code == 200 and resp.json()["mode"] == "enforce"
    (call,) = gateway.calls("PUT", "/_apishield/mode")
    assert call.headers["x-apishield-admin-token"] == ADMIN_TOKEN
    assert gateway.mode == "enforce"
    with app.state.session_factory() as s:
        entry = s.query(AuditRow).filter_by(action="mode.change").one()
    assert entry.actor == "admin@demo.local" and entry.details == {"from": "monitor", "to": "enforce"}
    assert ADMIN_TOKEN not in resp.text


def test_mode_switch_with_gateway_down_changes_nothing(client, as_admin, gateway):
    gateway.down = True
    resp = client.patch("/api/settings", json={"mode": "enforce"}, headers=as_admin)
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "gateway_unreachable"
    assert client.get("/api/settings", headers=as_admin).json()["mode"] == "monitor"


def test_gateway_token_mismatch_is_reported(client, as_admin, app, gateway):
    app.state.gateway._token = "wrong"
    resp = client.patch("/api/settings", json={"mode": "enforce"}, headers=as_admin)
    assert resp.status_code == 502 and resp.json()["error"]["code"] == "gateway_auth_failed"
    assert "wrong" not in resp.text


def test_login_as_each_demo_role(client):
    for role in ("admin", "analyst", "viewer"):
        assert "Authorization" in login(client, role)
