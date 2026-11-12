"""The demo storyline from section 7 of the plan, run against the real demo API."""
import shutil
import time
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from demo_api.main import app as demo_api
from gateway.apishield_gateway.config import load_settings

from .helpers import make_gateway, wait_for_events

GATEWAY_DIR = Path(__file__).resolve().parents[1]
SQLI = {"q": "' OR '1'='1"}


def _gateway(tmp_path, **overrides):
    settings = load_settings(GATEWAY_DIR / "gateway.yaml", env={})  # the shipped config
    rules = tmp_path / "rules"
    rules.mkdir()
    shutil.copy(GATEWAY_DIR / "rules" / "builtin.yaml", rules / "builtin.yaml")
    return make_gateway(tmp_path, demo_api, settings=settings, rules_dir=str(rules), **overrides)


@pytest.fixture
def shielded(tmp_path):
    app, sink = _gateway(tmp_path)
    with TestClient(app) as client:
        yield client, sink


def _login(client, user="alice", password="alice123"):
    return client.post("/login", json={"username": user, "password": password})


def _bearer(client):
    return {"Authorization": f"Bearer {_login(client).json()['token']}"}


def test_normal_use_still_works_through_the_gateway(shielded):
    client, _ = shielded
    login = _login(client)
    assert login.status_code == 200 and login.json()["token"].count(".") == 2  # token not masked
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    assert client.get("/search", params={"q": "ali"}).json() == {"results": [{"id": 1, "username": "alice"}]}
    assert client.get("/users/1", headers=headers).json()["username"] == "alice"
    assert client.post("/comments", json={"text": "nice post"}).json()["saved"] is True
    assert _login(client, password="wrong").status_code == 401  # upstream's own 401 passes through


def test_simulator_demo_keys_are_known_and_give_separate_callers(shielded):
    client, sink = shielded
    for key in ("key-alice", "key-bob", "key-mallory"):
        assert client.get("/search", params={"q": "a"}, headers={"X-API-Key": key}).status_code == 200
    assert client.get("/search", params={"q": "a"}, headers={"X-API-Key": "key-unknown"}).status_code == 401
    callers = [e["caller"] for e in wait_for_events(sink, 4)[:3]]
    assert len(set(callers)) == 3 and all(c.startswith("key_") for c in callers)
    assert not any("alice" in c or "mallory" in c for c in callers)  # the key never appears in events


def test_sql_injection_on_search_is_blocked(shielded):
    client, sink = shielded
    r = client.get("/search", params=SQLI)
    assert r.status_code == 403 and "results" not in r.json()
    event = wait_for_events(sink)[0]
    assert event["rule_hits"] == ["builtin-sqli"] and event["path_template"] == "/search"


def test_brute_force_on_login_returns_429_with_retry_after(shielded):
    client, sink = shielded
    statuses = [_login(client, password=f"guess{i}").status_code for i in range(8)]
    assert statuses == [401] * 5 + [429] * 3
    limited = _login(client, password="alice123")
    assert limited.status_code == 429 and int(limited.headers["retry-after"]) >= 1
    assert client.get("/search", params={"q": "bob"}).status_code == 200  # other routes unaffected
    assert wait_for_events(sink, 10)[5]["rule_hits"] == ["ratelimit.login"]


def test_admin_route_now_requires_a_token(shielded):
    client, _ = shielded
    r = client.get("/admin/stats")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert client.get("/admin/stats", headers=_bearer(client)).status_code == 200


def test_forged_and_expired_tokens_are_rejected(shielded):
    client, _ = shielded
    soon = int(time.time()) + 600
    unsigned = jwt.encode({"sub": "3", "role": "admin", "exp": soon}, None, algorithm="none")
    wrong_key = jwt.encode({"sub": "3", "role": "admin", "exp": soon}, "not-the-real-secret" * 2, algorithm="HS256")
    expired = jwt.encode({"sub": "1", "role": "user", "exp": int(time.time()) - 60}, "dev-secret", algorithm="HS256")
    for token, code in ((unsigned, "jwt_alg_none"), (wrong_key, "jwt_bad_signature"), (expired, "jwt_expired")):
        r = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401 and r.json()["error"]["code"] == code


def test_leaked_api_key_and_stack_traces_are_masked(shielded):
    client, sink = shielded
    profile = client.get("/profile", headers=_bearer(client))
    assert profile.json() == {"user_id": "1", "api_key": "[REDACTED:api_key]"}
    debug = client.get("/debug")
    assert debug.status_code == 500 and debug.json() == {"trace": "[REDACTED:stack_trace]"}
    hits = [e["rule_hits"] for e in wait_for_events(sink, 3)]
    assert ["resp.secret.api_key"] in hits and ["resp.error.stack_trace"] in hits


def test_bad_input_is_rejected_before_it_reaches_the_api(shielded):
    client, _ = shielded
    assert client.post("/login", json={"username": "alice"}).status_code == 400
    assert client.post("/login", content="username=alice", headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.get("/users/abc", headers=_bearer(client)).status_code == 400
    assert client.post("/comments", json={"text": "<script>steal()</script>"}).status_code == 403


def test_monitor_mode_shows_the_before_picture(tmp_path):
    app, sink = _gateway(tmp_path, mode="monitor")
    with TestClient(app) as client:
        leaked = client.get("/search", params=SQLI)
        open_admin = client.get("/admin/stats")
        events = wait_for_events(sink, 2)
    assert len(leaked.json()["results"]) == 3  # the attack works, but it is recorded
    assert open_admin.status_code == 200
    assert events[0]["action"] == "log" and events[0]["rule_hits"] == ["builtin-sqli"]
    assert events[1]["rule_hits"] == ["auth.missing_credentials"]
