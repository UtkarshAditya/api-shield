import jwt
from fastapi.testclient import TestClient

from demo_api.main import build_app


def _login(client, username="alice", password="alice123"):
    r = client.post("/login", json={"username": username, "password": password})
    return r.json()["token"]


def test_fixed_jwt_is_verified():
    client = TestClient(build_app("fixed"))
    forged = jwt.encode({"sub": "999", "role": "admin"}, "wrong-key", algorithm="HS256")
    r = client.get("/users/1", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_fixed_idor_is_blocked():
    client = TestClient(build_app("fixed"))
    token = _login(client)
    r = client.get("/users/3", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_fixed_admin_stats_requires_admin_role():
    client = TestClient(build_app("fixed"))
    token = _login(client)  # alice, role=user
    r = client.get("/admin/stats", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_fixed_sqli_payload_returns_no_extra_rows():
    client = TestClient(build_app("fixed"))
    r = client.get("/search", params={"q": "' OR '1'='1"})
    assert r.json()["results"] == []


def test_fixed_profile_does_not_leak_secret():
    client = TestClient(build_app("fixed"))
    token = _login(client)
    r = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
    assert "api_key" not in r.json()


def test_fixed_rate_limit_blocks_after_5_attempts():
    client = TestClient(build_app("fixed"))
    for _ in range(5):
        client.post("/login", json={"username": "alice", "password": "wrong"})
    r = client.post("/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 429