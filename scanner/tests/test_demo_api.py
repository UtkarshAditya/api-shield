from fastapi.testclient import TestClient

from demo_api.main import app

client = TestClient(app)


def _token(user="alice", pw="alice123"):
    r = client.post("/login", json={"username": user, "password": pw})
    assert r.status_code == 200
    return r.json()["token"]


def test_login_wrong_password_is_401():
    r = client.post("/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401


def test_flaw_admin_stats_needs_no_token():
    assert client.get("/admin/stats").status_code == 200


def test_flaw_idor_alice_reads_admin():
    h = {"Authorization": f"Bearer {_token()}"}
    r = client.get("/users/3", headers=h)
    assert r.status_code == 200 and r.json()["role"] == "admin"


def test_flaw_sql_injection_returns_all_users():
    r = client.get("/search", params={"q": "' OR '1'='1"})
    assert len(r.json()["results"]) == 3


def test_flaw_verbose_error_leaks_trace():
    r = client.get("/debug")
    assert r.status_code == 500 and "Traceback" in r.json()["trace"]


def test_flaw_profile_leaks_api_key():
    h = {"Authorization": f"Bearer {_token()}"}
    assert "sk_live" in client.get("/profile", headers=h).json()["api_key"]