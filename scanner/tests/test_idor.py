from fastapi.testclient import TestClient

from demo_api.main import app
from scanner.apishield_scanner.checks.idor import check_idor
from scanner.apishield_scanner.client import ApiClient
from scanner.apishield_scanner.models import Endpoint


def _login(http, username="alice", password="alice123"):
    r = http.post("/login", json={"username": username, "password": password})
    return r.json()["token"]


def test_alice_can_read_admins_data():
    http = TestClient(app)
    token = _login(http)
    client = ApiClient("http://testserver", http=http)
    endpoints = [
        Endpoint(
            method="GET", path="/users/{user_id}",
            params=[{"name": "user_id", "in": "path", "required": True, "type": "integer"}],
            requires_auth=True,
        )
    ]
    findings = check_idor(client, endpoints, token=token, own_id=1)
    assert len(findings) == 1
    assert 3 in findings[0].evidence["ids_also_readable"]  # admin's id