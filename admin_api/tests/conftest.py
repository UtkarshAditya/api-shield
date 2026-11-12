from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from admin_api.config import Config
from admin_api.main import create_app

ADMIN_TOKEN = "test-gateway-admin-token-5f2c"
SALT = "test-pseudo-salt"


class FakeGateway:
    """Stands in for the gateway's control endpoints via httpx.MockTransport."""

    def __init__(self):
        self.mode = "monitor"
        self.rules: dict = {}
        self.requests: list = []
        self.down = False
        self.reject_rules = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        self.requests.append(request)
        path = request.url.path
        if path == "/_apishield/health":
            return httpx.Response(200, json={"status": "ok", "mode": self.mode, "rules": len(self.rules)})
        if request.headers.get("x-apishield-admin-token") != ADMIN_TOKEN:
            return httpx.Response(401, json={"detail": "Invalid admin token"})
        if path == "/_apishield/mode" and request.method == "PUT":
            self.mode = json.loads(request.content)["mode"]
            return httpx.Response(200, json={"mode": self.mode})
        if path == "/_apishield/rules" and request.method == "GET":
            return httpx.Response(200, json={"rules": [{**r, "hits": 999} for r in self.rules.values()], "errors": []})
        if path == "/_apishield/rules" and request.method == "POST":
            if self.reject_rules:
                return httpx.Response(400, json={"detail": "rule x: unknown signature 'nope'"})
            for rule in json.loads(request.content)["rules"]:
                self.rules[rule["id"]] = rule
            return httpx.Response(200, json={"saved": []})
        if path.startswith("/_apishield/rules/") and request.method == "DELETE":
            rule_id = path.rsplit("/", 1)[1]
            if self.rules.pop(rule_id, None) is None:
                return httpx.Response(404, json={"detail": "No runtime rule with that id"})
            return httpx.Response(200, json={"removed": rule_id})
        return httpx.Response(404, json={"detail": "Not found"})

    def calls(self, method: str, path: str) -> list:
        return [r for r in self.requests if r.method == method and r.url.path == path]


def make_config(**overrides) -> Config:
    base = dict(database_url="sqlite://", auto_migrate=False, demo_seed=True, admin_token=ADMIN_TOKEN,
                pseudo_salt=SALT, jwt_secret="test-jwt-secret-that-is-long-enough-123", redis_url="")
    base.update(overrides)
    return Config(**base)


@pytest.fixture
def gateway():
    return FakeGateway()


@pytest.fixture
def app(gateway):
    return create_app(make_config(), gateway_transport=httpx.MockTransport(gateway.handler), run_background=False)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def login(client: TestClient, role: str = "admin") -> dict:
    resp = client.post("/api/auth/login", json={"email": f"{role}@demo.local", "password": "demo"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


@pytest.fixture
def as_admin(client):
    return login(client, "admin")


@pytest.fixture
def as_analyst(client):
    return login(client, "analyst")


@pytest.fixture
def as_viewer(client):
    return login(client, "viewer")


def event(ts: str, *, caller="key_1a2b3c4d", ip="10.0.0.1", method="GET", path="/search", status=200,
          latency=12.0, action="allow", rule_hits=()) -> dict:
    """A raw gateway traffic event, exactly as it appears on the Redis stream."""
    return {"ts": ts, "req_id": "r" + ts[-6:], "caller": caller, "ip": ip, "method": method,
            "path_template": path, "status": status, "latency_ms": latency, "req_size": 0, "resp_size": 100,
            "shape_hash": "ff417be79483e4e3", "rule_hits": list(rule_hits), "action": action}
