from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo_api.main import app
from scanner.apishield_scanner.checks.missing_auth import check_missing_auth
from scanner.apishield_scanner.client import ApiClient, UnsafeRequestError
from scanner.apishield_scanner.models import Endpoint
from scanner.apishield_scanner.spec import load_spec, parse_endpoints

SPEC = Path(__file__).resolve().parents[2] / "demo_api" / "openapi.json"


def _client(safe_mode=True):
    return ApiClient("http://testserver", safe_mode=safe_mode, http=TestClient(app))


def test_finds_unenforced_auth_on_admin_stats():
    findings = check_missing_auth(_client(), parse_endpoints(load_spec(SPEC)))
    assert [f.endpoint for f in findings] == ["/admin/stats"]
    f = findings[0]
    assert f.method == "GET"
    assert f.evidence["status_code"] == 200
    assert f.suggested_rule["match"]["path"] == "/admin/stats"


def test_safe_mode_blocks_post():
    with pytest.raises(UnsafeRequestError):
        _client().request("POST", "/comments", json={})


def test_safe_mode_check_skips_unsafe_methods():
    ep = Endpoint(method="POST", path="/comments", requires_auth=True)
    assert check_missing_auth(_client(), [ep]) == []