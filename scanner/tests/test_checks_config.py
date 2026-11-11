from fastapi.testclient import TestClient

from demo_api.main import app
from scanner.apishield_scanner.checks.headers_cors import check_headers_cors
from scanner.apishield_scanner.checks.rate_limit import check_rate_limit
from scanner.apishield_scanner.checks.secrets_errors import check_secrets_errors
from scanner.apishield_scanner.client import ApiClient, login
from scanner.apishield_scanner.models import Endpoint


def _client():
    return ApiClient("http://testserver", http=TestClient(app))


def test_login_has_no_rate_limit():
    ep = Endpoint(method="POST", path="/login")
    findings = check_rate_limit(_client(), [ep], burst=10)
    assert len(findings) == 1
    assert findings[0].evidence["got_429"] is False


def test_headers_and_cors_flagged():
    ep = Endpoint(method="GET", path="/search")
    findings = check_headers_cors(_client(), [ep])
    assert len(findings) == 1
    assert findings[0].evidence["cors_wildcard"] is True


def test_profile_leaks_secret():
    c = _client()
    token = login(c, "/login", "alice", "alice123")
    ep = Endpoint(method="GET", path="/profile", requires_auth=True)
    findings = check_secrets_errors(c, [ep], token=token)
    assert len(findings) == 1 and findings[0].evidence["secrets_found"] is True


def test_debug_leaks_trace():
    ep = Endpoint(method="GET", path="/debug")
    findings = check_secrets_errors(_client(), [ep])
    assert len(findings) == 1 and findings[0].evidence["verbose_error"] is True