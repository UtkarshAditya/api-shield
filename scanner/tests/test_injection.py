from fastapi.testclient import TestClient

from demo_api.main import app
from scanner.apishield_scanner.checks.injection import check_injection
from scanner.apishield_scanner.client import ApiClient
from scanner.apishield_scanner.models import Endpoint


def test_finds_sql_injection_on_search():
    client = ApiClient("http://testserver", http=TestClient(app))
    endpoints = [
        Endpoint(
            method="GET", path="/search",
            params=[{"name": "q", "in": "query", "required": False, "type": "string"}],
        )
    ]
    findings = check_injection(client, endpoints)
    assert len(findings) == 1
    assert findings[0].evidence["payload"] in [
        "' OR '1'='1", "'", "' OR 1=1--", "\" OR \"1\"=\"1"
    ]