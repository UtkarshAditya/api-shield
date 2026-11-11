from pathlib import Path

from fastapi.testclient import TestClient

from demo_api.main import app
from scanner.apishield_scanner.checks.jwt_flaws import check_jwt_flaws
from scanner.apishield_scanner.client import ApiClient
from scanner.apishield_scanner.spec import load_spec, parse_endpoints

SPEC = Path(__file__).resolve().parents[2] / "demo_api" / "openapi.json"


def test_forged_and_none_alg_tokens_are_accepted():
    client = ApiClient("http://testserver", http=TestClient(app))
    endpoints = parse_endpoints(load_spec(SPEC))
    findings = check_jwt_flaws(client, endpoints)
    probes = {f.evidence["probe"] for f in findings}
    assert probes == {"forged-signature", "alg-none"}