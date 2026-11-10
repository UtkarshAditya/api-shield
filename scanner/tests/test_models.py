from scanner.apishield_scanner.models import Endpoint, Finding


def test_finding_to_dict_has_contract_fields():
    f = Finding(
        id="f-1", endpoint="/login", method="POST", owasp_cat="API4:2023",
        title="No rate limit", severity="high", risk_score=8.0,
        evidence={"status": 401}, fix="Add a rate limit",
    )
    d = f.to_dict()
    for key in ["id", "endpoint", "method", "owasp_cat", "title", "severity",
                "risk_score", "evidence", "fix", "suggested_rule"]:
        assert key in d
    assert d["suggested_rule"] is None


def test_endpoint_defaults():
    e = Endpoint(method="GET", path="/x")
    assert e.params == [] and e.requires_auth is False