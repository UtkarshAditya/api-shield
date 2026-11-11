from scanner.apishield_scanner.models import Finding
from scanner.apishield_scanner.report import build_report
from scanner.apishield_scanner.risk import risk_band, score_finding


def _finding(owasp_cat, endpoint="/x"):
    return Finding(id="f", endpoint=endpoint, method="GET", owasp_cat=owasp_cat,
                    title="t", severity="high", risk_score=0.0, evidence={}, fix="f")


def test_sqli_scores_higher_than_headers():
    sqli = score_finding(_finding("API8:2023 Security Misconfiguration (Injection)"))
    headers = score_finding(_finding("API8:2023 Security Misconfiguration"))
    assert sqli > headers


def test_risk_band_thresholds():
    assert risk_band(9.5) == "critical"
    assert risk_band(7.5) == "high"
    assert risk_band(5.0) == "medium"
    assert risk_band(2.0) == "low"


def test_report_sorted_by_risk_descending():
    findings = [
        _finding("API8:2023 Security Misconfiguration", "/a"),
        _finding("API1:2023 Broken Object-Level Authorization", "/b"),
    ]
    report = build_report(findings, target="http://localhost:8000")
    scores = [f["risk_score"] for f in report["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert "api_risk_score" in report and "endpoint_risk" in report