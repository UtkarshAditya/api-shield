from scanner.apishield_scanner.models import Finding
from scanner.apishield_scanner.report import build_report
from scanner.apishield_scanner.report_html import render_html_report


def test_html_report_contains_finding_titles():
    f = Finding(id="a", endpoint="/x", method="GET",
                owasp_cat="API1:2023 Broken Object-Level Authorization",
                title="Test finding title", severity="high",
                risk_score=0.0, evidence={}, fix="Fix this")
    report = build_report([f], target="http://localhost:8000")
    html = render_html_report(report)
    assert "Test finding title" in html
    assert "Fix this" in html
    assert "localhost:8000" in html