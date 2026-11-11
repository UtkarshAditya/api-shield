LIKELIHOOD_IMPACT = {
    "API1:2023 Broken Object-Level Authorization": (4, 5),
    "API2:2023 Broken Authentication": (4, 5),
    "API3:2023 Broken Object Property Level Authorization / Excessive Data Exposure": (3, 4),
    "API4:2023 Unrestricted Resource Consumption": (3, 3),
    "API8:2023 Security Misconfiguration": (3, 3),
    "API8:2023 Security Misconfiguration (Injection)": (4, 5),
}
DEFAULT_LIKELIHOOD_IMPACT = (3, 3)


def score_finding(finding) -> float:
    """risk = likelihood x impact, scaled from a 0-25 range to 0-10."""
    likelihood, impact = LIKELIHOOD_IMPACT.get(finding.owasp_cat, DEFAULT_LIKELIHOOD_IMPACT)
    return round((likelihood * impact) / 25 * 10, 1)


def risk_band(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def score_all(findings: list) -> list:
    for f in findings:
        f.risk_score = score_finding(f)
    return findings


def endpoint_risk(findings: list) -> dict:
    """Worst finding per endpoint, with a small bump for extra findings, capped at 10."""
    scores = {}
    for f in findings:
        scores.setdefault(f.endpoint, []).append(f.risk_score)
    return {
        ep: round(min(10.0, max(s) + 0.1 * (len(s) - 1)), 1)
        for ep, s in scores.items()
    }


def api_risk(endpoint_scores: dict) -> float:
    if not endpoint_scores:
        return 0.0
    return round(sum(endpoint_scores.values()) / len(endpoint_scores), 1)