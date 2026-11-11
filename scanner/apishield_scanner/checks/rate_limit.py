from ..client import ApiClient
from ..models import Endpoint, Finding

OWASP = "API4:2023 Unrestricted Resource Consumption"


def check_rate_limit(client: ApiClient, endpoints: list[Endpoint], burst: int = 25) -> list[Finding]:
    findings = []
    for ep in endpoints:
        if ep.path != "/login" or ep.method != "POST":
            continue
        saw_429 = False
        for _ in range(burst):
            resp = client._http.request(
                "POST", client.base_url + ep.path,
                json={"username": "alice", "password": "wrong"},
            )
            if resp.status_code == 429:
                saw_429 = True
                break
        if not saw_429:
            findings.append(Finding(
                id="rate-limit-login", endpoint=ep.path, method=ep.method,
                owasp_cat=OWASP, title="No rate limit on login, brute force possible",
                severity="high", risk_score=0.0,
                evidence={"requests_sent": burst, "got_429": False},
                fix="Add a rate limit (e.g. 5 attempts/min) per IP or account on /login.",
                suggested_rule={"id": "rule-ratelimit-login",
                                 "match": {"path": "/login", "method": "POST"},
                                 "action": "rate_limit", "limit": "5/min", "source": "scanner"},
            ))
    return findings