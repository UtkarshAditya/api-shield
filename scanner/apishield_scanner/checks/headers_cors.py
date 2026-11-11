from ..client import ApiClient, UnsafeRequestError
from ..models import Endpoint, Finding

OWASP = "API8:2023 Security Misconfiguration"
EXPECTED_HEADERS = ["x-content-type-options", "strict-transport-security"]


def check_headers_cors(client: ApiClient, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []
    seen_paths = set()
    for ep in endpoints:
        if ep.path in seen_paths:
            continue
        seen_paths.add(ep.path)
        try:
            resp = client.request(
                ep.method if ep.method in ("GET",) else "GET", ep.path,
                headers={"Origin": "https://evil-example.com"},
            )
        except UnsafeRequestError:
            continue
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        missing = [h for h in EXPECTED_HEADERS if h not in headers_lower]
        cors_wildcard = headers_lower.get("access-control-allow-origin") == "*"
        if missing or cors_wildcard:
            findings.append(Finding(
                id=f"headers-{ep.path.strip('/').replace('/', '-') or 'root'}",
                endpoint=ep.path, method="GET", owasp_cat=OWASP,
                title="Missing security headers or permissive CORS",
                severity="medium", risk_score=0.0,
                evidence={"missing_headers": missing, "cors_wildcard": cors_wildcard},
                fix="Add security headers (HSTS, X-Content-Type-Options) and restrict CORS to known origins.",
                suggested_rule={"id": f"rule-headers-{ep.path.strip('/').replace('/', '-') or 'root'}",
                                 "match": {"path": ep.path}, "action": "add_security_headers", "source": "scanner"},
            ))
    return findings