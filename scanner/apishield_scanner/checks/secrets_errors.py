import re

from ..client import ApiClient, UnsafeRequestError
from ..models import Endpoint, Finding

OWASP = "API3:2023 Broken Object Property Level Authorization / Excessive Data Exposure"
SECRET_PATTERNS = [re.compile(r"sk_live_[A-Za-z0-9]+"), re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")]
ERROR_HINTS = ("traceback", "stack trace", "exception", "at line")


def check_secrets_errors(client: ApiClient, endpoints: list[Endpoint], token: str | None = None) -> list[Finding]:
    findings = []
    for ep in endpoints:
        try:
            resp = client.request(ep.method if ep.method == "GET" else "GET", ep.path, token=token)
        except UnsafeRequestError:
            continue
        body = resp.text
        body_lower = body.lower()
        leaked = [p.pattern for p in SECRET_PATTERNS if p.search(body)]
        verbose = resp.status_code >= 500 and any(h in body_lower for h in ERROR_HINTS)
        if leaked or verbose:
            findings.append(Finding(
                id=f"exposure-{ep.path.strip('/').replace('/', '-') or 'root'}",
                endpoint=ep.path, method="GET", owasp_cat=OWASP,
                title="Response leaks a secret or a verbose error trace",
                severity="high", risk_score=0.0,
                evidence={"secrets_found": bool(leaked), "verbose_error": verbose,
                          "snippet": body[:200]},
                fix="Never return secrets in API responses. Return generic error "
                    "messages and log tracebacks server-side only.",
                suggested_rule={"id": f"rule-mask-{ep.path.strip('/').replace('/', '-') or 'root'}",
                                 "match": {"path": ep.path}, "action": "mask_response", "source": "scanner"},
            ))
    return findings