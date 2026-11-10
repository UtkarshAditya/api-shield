from ..client import ApiClient, UnsafeRequestError
from ..models import Endpoint, Finding
from ..spec import fill_path_params

OWASP = "API2:2023 Broken Authentication"


def check_missing_auth(client: ApiClient, endpoints: list[Endpoint]) -> list[Finding]:
    """Call every endpoint the spec says is protected, with NO token."""
    findings = []
    for ep in endpoints:
        if not ep.requires_auth:
            continue
        path = fill_path_params(ep)
        try:
            resp = client.request(ep.method, path)  # no token on purpose
        except UnsafeRequestError:
            continue  # safe mode skipped this method
        if 200 <= resp.status_code < 300:
            slug = ep.path.strip("/").replace("/", "-")
            slug = slug.replace("{", "").replace("}", "")
            findings.append(
                Finding(
                    id=f"missing-auth-{ep.method.lower()}-{slug}",
                    endpoint=ep.path,
                    method=ep.method,
                    owasp_cat=OWASP,
                    title="Protected endpoint reachable without authentication",
                    severity="high",
                    risk_score=0.0,  # filled in by risk.py (PR 6)
                    evidence={
                        "request": f"{ep.method} {path} (no Authorization header)",
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:200],
                    },
                    fix="Enforce authentication on this route (reject requests "
                        "without a valid token with 401).",
                    suggested_rule={  # DRAFT: confirm the format with M1
                        "id": f"rule-require-auth-{slug}",
                        "match": {"path": ep.path, "method": ep.method},
                        "action": "require_auth",
                        "source": "scanner",
                    },
                )
            )
    return findings