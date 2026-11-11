from ..client import ApiClient, UnsafeRequestError
from ..models import Endpoint, Finding

OWASP = "API1:2023 Broken Object-Level Authorization"


def check_idor(client: ApiClient, endpoints: list[Endpoint], token: str,
               own_id: int, probe_ids=(1, 2, 3)) -> list[Finding]:
    """Log in as one user (own_id) and try reading nearby numeric IDs."""
    findings = []
    for ep in endpoints:
        if not ep.requires_auth:
            continue
        id_param = next(
            (p for p in ep.params if p["in"] == "path" and p["type"] == "integer"),
            None,
        )
        if id_param is None:
            continue

        leaked_ids = []
        for probe_id in probe_ids:
            if probe_id == own_id:
                continue
            path = ep.path.replace("{" + id_param["name"] + "}", str(probe_id))
            try:
                resp = client.request(ep.method, path, token=token)
            except UnsafeRequestError:
                continue
            if 200 <= resp.status_code < 300:
                leaked_ids.append(probe_id)

        if leaked_ids:
            findings.append(
                Finding(
                    id=f"idor-{ep.method.lower()}-{id_param['name']}",
                    endpoint=ep.path,
                    method=ep.method,
                    owasp_cat=OWASP,
                    title="Endpoint returns other users' data by changing the ID",
                    severity="high",
                    risk_score=0.0,
                    evidence={
                        "logged_in_as": own_id,
                        "ids_also_readable": leaked_ids,
                    },
                    fix="Check that the authenticated user owns the requested "
                        "object before returning it (not just that a token exists).",
                    suggested_rule={
                        "id": f"rule-idor-{id_param['name']}",
                        "match": {"path": ep.path, "method": ep.method},
                        "action": "enforce_ownership",
                        "source": "scanner",
                    },
                )
            )
    return findings