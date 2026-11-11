from ..client import ApiClient, UnsafeRequestError
from ..models import Endpoint, Finding

OWASP = "API8:2023 Security Misconfiguration (Injection)"

PAYLOADS = ["' OR '1'='1", "'", "' OR 1=1--", "\" OR \"1\"=\"1"]
SQL_ERROR_HINTS = ("sql", "sqlite", "syntax", "operationalerror")


def check_injection(client: ApiClient, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []
    for ep in endpoints:
        query_params = [p for p in ep.params if p["in"] == "query"]
        if not query_params:
            continue

        for param in query_params:
            baseline_count = None
            for payload in PAYLOADS:
                try:
                    resp = client.request(
                        ep.method, ep.path, params={param["name"]: payload}
                    )
                except UnsafeRequestError:
                    break

                body_lower = resp.text.lower()
                error_leak = resp.status_code == 500 and any(
                    h in body_lower for h in SQL_ERROR_HINTS
                )

                large_result = False
                try:
                    data = resp.json()
                    results = data.get("results")
                    if isinstance(results, list):
                        if baseline_count is None:
                            baseline_count = len(results)
                        elif len(results) > baseline_count:
                            large_result = True
                except ValueError:
                    pass

                if error_leak or large_result:
                    findings.append(
                        Finding(
                            id=f"sqli-{ep.method.lower()}-{param['name']}",
                            endpoint=ep.path,
                            method=ep.method,
                            owasp_cat=OWASP,
                            title=f"Possible SQL injection via '{param['name']}'",
                            severity="critical",
                            risk_score=0.0,
                            evidence={
                                "payload": payload,
                                "status_code": resp.status_code,
                                "signal": "sql_error" if error_leak else "result_count_changed",
                                "response_snippet": resp.text[:200],
                            },
                            fix="Use parameterized queries instead of building "
                                "SQL with string concatenation.",
                            suggested_rule={
                                "id": f"rule-block-sqli-{param['name']}",
                                "match": {"path": ep.path, "method": ep.method},
                                "action": "block",
                                "pattern": "sql_injection",
                                "source": "scanner",
                            },
                        )
                    )
                    break  # one finding per param is enough
    return findings