import jwt

from ..client import ApiClient, UnsafeRequestError
from ..models import Endpoint, Finding
from ..spec import fill_path_params

OWASP = "API2:2023 Broken Authentication"


def _forged_token() -> str:
    """A token signed with a key the server never issued, claiming admin."""
    return jwt.encode(
        {"sub": "999", "role": "admin", "exp": 9999999999},
        "attacker-controlled-key",
        algorithm="HS256",
    )


def _none_alg_token() -> str:
    """A token using alg=none, which has no signature at all."""
    return jwt.encode(
        {"sub": "999", "role": "admin", "exp": 9999999999},
        key="",
        algorithm="none",
    )


def check_jwt_flaws(client: ApiClient, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []
    protected = [e for e in endpoints if e.requires_auth]
    if not protected:
        return findings

    probe_ep = protected[0]  # one representative protected endpoint is enough
    path = fill_path_params(probe_ep)

    probes = {
        "forged-signature": _forged_token(),
        "alg-none": _none_alg_token(),
    }
    for probe_name, token in probes.items():
        try:
            resp = client.request(probe_ep.method, path, token=token)
        except UnsafeRequestError:
            continue
        if 200 <= resp.status_code < 300:
            findings.append(
                Finding(
                    id=f"jwt-flaw-{probe_name}",
                    endpoint=probe_ep.path,
                    method=probe_ep.method,
                    owasp_cat=OWASP,
                    title=f"Server accepts a JWT with {probe_name.replace('-', ' ')}",
                    severity="critical",
                    risk_score=0.0,
                    evidence={
                        "probe": probe_name,
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:200],
                    },
                    fix="Verify the JWT signature with the server's real secret "
                        "and reject alg=none tokens explicitly.",
                    suggested_rule={
                        "id": f"rule-strict-jwt-{probe_name}",
                        "match": {"path": probe_ep.path, "method": probe_ep.method},
                        "action": "require_valid_jwt",
                        "source": "scanner",
                    },
                )
            )
    return findings