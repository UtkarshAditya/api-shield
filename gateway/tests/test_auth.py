import time
from pathlib import Path

import jwt

from gateway.apishield_gateway.auth import AuthStage
from gateway.apishield_gateway.config import Settings, hash_key
from gateway.apishield_gateway.spec import ApiSpec, load_spec_file

from .helpers import make_ctx, run

SPEC = ApiSpec(load_spec_file(Path(__file__).resolve().parents[2] / "demo_api" / "openapi.json"))
SECRET = "test-secret-that-is-long-enough-for-hs256"


def _settings(**kw):
    return Settings(jwt_secret=SECRET, api_keys={hash_key("good-key"): "client-a"}, **kw)


def _token(secret=SECRET, alg="HS256", **claims):
    payload = {"sub": "7", "exp": int(time.time()) + 600, **claims}
    return jwt.encode(payload, secret, algorithm=alg)


def _check(settings, path="/profile", **headers):
    ctx = make_ctx(path=path, headers=headers, spec=SPEC)
    return ctx, run(AuthStage(settings).on_request(ctx))


def test_valid_api_key_sets_masked_caller():
    ctx, decision = _check(_settings(), **{"X-API-Key": "good-key"})
    assert decision is None and ctx.authenticated
    assert ctx.caller.startswith("key_") and "good-key" not in ctx.caller


def test_unknown_api_key_is_401():
    _, decision = _check(_settings(), **{"X-API-Key": "nope"})
    assert decision.status == 401 and decision.hit == "auth.invalid_api_key"


def test_valid_jwt_sets_caller_from_subject():
    ctx, decision = _check(_settings(), Authorization=f"Bearer {_token()}")
    assert decision is None and ctx.caller == "user_7" and ctx.auth_method == "jwt"


def test_alg_none_is_rejected():
    forged = jwt.encode({"sub": "3", "role": "admin", "exp": int(time.time()) + 600}, None, algorithm="none")
    _, decision = _check(_settings(), Authorization=f"Bearer {forged}")
    assert decision.status == 401 and decision.hit == "auth.jwt_alg_none"


def test_expired_token_is_rejected():
    _, decision = _check(_settings(), Authorization=f"Bearer {_token(exp=int(time.time()) - 5)}")
    assert decision.hit == "auth.jwt_expired"


def test_wrong_signature_is_rejected():
    _, decision = _check(_settings(), Authorization=f"Bearer {_token(secret='x' * 40)}")
    assert decision.hit == "auth.jwt_bad_signature"


def test_wrong_issuer_and_audience_are_rejected():
    s = _settings(jwt_issuer="https://issuer.example", jwt_audience="my-api")
    good = _token(iss="https://issuer.example", aud="my-api")
    assert _check(s, Authorization=f"Bearer {good}")[1] is None
    bad_iss = _token(iss="https://evil.example", aud="my-api")
    assert _check(s, Authorization=f"Bearer {bad_iss}")[1].hit == "auth.jwt_wrong_issuer"
    bad_aud = _token(iss="https://issuer.example", aud="other-api")
    assert _check(s, Authorization=f"Bearer {bad_aud}")[1].hit == "auth.jwt_wrong_audience"


def test_algorithm_outside_allow_list_is_rejected():
    _, decision = _check(_settings(), Authorization=f"Bearer {_token(alg='HS512')}")
    assert decision.hit == "auth.jwt_alg_not_allowed"


def test_protected_route_without_credentials_is_401():
    _, decision = _check(_settings(), path="/admin/stats")
    assert decision.status == 401 and decision.hit == "auth.missing_credentials"
    assert decision.headers["WWW-Authenticate"] == "Bearer"


def test_public_route_allows_anonymous_and_uses_ip_as_caller():
    ctx, decision = _check(_settings(), path="/search")
    assert decision is None and ctx.caller == "ip_10.0.0.1" and not ctx.authenticated


def test_spec_auth_requirement_can_be_switched_off():
    _, decision = _check(_settings(enforce_spec_auth=False), path="/admin/stats")
    assert decision is None


def test_without_a_jwt_key_structural_checks_still_apply():
    s = Settings()  # no secret configured: upstream verifies signatures
    ok, decision = _check(s, Authorization=f"Bearer {_token()}")
    assert decision is None and ok.auth_method == "jwt_unverified" and not ok.authenticated
    expired = _token(exp=int(time.time()) - 5)
    assert _check(s, Authorization=f"Bearer {expired}")[1].hit == "auth.jwt_expired"
