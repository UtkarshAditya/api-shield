"""Stage 2: authentication checks (API key lookup and JWT verification)."""
from __future__ import annotations

import jwt

from .config import Settings, hash_key
from .context import Decision, RequestContext

_CHALLENGE = {"WWW-Authenticate": "Bearer"}


class AuthStage:
    name = "auth"

    def __init__(self, settings: Settings):
        self.s = settings

    async def on_request(self, ctx: RequestContext):
        s = self.s
        ctx.caller = f"ip_{ctx.ip}"
        api_key = ctx.header(s.api_key_header)
        authorization = ctx.header("authorization")

        if api_key:
            ctx.credential_presented = True
            digest = hash_key(api_key)
            if digest not in s.api_keys:
                return self._deny("invalid_api_key", "Unknown API key")
            ctx.authenticated = True
            ctx.auth_method = "api_key"
            ctx.caller = f"key_{digest[:8]}"  # a stable ID that never exposes the key
        elif authorization[:7].lower() == "bearer ":
            ctx.credential_presented = True
            reason = self._verify_jwt(ctx, authorization[7:].strip())
            if reason:
                return self._deny(*reason)

        needs_auth = ctx.operation is not None and ctx.operation.requires_auth
        if s.enforce_spec_auth and needs_auth and not self._has_credential(ctx):
            return Decision(401, "auth_required", "This endpoint requires authentication",
                            hit="auth.missing_credentials", headers=_CHALLENGE)
        return None

    def _has_credential(self, ctx: RequestContext) -> bool:
        # With no JWT key configured the gateway cannot verify tokens itself, so a
        # structurally valid token is passed on for the upstream to verify.
        return ctx.authenticated or ctx.auth_method == "jwt_unverified"

    def _deny(self, code: str, message: str) -> Decision:
        return Decision(401, code, message, hit=f"auth.{code}", headers=_CHALLENGE)

    def _verify_jwt(self, ctx: RequestContext, token: str):
        s = self.s
        try:
            alg = str(jwt.get_unverified_header(token).get("alg", "none"))
        except jwt.PyJWTError:
            return "jwt_malformed", "Malformed token"
        if alg.lower() == "none":
            return "jwt_alg_none", "Unsigned tokens (alg=none) are not accepted"

        if not s.jwt_secret:
            try:  # no key to verify with: structural checks only (format and expiry)
                claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": True,
                                                    "verify_aud": False})
            except jwt.ExpiredSignatureError:
                return "jwt_expired", "Token has expired"
            except jwt.PyJWTError:
                return "jwt_malformed", "Malformed token"
            ctx.auth_method = "jwt_unverified"
            ctx.claims = claims
            return None

        if alg not in s.jwt_algorithms:
            return "jwt_alg_not_allowed", "Token signing algorithm is not accepted"
        try:
            claims = jwt.decode(
                token, s.jwt_secret, algorithms=s.jwt_algorithms,
                issuer=s.jwt_issuer, audience=s.jwt_audience,
                options={"require": ["exp"], "verify_aud": bool(s.jwt_audience)},
            )
        except jwt.ExpiredSignatureError:
            return "jwt_expired", "Token has expired"
        except jwt.InvalidIssuerError:
            return "jwt_wrong_issuer", "Token issuer is not accepted"
        except jwt.InvalidAudienceError:
            return "jwt_wrong_audience", "Token audience is not accepted"
        except jwt.InvalidSignatureError:
            return "jwt_bad_signature", "Token signature is invalid"
        except jwt.PyJWTError:
            return "jwt_invalid", "Token is invalid"
        ctx.authenticated = True
        ctx.auth_method = "jwt"
        ctx.claims = claims
        if claims.get("sub") is not None:
            ctx.caller = f"user_{claims['sub']}"
        return None
