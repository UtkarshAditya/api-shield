"""Users, passwords (bcrypt), JWTs and role checks. Permissions mirror
frontend/src/auth/roles.ts; keep the two in sync."""
from __future__ import annotations

from datetime import timedelta

import bcrypt
import jwt
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .db import utcnow
from .deps import get_session
from .errors import APIError
from .models import User

PERMISSIONS = {
    "admin": {"alerts.triage", "rules.edit", "scans.run", "settings.edit", "mode.switch",
              "data.purge", "users.manage"},
    "analyst": {"alerts.triage", "rules.edit", "scans.run"},
    "viewer": set(),
}
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def can(role: str | None, permission: str) -> bool:
    return role in PERMISSIONS and permission in PERMISSIONS[role]


def issue_token(user: User, secret: str, ttl_hours: int) -> str:
    now = utcnow()
    claims = {"sub": user.id, "role": user.role, "iat": now, "exp": now + timedelta(hours=ttl_hours)}
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def user_view(user: User) -> dict:
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role}


def _token_from(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # EventSource cannot send headers, so the SSE stream alone accepts ?access_token=.
    if request.url.path.endswith("/traffic/stream"):
        return request.query_params.get("access_token")
    return None


def current_user(request: Request, session: Session = Depends(get_session)) -> User:
    token = _token_from(request)
    if not token:
        raise APIError(401, "unauthorized", "Sign in to continue.")
    try:
        claims = jwt.decode(token, request.app.state.config.jwt_secret, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise APIError(401, "token_expired", "Session expired. Sign in again.") from None
    except jwt.InvalidTokenError:
        raise APIError(401, "unauthorized", "Invalid session.") from None
    user = session.get(User, claims.get("sub"))
    if user is None:
        raise APIError(401, "unauthorized", "Invalid session.")
    return user


def require(permission: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if not can(user.role, permission):
            raise APIError(403, "forbidden", "Your role does not allow this action.")
        return user
    return dependency
