"""Auth, upstreams and settings."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..auth import can, current_user, issue_token, user_view, verify_password
from ..deps import get_config, get_gateway, get_session
from ..errors import APIError
from ..models import SettingsRow, Upstream, User

router = APIRouter()


class LoginBody(BaseModel):
    email: str
    password: str


@router.post("/auth/login")
def login(body: LoginBody, session: Session = Depends(get_session), cfg=Depends(get_config)):
    user = session.scalar(select(User).where(func.lower(User.email) == body.email.strip().lower()))
    if user is None or not verify_password(body.password, user.password_hash):
        raise APIError(401, "invalid_credentials", "Email or password is incorrect.")
    return {"token": issue_token(user, cfg.jwt_secret, cfg.token_ttl_hours), "user": user_view(user)}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return user_view(user)


def upstream_view(u: Upstream) -> dict:
    return {"id": u.id, "name": u.name, "url": u.url}


@router.get("/upstreams")
def list_upstreams(session: Session = Depends(get_session), _user=Depends(current_user)):
    return [upstream_view(u) for u in session.scalars(select(Upstream).order_by(Upstream.id))]


def settings_view(session: Session) -> dict:
    row = session.get(SettingsRow, 1)
    return {"mode": row.mode, "fail_open": row.fail_open, "retention_days": row.retention_days,
            "redaction_patterns": list(row.redaction_patterns or []),
            "upstreams": [upstream_view(u) for u in session.scalars(select(Upstream).order_by(Upstream.id))]}


@router.get("/settings")
def get_settings(session: Session = Depends(get_session), _user=Depends(current_user)):
    return settings_view(session)


class SettingsPatch(BaseModel):
    mode: Literal["monitor", "enforce"] | None = None
    fail_open: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=365)
    redaction_patterns: list[str] | None = None


@router.patch("/settings")
async def patch_settings(body: SettingsPatch, session: Session = Depends(get_session),
                         user: User = Depends(current_user), gateway=Depends(get_gateway)):
    row = session.get(SettingsRow, 1)
    changes = body.model_dump(exclude_none=True)
    mode_change = "mode" in changes and changes["mode"] != row.mode
    other = {k: v for k, v in changes.items() if k != "mode"}
    if mode_change and not can(user.role, "mode.switch"):
        raise APIError(403, "forbidden", "Only admins can switch between monitor and enforce.")
    if other and not can(user.role, "settings.edit"):
        raise APIError(403, "forbidden", "Your role cannot change settings.")

    if mode_change:
        await gateway.set_mode(changes["mode"])  # raises (and saves nothing) if the gateway is down
        audit.record(session, user.email, "mode.change", "settings", **{"from": row.mode, "to": changes["mode"]})
        row.mode = changes["mode"]
    if other:
        # fail_open is stored only: the gateway reads it from its own config at start (no control endpoint).
        for key, value in other.items():
            setattr(row, key, value)
        audit.record(session, user.email, "settings.update", "settings", fields=sorted(other))
    session.commit()
    return settings_view(session)
