"""FastAPI dependencies: database session, config, shared services."""
from __future__ import annotations

from fastapi import Depends, Query, Request
from sqlalchemy.orm import Session

from .errors import not_found
from .models import Upstream


def get_session(request: Request):
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def get_config(request: Request):
    return request.app.state.config


def get_gateway(request: Request):
    return request.app.state.gateway


def get_ingestor(request: Request):
    return request.app.state.ingestor


def upstream_id(upstream_id: str = Query(..., description="Upstream to read"),
                session: Session = Depends(get_session)) -> str:
    if session.get(Upstream, upstream_id) is None:
        raise not_found("Upstream")
    return upstream_id
