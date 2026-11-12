"""Metrics, recent traffic and the live SSE stream."""
from __future__ import annotations

import asyncio
import json
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .. import metrics
from ..auth import current_user
from ..deps import get_config, get_ingestor, get_session, upstream_id

router = APIRouter()
RangeParam = Literal["1h", "24h", "7d"]
HEARTBEAT_SECONDS = 15.0


@router.get("/metrics/summary")
def metrics_summary(range: RangeParam = "24h", up: str = Depends(upstream_id),
                    session: Session = Depends(get_session), _user=Depends(current_user), cfg=Depends(get_config)):
    return metrics.summary(session, up, range, salt=cfg.pseudo_salt)


@router.get("/metrics/timeseries")
def metrics_timeseries(range: RangeParam = "24h", metric: Literal["requests"] = "requests",
                       up: str = Depends(upstream_id), session: Session = Depends(get_session),
                       _user=Depends(current_user)):
    return metrics.timeseries(session, up, range)


@router.get("/traffic/recent")
def traffic_recent(limit: int = Query(100, ge=1, le=1000), up: str = Depends(upstream_id),
                   ingestor=Depends(get_ingestor), _user=Depends(current_user)):
    items = ingestor.recent_events(up, limit)
    return {"items": items, "total": len(items)}


@router.get("/traffic/stream")
async def traffic_stream(request: Request, up: str = Depends(upstream_id), ingestor=Depends(get_ingestor),
                         _user=Depends(current_user)):
    """Server-sent events: `event: traffic` with one masked event per message, and a
    `: ping` comment every 15 s so proxies keep the connection open."""
    heartbeat = request.app.state.sse_heartbeat

    async def stream():
        queue = ingestor.subscribe()
        try:
            yield ": connected\n\n"
            while True:
                try:
                    event_up, event = await asyncio.wait_for(queue.get(), timeout=heartbeat)
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        return
                    yield ": ping\n\n"
                    continue
                if event_up == up:
                    yield f"event: traffic\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
        finally:
            ingestor.unsubscribe(queue)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
