"""Aggregation math over the per-minute traffic tables: time buckets, totals, p95 latency,
top endpoints and callers, rule hits, and the API risk score from the latest scan."""
from __future__ import annotations

import bisect
import math
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scanner.apishield_scanner.risk import endpoint_risk

from .db import iso
from .masking import safe_caller
from .models import AlertRow, FindingRow, ScanRow, TrafficMinute, TrafficMinuteCaller, TrafficMinuteEndpoint, TrafficMinuteRule

# `blocked` per M1: anything the gateway stopped. Everything else (allow, log) is allowed.
BLOCKED_ACTIONS = frozenset({"block", "throttle", "challenge"})

# range -> (window, bucket size): 60 x 1 min, 96 x 15 min, 84 x 2 h
RANGES = {
    "1h": (timedelta(hours=1), timedelta(minutes=1)),
    "24h": (timedelta(hours=24), timedelta(minutes=15)),
    "7d": (timedelta(days=7), timedelta(hours=2)),
}

# Latency histogram: bucket i holds latencies <= LATENCY_BOUNDS[i] ms. Bounds grow by 10%,
# so a p95 read from the histogram is at most 10% above the exact value.
LATENCY_BOUNDS = [round(0.25 * 1.1 ** i, 3) for i in range(121)]  # 0.25 ms .. ~23 s, then overflow
ACTIVE_ALERT_STATUSES = ("new", "acknowledged")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def is_blocked(action: str) -> bool:
    return action in BLOCKED_ACTIONS


def floor_time(ts: datetime, step: timedelta) -> datetime:
    return _EPOCH + ((ts - _EPOCH) // step) * step


def latency_bucket(latency_ms: float) -> int:
    return bisect.bisect_left(LATENCY_BOUNDS, latency_ms)  # len(LATENCY_BOUNDS) = overflow


def merge_hist(target: dict, other: dict) -> dict:
    for key, count in (other or {}).items():
        target[str(key)] = target.get(str(key), 0) + count
    return target


def p95_from_hist(hist: dict) -> float:
    """Nearest-rank 95th percentile, reported as the upper bound of its bucket."""
    total = sum(hist.values())
    if not total:
        return 0.0
    rank = math.ceil(0.95 * total)
    seen = 0
    for idx in sorted(int(k) for k in hist):
        seen += hist[str(idx)]
        if seen >= rank:
            return LATENCY_BOUNDS[min(idx, len(LATENCY_BOUNDS) - 1)]
    return LATENCY_BOUNDS[-1]


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def window(range_: str, now: datetime | None = None) -> tuple[datetime, datetime]:
    """[start, end) covering the last `range` of whole minutes, including the current minute."""
    span, _ = RANGES[range_]
    end = floor_time(_now(now), timedelta(minutes=1)) + timedelta(minutes=1)
    return end - span, end


# ---- Time series ------------------------------------------------------------------

def timeseries(session: Session, upstream_id: str, range_: str, now: datetime | None = None) -> dict:
    span, step = RANGES[range_]
    end = floor_time(_now(now), step) + step
    start = end - span
    counts = {start + k * step: [0, 0] for k in range(span // step)}
    rows = session.execute(
        select(TrafficMinute.minute, TrafficMinute.requests, TrafficMinute.blocked)
        .where(TrafficMinute.upstream_id == upstream_id, TrafficMinute.minute >= start, TrafficMinute.minute < end)
    )
    for minute, requests, blocked in rows:
        bucket = counts[floor_time(minute, step)]
        bucket[0] += requests - blocked
        bucket[1] += blocked
    return {"range": range_, "metric": "requests",
            "points": [{"t": iso(t), "allowed": a, "blocked": b} for t, (a, b) in sorted(counts.items())]}


# ---- Summary ----------------------------------------------------------------------

def totals(session: Session, upstream_id: str, start: datetime, end: datetime) -> dict:
    requests = blocked = 0
    hist: dict = {}
    for row in session.scalars(select(TrafficMinute).where(
            TrafficMinute.upstream_id == upstream_id, TrafficMinute.minute >= start, TrafficMinute.minute < end)):
        requests += row.requests
        blocked += row.blocked
        merge_hist(hist, row.latency_hist)
    return {"requests": requests, "blocked": blocked, "allowed": requests - blocked,
            "p95_latency_ms": p95_from_hist(hist)}


def rule_hits(session: Session, upstream_id: str, since: datetime) -> dict:
    rows = session.execute(
        select(TrafficMinuteRule.rule_id, func.sum(TrafficMinuteRule.hits))
        .where(TrafficMinuteRule.upstream_id == upstream_id, TrafficMinuteRule.minute >= since)
        .group_by(TrafficMinuteRule.rule_id)
    )
    return {rule_id: int(hits or 0) for rule_id, hits in rows}


def endpoint_requests(session: Session, upstream_id: str, since: datetime) -> dict:
    rows = session.execute(
        select(TrafficMinuteEndpoint.method, TrafficMinuteEndpoint.path_template,
               func.sum(TrafficMinuteEndpoint.requests), func.sum(TrafficMinuteEndpoint.blocked))
        .where(TrafficMinuteEndpoint.upstream_id == upstream_id, TrafficMinuteEndpoint.minute >= since)
        .group_by(TrafficMinuteEndpoint.method, TrafficMinuteEndpoint.path_template)
    )
    return {(m, p): (int(r or 0), int(b or 0)) for m, p, r, b in rows}


def latest_scan(session: Session, upstream_id: str) -> ScanRow | None:
    return session.scalar(select(ScanRow).where(ScanRow.upstream_id == upstream_id, ScanRow.status == "done")
                          .order_by(ScanRow.started_at.desc()).limit(1))


def current_risk(session: Session, upstream_id: str) -> dict:
    """Risk from the latest finished scan, counting only findings that are still open.
    Endpoints whose findings are all mitigated score 0 but stay in the average, so applying
    a suggested rule always lowers the score. `previous` is the scan's own score."""
    scan = latest_scan(session, upstream_id)
    if scan is None:
        return {"risk_score": 0.0, "previous": 0.0, "drivers": [], "endpoint_risk": {}}
    findings = list(session.scalars(select(FindingRow).where(FindingRow.scan_id == scan.id)))
    open_findings = [f for f in findings if f.status == "open"]
    open_scores = endpoint_risk([SimpleNamespace(endpoint=f.endpoint, risk_score=f.risk_score) for f in open_findings])
    endpoints = set(scan.endpoint_risk or {}) | {f.endpoint for f in findings}
    per_endpoint = {ep: open_scores.get(ep, 0.0) for ep in endpoints}
    score = round(sum(per_endpoint.values()) / len(per_endpoint), 1) if per_endpoint else 0.0
    drivers = [{"title": f.title, "endpoint": f"{f.method} {f.endpoint}", "severity": f.severity,
                "risk_score": f.risk_score}
               for f in sorted(open_findings, key=lambda f: f.risk_score, reverse=True)[:3]]
    return {"risk_score": score, "previous": scan.api_risk_score or 0.0, "drivers": drivers,
            "endpoint_risk": per_endpoint}


def summary(session: Session, upstream_id: str, range_: str, now: datetime | None = None, salt: str = "") -> dict:
    start, end = window(range_, now)
    span = end - start
    cur = totals(session, upstream_id, start, end)
    prev = totals(session, upstream_id, start - span, start)
    risk = current_risk(session, upstream_id)

    ep_rows = session.execute(
        select(TrafficMinuteEndpoint.method, TrafficMinuteEndpoint.path_template,
               func.sum(TrafficMinuteEndpoint.requests).label("req"), func.sum(TrafficMinuteEndpoint.blocked))
        .where(TrafficMinuteEndpoint.upstream_id == upstream_id,
               TrafficMinuteEndpoint.minute >= start, TrafficMinuteEndpoint.minute < end)
        .group_by(TrafficMinuteEndpoint.method, TrafficMinuteEndpoint.path_template)
        .order_by(func.sum(TrafficMinuteEndpoint.requests).desc()).limit(10)
    )
    top_endpoints = [{"method": m, "path_template": p, "requests": int(r), "blocked": int(b),
                      "risk_score": risk["endpoint_risk"].get(p, 0.0)} for m, p, r, b in ep_rows]

    alerts = list(session.scalars(select(AlertRow).where(AlertRow.upstream_id == upstream_id)))
    caller_rows = session.execute(
        select(TrafficMinuteCaller.caller, func.sum(TrafficMinuteCaller.requests))
        .where(TrafficMinuteCaller.upstream_id == upstream_id,
               TrafficMinuteCaller.minute >= start, TrafficMinuteCaller.minute < end)
        .group_by(TrafficMinuteCaller.caller)
        .order_by(func.sum(TrafficMinuteCaller.requests).desc()).limit(5)
    )
    top_callers = [{"caller": safe_caller(c, salt), "requests": int(r),
                    "alerts": sum(1 for a in alerts if a.caller == c and a.status != "false_positive")}
                   for c, r in caller_rows]

    active = sum(1 for a in alerts if a.status in ACTIVE_ALERT_STATUSES)
    # Previous period: alerts raised in that window and not dismissed as false positives.
    prev_alerts = sum(1 for a in alerts if start - span <= a.ts < start and a.status != "false_positive")

    return {
        "range": range_,
        "requests": cur["requests"], "blocked": cur["blocked"], "allowed": cur["allowed"],
        "active_alerts": active,
        "p95_latency_ms": cur["p95_latency_ms"],
        "risk_score": risk["risk_score"],
        "risk_drivers": risk["drivers"],
        "previous": {"requests": prev["requests"], "blocked": prev["blocked"], "active_alerts": prev_alerts,
                     "p95_latency_ms": prev["p95_latency_ms"], "risk_score": risk["previous"]},
        "top_endpoints": top_endpoints,
        "top_callers": top_callers,
    }
