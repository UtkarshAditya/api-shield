"""Demo-replay alerts: a stand-in until the learner (M3) writes alerts into the shared table.

It reads the ingestor's recent events (already masked: callers carry the Admin API's own
pseudonyms, so an alert's caller matches the same caller in /traffic/recent) and compares each
caller with the rest of the traffic in the same window (the "normal" population):

  * request rate per endpoint        vs the other callers' rate on that endpoint
  * failed responses (4xx/5xx)       vs the other callers' failure ratio there
  * gateway rule hits               vs the other callers' hit ratio there
  * payload shapes / endpoints       never seen from any other caller

Each reason carries {feature, observed, baseline, z}, computed from the data. Alerts are
upserted under a deterministic id ("al_demo_" + hash of upstream, caller, endpoint), so running
it again updates the same rows instead of duplicating them, and an analyst's status (for
example false_positive) is kept. Every generated alert says in its explanation that it comes
from the demo replay, not from M3. Only pseudonymized ids and counts are ever stored.
"""
from __future__ import annotations

import hashlib
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select

from .db import utcnow
from .ingest import _parse_ts
from .models import AlertRow

ID_PREFIX = "al_demo_"
MARKER = "(Demo replay: computed by the Admin API from recent traffic, not by the M3 learner.)"
WINDOW = timedelta(minutes=15)
MIN_REQUESTS = 5          # fewer requests than this from one caller on one endpoint: no alert
MIN_SCORE = 0.5
Z_CAP = 99.0
BUCKET = timedelta(seconds=15)  # alert timeline resolution
BUCKETS = 20                    # 5 minutes of timeline, ending at the caller's last request


@dataclass
class Stats:
    count: int = 0
    failed: int = 0
    flagged: int = 0
    first: datetime | None = None
    last: datetime | None = None

    def add(self, ts: datetime, event: dict) -> None:
        self.count += 1
        self.failed += int(event.get("status", 0) >= 400)
        self.flagged += int(bool(event.get("rule_hits")) or event.get("action") not in ("allow", None))
        self.first = ts if self.first is None or ts < self.first else self.first
        self.last = ts if self.last is None or ts > self.last else self.last

    def per_minute(self) -> float:
        span = (self.last - self.first).total_seconds() / 60 if self.first and self.last else 0
        return self.count / max(span, 1.0)  # at least a one-minute window


def _z(observed: float, baseline: list, floor: float) -> float:
    mean = statistics.fmean(baseline) if baseline else 0.0
    spread = statistics.pstdev(baseline) if len(baseline) > 1 else 0.0
    return round(min(Z_CAP, (observed - mean) / max(spread, floor, 0.25 * mean)), 1)


def _pct(x: float) -> str:
    return f"{round(100 * x)}%"


def _alert_id(upstream_id: str, caller: str, endpoint: str) -> str:
    return ID_PREFIX + hashlib.sha256(f"{upstream_id}|{caller}|{endpoint}".encode()).hexdigest()[:12]


def detect(events: list, upstream_id: str, now: datetime | None = None) -> list:
    """Alerts (as dicts for AlertRow) for callers that stand out from the rest of the traffic."""
    now = now or utcnow()
    window = []
    for e in events:
        ts = _parse_ts(e.get("ts"))
        if ts is not None and now - WINDOW <= ts <= now + timedelta(minutes=1):
            window.append((ts, e))

    per = defaultdict(Stats)                    # (caller, endpoint) -> Stats
    shapes = defaultdict(set)                   # (caller, endpoint) -> shape hashes
    times = defaultdict(list)                   # (caller, endpoint) -> request times
    for ts, e in window:
        key = (e["caller"], f"{e['method']} {e['path_template']}")
        per[key].add(ts, e)
        times[key].append(ts)
        if e.get("shape_hash"):
            shapes[key].add(e["shape_hash"])

    by_endpoint = defaultdict(list)
    for (caller, endpoint), stats in per.items():
        by_endpoint[endpoint].append((caller, stats))

    alerts = []
    for (caller, endpoint), s in per.items():
        if s.count < MIN_REQUESTS:
            continue
        peers = [p for c, p in by_endpoint[endpoint] if c != caller]
        peer_shapes = set().union(*(shapes[(c, endpoint)] for c, _ in by_endpoint[endpoint] if c != caller))
        reasons = []

        rate = s.per_minute()
        if not peers:
            reasons.append({"feature": "Endpoint never seen in normal traffic", "observed": f"{s.count} requests",
                            "baseline": "0 requests from other callers", "z": round(min(Z_CAP, 3.0 + s.count / 5), 1)})
        else:
            peer_rates = [p.per_minute() for p in peers]
            z = _z(rate, peer_rates, floor=1.0)
            if z >= 3:
                reasons.append({"feature": "Request rate", "observed": f"{rate:.0f} req/min",
                                "baseline": f"{statistics.fmean(peer_rates):.0f} req/min", "z": z})

            def ratio(field: str):
                observed = getattr(s, field) / s.count
                base = [getattr(p, field) / p.count for p in peers]
                return observed, base, _z(observed, base, floor=0.05)

            fail, fail_base, z = ratio("failed")
            if fail >= 0.3 and z >= 3:
                feature = "Failed logins" if endpoint.endswith("/login") else "Error ratio"
                reasons.append({"feature": feature, "observed": f"{_pct(fail)} of {s.count} requests failed",
                                "baseline": _pct(statistics.fmean(fail_base)), "z": z})
            hit, hit_base, z = ratio("flagged")
            if hit >= 0.3 and z >= 3:
                reasons.append({"feature": "Gateway rule hits", "observed": f"{_pct(hit)} of requests",
                                "baseline": _pct(statistics.fmean(hit_base)), "z": z})
            new_shapes = shapes[(caller, endpoint)] - peer_shapes
            if new_shapes:
                reasons.append({"feature": "New payload shape", "observed": f"{len(new_shapes)} shape(s) never seen",
                                "baseline": f"{len(peer_shapes)} known shape(s)",
                                "z": round(min(Z_CAP, 3.0 + 2 * len(new_shapes)), 1)})
        if not reasons:
            continue

        reasons.sort(key=lambda r: r.get("z") or 0, reverse=True)
        top = reasons[0].get("z") or 0
        score = round(min(0.99, 1 - math.exp(-top / 4) + 0.03 * (len(reasons) - 1)), 2)
        if score < MIN_SCORE:
            continue
        severity = "critical" if score >= 0.9 else "high" if score >= 0.75 else "medium"
        timeline = _timeline(times[(caller, endpoint)], s.last)
        alerts.append({
            "id": _alert_id(upstream_id, caller, endpoint), "upstream_id": upstream_id, "ts": s.last,
            "caller": caller, "endpoint": endpoint, "score": score, "severity": severity, "reasons": reasons,
            "explanation": _explain(caller, endpoint, s, reasons), "group_id": "grp_demo_" + caller[-8:],
            "timeline": timeline,
        })
    return alerts


def _timeline(times: list, last: datetime) -> list:
    """Requests per 15 s bucket over the 5 minutes up to `last`, zeros included."""
    end = last.timestamp() - last.timestamp() % BUCKET.total_seconds() + BUCKET.total_seconds()
    start = end - BUCKETS * BUCKET.total_seconds()
    counts = [0] * BUCKETS
    for t in times:
        i = int((t.timestamp() - start) // BUCKET.total_seconds())
        if 0 <= i < BUCKETS:
            counts[i] += 1
    return [{"ts": datetime.fromtimestamp(start + i * BUCKET.total_seconds(), last.tzinfo).isoformat().replace("+00:00", "Z"),
             "count": n} for i, n in enumerate(counts)]


def _explain(caller: str, endpoint: str, s: Stats, reasons: list) -> str:
    features = {r["feature"] for r in reasons}
    parts = [f"This caller sent {s.count} requests to {endpoint}"]
    if "Endpoint never seen in normal traffic" in features:
        parts.append("an endpoint no other caller used")
    if "Request rate" in features:
        rate = next(r for r in reasons if r["feature"] == "Request rate")
        parts.append(f"at {rate['observed']} against a normal {rate['baseline']}")
    text = ", ".join(parts) + "."
    if "Failed logins" in features:
        text += " Most logins failed, which usually means password guessing."
    elif "Error ratio" in features:
        text += " Most of its requests failed."
    if "Gateway rule hits" in features:
        text += " Many requests matched gateway rules (for example the SQL injection signature or the login rate limit)."
    if "New payload shape" in features:
        text += " It also sent payload shapes that normal callers never send."
    return f"{text} {MARKER}"


def upsert(session, alerts: list) -> dict:
    """Writes the alerts idempotently and re-ranks the upstream's alerts (active first, by score)."""
    created = updated = 0
    for data in alerts:
        row = session.get(AlertRow, data["id"])
        if row is None:
            session.add(AlertRow(rank=0, status="new", **data))
            created += 1
        else:  # keep the analyst's status
            for key in ("ts", "caller", "endpoint", "score", "severity", "reasons", "explanation", "group_id", "timeline"):
                setattr(row, key, data[key])
            updated += 1
    session.flush()
    for up in {a["upstream_id"] for a in alerts}:
        rows = list(session.scalars(select(AlertRow).where(AlertRow.upstream_id == up)))
        rows.sort(key=lambda r: (r.status not in ("new", "acknowledged"), -r.score, r.id))
        for i, row in enumerate(rows, 1):
            row.rank = i
    session.commit()
    return {"created": created, "updated": updated, "alerts": [a["id"] for a in alerts]}


def run_once(session_factory, ingestor, upstream_id: str, now: datetime | None = None) -> dict:
    alerts = detect(ingestor.recent_events(upstream_id, ingestor.recent.maxlen or 2000), upstream_id, now)
    if not alerts:
        return {"created": 0, "updated": 0, "alerts": []}
    with session_factory() as session:
        return upsert(session, alerts)
