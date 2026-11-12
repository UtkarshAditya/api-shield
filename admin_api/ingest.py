"""Traffic ingestion: reads the gateway's Redis stream with XREADGROUP (group `admin-api`),
pseudonymizes callers and IPs before anything is stored, updates the per-minute aggregates,
keeps a bounded buffer of recent events and fans them out to SSE subscribers.

If Redis is down, ingestion pauses with a warning and retries; the dashboard keeps reading
the stored aggregates and the in-memory recent buffer."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from .config import Config
from .db import utcnow
from .metrics import floor_time, is_blocked, latency_bucket
from .models import TrafficMinute, TrafficMinuteCaller, TrafficMinuteEndpoint, TrafficMinuteRule
from .privacy import pseudonymize

log = logging.getLogger("apishield.admin.ingest")

ACTIONS = ("allow", "log", "throttle", "challenge", "block")
AGGREGATE_TABLES = (TrafficMinute, TrafficMinuteEndpoint, TrafficMinuteCaller, TrafficMinuteRule)
_MINUTE = timedelta(minutes=1)


def _parse_ts(value) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def mask_event(event: dict, salt: str) -> dict | None:
    """The traffic event as the dashboard may see it: same fields, caller and ip pseudonymized.
    Returns None for an entry that is not a traffic event."""
    if not isinstance(event, dict) or _parse_ts(event.get("ts")) is None:
        return None
    raw_ip = str(event.get("ip") or "")
    caller = str(event.get("caller") or (f"ip_{raw_ip}" if raw_ip else "ip_unknown"))
    action = event.get("action") if event.get("action") in ACTIONS else "allow"
    return {
        "ts": str(event["ts"]),
        "req_id": str(event.get("req_id") or ""),
        "caller": pseudonymize(caller, salt),
        "ip": pseudonymize(raw_ip, salt) if raw_ip else "ip_unknown",
        "method": str(event.get("method") or "GET").upper(),
        "path_template": str(event.get("path_template") or "/"),
        "status": int(event.get("status") or 0),
        "latency_ms": float(event.get("latency_ms") or 0.0),
        "req_size": int(event.get("req_size") or 0),
        "resp_size": int(event.get("resp_size") or 0),
        "shape_hash": str(event.get("shape_hash") or ""),
        "rule_hits": [str(h) for h in (event.get("rule_hits") or [])],
        "action": action,
    }


def _row(session, table, **key):
    """Fetch an aggregate row by primary key, or add a zeroed one."""
    pk = tuple(key[c.name] for c in table.__table__.primary_key.columns)
    row = session.get(table, pk)
    if row is None:
        counters = {c: 0 for c in ("requests", "blocked", "hits") if hasattr(table, c)}
        row = table(**counters, **key)
        session.add(row)
    return row


class TrafficIngestor:
    def __init__(self, cfg: Config, session_factory, redis=None):
        self.cfg = cfg
        self.session_factory = session_factory
        self.redis = redis
        self.redis_ok = False
        self.processed = 0
        self.recent: deque = deque(maxlen=cfg.recent_events)  # (upstream_id, masked event), newest first
        self._subscribers: set = set()
        self._last_retention = 0.0

    # ---- processing (sync, runs in a worker thread) ----

    def process(self, raw_events: list, upstream_id: str | None = None) -> list:
        """Mask, aggregate and buffer a batch. Returns the masked events."""
        up = upstream_id or self.cfg.upstream_id
        masked = [m for m in (mask_event(e, self.cfg.pseudo_salt) for e in raw_events) if m]
        if masked:
            self._aggregate(up, masked)
            for event in masked:
                self.recent.appendleft((up, event))
            self.processed += len(masked)
        return masked

    def _aggregate(self, up: str, events: list) -> None:
        minutes: dict = {}
        endpoints: dict = {}
        callers: dict = {}
        rules: dict = {}
        for e in events:
            minute = floor_time(_parse_ts(e["ts"]), _MINUTE)
            blocked = 1 if is_blocked(e["action"]) else 0
            m = minutes.setdefault(minute, [0, 0, {}])
            m[0] += 1
            m[1] += blocked
            bucket = str(latency_bucket(e["latency_ms"]))
            m[2][bucket] = m[2].get(bucket, 0) + 1
            ep = endpoints.setdefault((minute, e["method"], e["path_template"]), [0, 0])
            ep[0] += 1
            ep[1] += blocked
            c = callers.setdefault((minute, e["caller"]), [0, 0])
            c[0] += 1
            c[1] += blocked
            for rule_id in e["rule_hits"]:
                rules[(minute, rule_id)] = rules.get((minute, rule_id), 0) + 1

        with self.session_factory() as session:
            for minute, (req, blk, hist) in minutes.items():
                row = _row(session, TrafficMinute, upstream_id=up, minute=minute, latency_hist={})
                row.requests += req
                row.blocked += blk
                merged = dict(row.latency_hist or {})
                for k, v in hist.items():
                    merged[k] = merged.get(k, 0) + v
                row.latency_hist = merged  # reassign so the JSON change is persisted
            for (minute, method, path), (req, blk) in endpoints.items():
                row = _row(session, TrafficMinuteEndpoint, upstream_id=up, minute=minute, method=method,
                           path_template=path)
                row.requests += req
                row.blocked += blk
            for (minute, caller), (req, blk) in callers.items():
                row = _row(session, TrafficMinuteCaller, upstream_id=up, minute=minute, caller=caller)
                row.requests += req
                row.blocked += blk
            for (minute, rule_id), hits in rules.items():
                row = _row(session, TrafficMinuteRule, upstream_id=up, minute=minute, rule_id=rule_id)
                row.hits += hits
            session.commit()

    def recent_events(self, upstream_id: str, limit: int) -> list:
        return [e for up, e in list(self.recent) if up == upstream_id][:limit]

    # ---- retention and purge ----

    def apply_retention(self, retention_days: int) -> int:
        cutoff = utcnow() - timedelta(days=retention_days)
        removed = 0
        with self.session_factory() as session:
            for table in AGGREGATE_TABLES:
                removed += session.execute(delete(table).where(table.minute < cutoff)).rowcount or 0
            session.commit()
        return removed

    def purge(self, upstream_id: str) -> tuple[int, int]:
        """Deletes every stored aggregate and buffered event for the upstream."""
        before = len(self.recent)
        self.recent = deque(((u, e) for u, e in self.recent if u != upstream_id), maxlen=self.recent.maxlen)
        removed = 0
        with self.session_factory() as session:
            for table in AGGREGATE_TABLES:
                removed += session.execute(delete(table).where(table.upstream_id == upstream_id)).rowcount or 0
            session.commit()
        return before - len(self.recent), removed

    # ---- SSE fan-out (event loop only) ----

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, events: list, upstream_id: str | None = None) -> None:
        up = upstream_id or self.cfg.upstream_id
        for queue in list(self._subscribers):
            for event in events:
                try:
                    queue.put_nowait((up, event))
                except asyncio.QueueFull:  # a slow client misses events; it never slows ingestion
                    break

    # ---- Redis consumer ----

    async def _ensure_group(self) -> None:
        """Create the consumer group if it is missing (M3 uses its own group, `learner`).
        Checks first, so the normal path never gets an error reply."""
        from redis.exceptions import ResponseError
        stream, group = self.cfg.event_stream, self.cfg.consumer_group
        if await self.redis.exists(stream):
            if any(g.get("name") == group for g in await self.redis.xinfo_groups(stream)):
                return
        try:
            await self.redis.xgroup_create(stream, group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):  # another instance created it first
                raise

    async def read_once(self, stream_id: str = ">", block_ms: int | None = 2000) -> int:
        """One XREADGROUP round: process, ack, publish. Returns the number of entries read."""
        resp = await self.redis.xreadgroup(self.cfg.consumer_group, self.cfg.consumer_name,
                                           {self.cfg.event_stream: stream_id}, count=500,
                                           block=block_ms if stream_id == ">" else None)
        read = 0
        for _stream, entries in resp or []:
            if not entries:
                continue
            ids, events = [], []
            for entry_id, fields in entries:
                ids.append(entry_id)
                try:
                    events.append(json.loads((fields or {}).get("data", "")))
                except (TypeError, ValueError):
                    log.debug("skipping malformed stream entry %s", entry_id)
            masked = await asyncio.to_thread(self.process, events)
            await self.redis.xack(self.cfg.event_stream, self.cfg.consumer_group, *ids)  # ack after commit
            self.publish(masked)
            read += len(entries)
        return read

    async def run(self, retention_days) -> None:
        """retention_days: a callable returning the current Settings.retention_days."""
        if self.redis is None and not self.cfg.redis_url:
            log.warning("APISHIELD_REDIS_URL is not set; traffic ingestion is off "
                        "(the dashboard shows stored data and the in-memory buffer only)")
            return
        backoff, pending_done = 1.0, False
        while True:
            try:
                if self.redis is None:
                    import redis.asyncio as aioredis
                    self.redis = aioredis.from_url(self.cfg.redis_url, decode_responses=True)
                if not self.redis_ok:  # (re)connected: make sure the group exists
                    await self._ensure_group()
                    log.info("reading %s as group %s", self.cfg.event_stream, self.cfg.consumer_group)
                self.redis_ok, backoff = True, 1.0
                if not pending_done:  # first re-read entries delivered to us but never acked
                    while await self.read_once("0"):
                        pass
                    pending_done = True
                await self.read_once()
                if time.monotonic() - self._last_retention > 600:
                    self._last_retention = time.monotonic()
                    await asyncio.to_thread(self.apply_retention, retention_days())
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # Redis down, network blip: never let the consumer die
                log.debug("traffic consumer error", exc_info=True)
                if self.redis_ok or backoff == 1.0:
                    log.warning("Redis unavailable (%s); traffic ingestion paused, serving stored data and "
                                "the in-memory buffer. Retrying.", type(exc).__name__)
                self.redis_ok = False
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
