import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import fakeredis
import pytest
from sqlalchemy import inspect

from admin_api import metrics
from admin_api.db import Base, iso
from admin_api.ingest import TrafficIngestor, mask_event
from admin_api.main import create_app
from admin_api.privacy import pseudonymize
from admin_api.routes.traffic import traffic_stream

from .conftest import SALT, event, make_config

NOW = datetime(2026, 11, 12, 10, 30, 20, tzinfo=timezone.utc)


def ts(minutes_ago: float = 0, base: datetime = NOW) -> str:
    return iso(base - timedelta(minutes=minutes_ago))


# ---- pure math -----------------------------------------------------------------------

def test_blocked_definition():
    assert [metrics.is_blocked(a) for a in ("allow", "log", "throttle", "challenge", "block")] == \
           [False, False, True, True, True]


def test_p95_nearest_rank_within_bucket_resolution():
    hist: dict = {}
    for latency in range(1, 101):  # 1..100 ms, exact nearest-rank p95 = 95
        key = str(metrics.latency_bucket(latency))
        hist[key] = hist.get(key, 0) + 1
    p95 = metrics.p95_from_hist(hist)
    assert 95 <= p95 <= 95 * 1.1
    assert metrics.p95_from_hist({}) == 0.0


def test_p95_ignores_fast_majority():
    hist: dict = {}
    for latency in [5.0] * 90 + [400.0] * 10:
        key = str(metrics.latency_bucket(latency))
        hist[key] = hist.get(key, 0) + 1
    assert 400 <= metrics.p95_from_hist(hist) <= 440


# ---- ingestion + aggregation -----------------------------------------------------------

@pytest.fixture
def ingest_app(gateway):
    import httpx
    return create_app(make_config(), gateway_transport=httpx.MockTransport(gateway.handler), run_background=False)


def test_mask_event_pseudonymizes_ip_and_user():
    masked = mask_event(event(ts(), caller="user_alice", ip="203.0.113.9"), SALT)
    assert masked["caller"] == pseudonymize("user_alice", SALT)
    assert masked["ip"] == pseudonymize("203.0.113.9", SALT)
    assert "203.0.113.9" not in json.dumps(masked) and "alice" not in json.dumps(masked)
    assert mask_event({"not": "an event"}, SALT) is None


def test_aggregates_counts_blocked_and_rule_hits(ingest_app):
    ing = ingest_app.state.ingestor
    ing.process([
        event(ts(0), action="allow"),
        event(ts(0), action="log", rule_hits=["log-rule"]),
        event(ts(0), action="block", status=403, rule_hits=["builtin-sqli"]),
        event(ts(1), action="throttle", status=429, rule_hits=["rule-ratelimit-login"]),
        event(ts(1), action="challenge", status=401, path="/admin/stats"),
        event(ts(90), action="allow"),  # previous hour
    ])
    with ingest_app.state.session_factory() as s:
        summary = metrics.summary(s, "up_shop", "1h", now=NOW)
        hits = metrics.rule_hits(s, "up_shop", NOW - timedelta(hours=24))
    assert (summary["requests"], summary["blocked"], summary["allowed"]) == (5, 3, 2)
    assert summary["previous"]["requests"] == 1
    assert hits == {"log-rule": 1, "builtin-sqli": 1, "rule-ratelimit-login": 1}
    search = next(e for e in summary["top_endpoints"] if e["path_template"] == "/search")
    assert (search["requests"], search["blocked"]) == (4, 2)


def test_p95_comes_from_ingested_data(ingest_app):
    ing = ingest_app.state.ingestor
    ing.process([event(ts(0), latency=float(i)) for i in range(1, 101)])
    with ingest_app.state.session_factory() as s:
        p95 = metrics.summary(s, "up_shop", "1h", now=NOW)["p95_latency_ms"]
    assert 95 <= p95 <= 104.5


@pytest.mark.parametrize("range_,points,step", [("1h", 60, timedelta(minutes=1)),
                                                ("24h", 96, timedelta(minutes=15)),
                                                ("7d", 84, timedelta(hours=2))])
def test_timeseries_bucket_sizes(ingest_app, range_, points, step):
    ingest_app.state.ingestor.process([event(ts(0)), event(ts(0), action="block")])
    with ingest_app.state.session_factory() as s:
        series = metrics.timeseries(s, "up_shop", range_, now=NOW)
    pts = series["points"]
    assert len(pts) == points
    starts = [datetime.fromisoformat(p["t"].replace("Z", "+00:00")) for p in pts]
    assert all(b - a == step for a, b in zip(starts, starts[1:]))
    assert sum(p["allowed"] for p in pts) == 1 and sum(p["blocked"] for p in pts) == 1
    assert pts[-1]["allowed"] + pts[-1]["blocked"] == 2  # the current bucket holds "now"


def test_events_land_in_the_right_bucket(ingest_app):
    ingest_app.state.ingestor.process([event(ts(16)), event(ts(14)), event(ts(14))])
    with ingest_app.state.session_factory() as s:
        pts = metrics.timeseries(s, "up_shop", "24h", now=NOW)["points"]
    # NOW is 10:30:20 -> buckets ...10:00, 10:15, 10:30. 16 min ago = 10:14:20 -> 10:00; 14 min ago -> 10:15
    assert [p["allowed"] for p in pts[-3:]] == [1, 2, 0]


def test_top_callers_are_pseudonymized(ingest_app):
    ingest_app.state.ingestor.process([event(ts(0), caller="ip_198.51.100.4", ip="198.51.100.4")] * 3)
    with ingest_app.state.session_factory() as s:
        callers = metrics.summary(s, "up_shop", "1h", now=NOW)["top_callers"]
    assert callers[0] == {"caller": pseudonymize("198.51.100.4", SALT), "requests": 3, "alerts": 0}


def test_retention_and_purge(ingest_app):
    ing = ingest_app.state.ingestor
    real_now = datetime.now(timezone.utc)
    ing.process([event(ts(0, real_now)), event(ts(60 * 24 * 20, real_now))])
    assert ing.apply_retention(14) == 3  # the old minute's total, endpoint and caller rows (no rule hits)
    buffered, rows = ing.purge("up_shop")
    assert buffered == 2 and rows == 3
    assert ing.recent_events("up_shop", 10) == []


# ---- Redis consumer ------------------------------------------------------------------------

def test_xreadgroup_consumer_acks_and_masks(ingest_app):
    async def scenario():
        redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        ing = TrafficIngestor(ingest_app.state.config, ingest_app.state.session_factory, redis=redis)
        await ing._ensure_group()
        await ing._ensure_group()  # BUSYGROUP is fine
        for i in range(3):
            await redis.xadd("apishield:traffic", {"data": json.dumps(event(ts(0), caller="user_bob", ip="10.1.1.1"))})
        await redis.xadd("apishield:traffic", {"data": "not json"})
        read = await ing.read_once(block_ms=10)
        pending = await redis.xpending("apishield:traffic", "admin-api")
        groups = await redis.xinfo_groups("apishield:traffic")
        return read, pending, groups, ing

    read, pending, groups, ing = asyncio.run(scenario())
    assert read == 4 and ing.processed == 3
    assert pending["pending"] == 0
    assert [g["name"] for g in groups] == ["admin-api"]
    recent = ing.recent_events("up_shop", 10)
    assert recent[0]["caller"] == pseudonymize("user_bob", SALT)
    assert "10.1.1.1" not in json.dumps(recent)


def test_consumer_survives_redis_outage(ingest_app, caplog):
    class DeadRedis:
        async def exists(self, *a, **k):
            raise ConnectionError("redis down")

    async def scenario():
        ing = TrafficIngestor(ingest_app.state.config, ingest_app.state.session_factory, redis=DeadRedis())
        task = asyncio.create_task(ing.run(lambda: 14))
        await asyncio.sleep(0.05)
        alive = not task.done()
        task.cancel()
        return alive, ing

    with caplog.at_level(logging.WARNING, logger="apishield.admin.ingest"):
        alive, ing = asyncio.run(scenario())
    assert alive and not ing.redis_ok
    assert "Redis unavailable" in caplog.text


# ---- REST + SSE ------------------------------------------------------------------------------

def test_recent_endpoint_returns_masked_events(client, app, as_viewer):
    app.state.ingestor.process([event(ts(0, datetime.now(timezone.utc)), caller="ip_192.0.2.55", ip="192.0.2.55")])
    resp = client.get("/api/traffic/recent?upstream_id=up_shop&limit=5", headers=as_viewer)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1 and body["items"][0]["caller"].startswith("ip_")
    assert "192.0.2.55" not in resp.text


def test_summary_and_timeseries_endpoints(client, app, as_viewer):
    app.state.ingestor.process([event(ts(0, datetime.now(timezone.utc)), action="block")])
    s = client.get("/api/metrics/summary?upstream_id=up_shop&range=1h", headers=as_viewer).json()
    assert s["requests"] == 1 and s["blocked"] == 1 and s["active_alerts"] == 4  # seeded new/acknowledged
    t = client.get("/api/metrics/timeseries?upstream_id=up_shop&range=7d", headers=as_viewer).json()
    assert len(t["points"]) == 84


def test_sse_stream_sends_events_and_heartbeats(app):
    app.state.sse_heartbeat = 0.05
    ing = app.state.ingestor

    class FakeRequest:
        def __init__(self):
            self.app = app

        async def is_disconnected(self):
            return False

    async def scenario():
        resp = await traffic_stream(FakeRequest(), up="up_shop", ingestor=ing, _user=None)
        it = resp.body_iterator
        first = await it.__anext__()
        masked = ing.process([event(ts(0, datetime.now(timezone.utc)), ip="203.0.113.200", caller="ip_203.0.113.200")])
        ing.publish(masked)
        ing.publish(masked, upstream_id="up_other")  # filtered out
        second = await it.__anext__()
        third = await it.__anext__()
        await it.aclose()
        return first, second, third, resp.media_type

    first, second, third, media = asyncio.run(scenario())
    assert media == "text/event-stream"
    assert first == ": connected\n\n"
    assert second.startswith("event: traffic\ndata: ") and "203.0.113.200" not in second
    assert third == ": ping\n\n"


def test_sse_accepts_query_token_only_on_stream(client, as_viewer):
    token = as_viewer["Authorization"].split()[1]
    assert client.get(f"/api/me?access_token={token}").status_code == 401


# ---- migrations -------------------------------------------------------------------------------

def test_alembic_migration_matches_models(tmp_path, gateway):
    import httpx
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    app = create_app(make_config(database_url=url, auto_migrate=True),
                     gateway_transport=httpx.MockTransport(gateway.handler), run_background=False)
    tables = set(inspect(app.state.engine).get_table_names()) - {"alembic_version"}
    assert tables == set(Base.metadata.tables)
