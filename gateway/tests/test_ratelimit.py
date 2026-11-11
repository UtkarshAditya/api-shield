import pytest

from gateway.apishield_gateway.config import LimitRule, Settings
from gateway.apishield_gateway.ratelimit import MemoryBucketStore, RateLimitStage, RedisBucketStore

from .helpers import make_ctx, run


def _drain(store, key, rate, burst, now, n):
    return [run(store.take_many([(key, rate, burst)], now=now))[0][0] for _ in range(n)]


def test_bucket_allows_burst_then_denies_with_retry_after():
    store = MemoryBucketStore()
    assert _drain(store, "k", 1.0, 3, 100.0, 4) == [True, True, True, False]
    allowed, retry = run(store.take_many([("k", 1.0, 3)], now=100.0))[0]
    assert not allowed and retry == pytest.approx(1.0)


def test_bucket_refills_over_time():
    store = MemoryBucketStore()
    _drain(store, "k", 0.5, 2, 100.0, 2)
    assert _drain(store, "k", 0.5, 2, 101.0, 1) == [False]  # only half a token back
    assert _drain(store, "k", 0.5, 2, 102.0, 1) == [True]


def test_buckets_are_independent_per_key():
    store = MemoryBucketStore()
    _drain(store, "a", 1.0, 1, 100.0, 1)
    assert _drain(store, "b", 1.0, 1, 100.0, 1) == [True]


def test_redis_lua_bucket_matches_memory_bucket():
    fakeredis = pytest.importorskip("fakeredis")
    pytest.importorskip("lupa")

    async def scenario():
        client = fakeredis.FakeAsyncRedis(decode_responses=True)
        store = RedisBucketStore(client)
        out = [(await store.take_many([("k", 1.0, 3)], now=100.0))[0][0] for _ in range(4)]
        denied = (await store.take_many([("k", 1.0, 3)], now=100.0))[0]
        later = (await store.take_many([("k", 1.0, 3)], now=101.5))[0]
        ttl = await client.ttl("apishield:rl:k")
        await client.aclose()
        return out, denied, later, ttl

    out, denied, later, ttl = run(scenario())
    assert out == [True, True, True, False]
    assert denied[0] is False and denied[1] == pytest.approx(1.0)
    assert later[0] is True
    assert 0 < ttl <= 4  # idle buckets expire on their own


def _stage(*rules, fail_open=True, store=None):
    return RateLimitStage(Settings(rate_limits=list(rules), fail_open=fail_open), store or MemoryBucketStore())


def test_stage_returns_429_with_retry_after():
    stage = _stage(LimitRule(id="login", scope="endpoint", limit=2, per=60, method="POST", path="/login"))
    results = [run(stage.on_request(make_ctx(method="POST", path="/login"))) for _ in range(3)]
    assert results[0] is None and results[1] is None
    assert results[2].status == 429 and results[2].hit == "ratelimit.login"
    assert int(results[2].headers["Retry-After"]) >= 1


def test_endpoint_limit_does_not_touch_other_routes_or_callers():
    stage = _stage(LimitRule(id="login", scope="endpoint", limit=1, per=60, method="POST", path="/login"))
    assert run(stage.on_request(make_ctx(method="POST", path="/login"))) is None
    assert run(stage.on_request(make_ctx(method="POST", path="/login"))).status == 429
    assert run(stage.on_request(make_ctx(method="GET", path="/search"))) is None
    assert run(stage.on_request(make_ctx(method="POST", path="/login", ip="10.0.0.2"))) is None


def test_ip_scope_is_shared_across_callers_on_one_ip():
    stage = _stage(LimitRule(id="per-ip", scope="ip", limit=1, per=60))
    first, second = make_ctx(), make_ctx()
    first.caller, second.caller = "key_aaaa", "key_bbbb"
    assert run(stage.on_request(first)) is None
    assert run(stage.on_request(second)).hit == "ratelimit.per-ip"


class _BrokenStore:
    async def take_many(self, checks, now=None):
        raise ConnectionError("redis down")


def test_backend_failure_fails_open_or_closed():
    rule = LimitRule(id="any", limit=1, per=60)
    ctx = make_ctx()
    assert run(_stage(rule, store=_BrokenStore()).on_request(ctx)) is None
    assert "ratelimit.backend_error" in ctx.rule_hits
    assert run(_stage(rule, fail_open=False, store=_BrokenStore()).on_request(make_ctx())).status == 503
