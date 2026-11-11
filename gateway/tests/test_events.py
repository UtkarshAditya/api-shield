import asyncio
import json

import pytest

from gateway.apishield_gateway.events import (EVENT_FIELDS, EventEmitter, MemorySink,
                                              RedisStreamSink, build_event)

from .helpers import make_ctx, run


def test_event_has_exactly_the_contract_fields():
    ctx = make_ctx(method="POST", path="/login", json_body={"username": "a", "password": "b"})
    ctx.hit("ratelimit.login", "block")
    event = build_event(ctx, status=429, resp_size=80, latency_ms=1.23456)
    assert tuple(event) == EVENT_FIELDS
    assert event["method"] == "POST" and event["path_template"] == "/login"
    assert event["status"] == 429 and event["action"] == "block"
    assert event["rule_hits"] == ["ratelimit.login"] and event["latency_ms"] == 1.23
    assert event["req_size"] == len(ctx.body) and event["ts"].endswith("Z")
    assert "password" not in json.dumps(event)  # shapes, not contents


def test_emitter_delivers_in_order():
    async def scenario():
        sink = MemorySink()
        emitter = EventEmitter(sink)
        await emitter.start()
        for i in range(250):
            emitter.emit({"n": i})
        await emitter.flush()
        await emitter.stop()
        return [e["n"] for e in sink.events]

    assert run(scenario()) == list(range(250))


class _SlowSink:
    def __init__(self):
        self.release = asyncio.Event()
        self.count = 0

    async def write(self, batch):
        await self.release.wait()
        self.count += len(batch)


def test_emit_never_blocks_and_drops_when_the_queue_is_full():
    async def scenario():
        sink = _SlowSink()
        emitter = EventEmitter(sink, queue_size=10, batch_size=1)
        await emitter.start()
        loop = asyncio.get_running_loop()
        started = loop.time()
        for i in range(1000):
            emitter.emit({"n": i})  # sink is stuck, emit must still return at once
        elapsed = loop.time() - started
        dropped = emitter.dropped
        sink.release.set()
        await emitter.flush()
        await emitter.stop()
        return elapsed, dropped, sink.count

    elapsed, dropped, delivered = run(scenario())
    assert elapsed < 0.5
    assert dropped >= 989 and dropped + delivered == 1000


class _FailingSink:
    async def write(self, batch):
        raise ConnectionError("redis down")


def test_sink_failure_is_counted_not_raised():
    async def scenario():
        emitter = EventEmitter(_FailingSink())
        await emitter.start()
        emitter.emit({"n": 1})
        await emitter.flush()
        await emitter.stop()
        return emitter.failed

    assert run(scenario()) == 1


def test_redis_stream_sink_writes_json_events():
    fakeredis = pytest.importorskip("fakeredis")

    async def scenario():
        client = fakeredis.FakeAsyncRedis(decode_responses=True)
        await RedisStreamSink(client, "apishield:traffic", maxlen=1000).write([{"req_id": "a"}, {"req_id": "b"}])
        entries = await client.xrange("apishield:traffic")
        await client.aclose()
        return [json.loads(fields["data"])["req_id"] for _, fields in entries]

    assert run(scenario()) == ["a", "b"]
