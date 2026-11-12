import asyncio

import pytest

from apishield_learning.config import LearningConfig
from apishield_learning.consumer import (
    FeatureEnvelope,
    RedisStreamConsumer,
)

VALID_EVENT = (
    b'{"ts":"2026-11-12T10:00:00Z","req_id":"r1","caller":"ip_192.0.2.1",'
    b'"ip":"192.0.2.1","method":"GET","path_template":"/","status":200,'
    b'"latency_ms":1.2,"req_size":0,"resp_size":12,"shape_hash":"abc",'
    b'"rule_hits":[],"action":"allow"}'
)


class FakeRedis:
    def __init__(self, entries=(), *, fail_reads=0, supports_autoclaim=True):
        self.entries = list(entries)
        self.pending = {}
        self.groups = set()
        self.group_creates = []
        self.read_calls = []
        self.acknowledgements = []
        self.dead_letters = []
        self.fail_reads = fail_reads
        self.supports_autoclaim = supports_autoclaim
        self.pings = 0
        self.closed = False

    async def xgroup_create(self, stream, group, id="0-0", mkstream=False):
        self.group_creates.append((stream, group, id, mkstream))
        if (stream, group) in self.groups:
            raise RuntimeError("BUSYGROUP Consumer Group name already exists")
        self.groups.add((stream, group))
        return True

    async def xautoclaim(
        self, stream, group, consumer, min_idle_ms, start_id="0-0", count=None
    ):
        if not self.supports_autoclaim:
            raise RuntimeError("unknown command XAUTOCLAIM")
        claimed = []
        for entry_id, record in self.pending.items():
            record["deliveries"] += 1
            claimed.append((entry_id.encode(), record["fields"]))
            if len(claimed) >= count:
                break
        return b"0-0", claimed, []

    async def xpending_range(
        self, stream, group, min="-", max="+", count=10, idle=None
    ):
        result = []
        for entry_id, record in self.pending.items():
            if min not in ("-", entry_id) or max not in ("+", entry_id):
                continue
            result.append(
                {
                    "message_id": entry_id.encode(),
                    "times_delivered": record["deliveries"],
                }
            )
            if len(result) >= count:
                break
        return result

    async def xclaim(self, stream, group, consumer, min_idle_ms, ids):
        result = []
        for entry_id in ids:
            record = self.pending.get(entry_id)
            if record:
                record["deliveries"] += 1
                result.append((entry_id.encode(), record["fields"]))
        return result

    async def xreadgroup(self, **kwargs):
        self.read_calls.append(kwargs)
        if self.fail_reads:
            self.fail_reads -= 1
            raise ConnectionError("simulated redis disconnect")
        messages = []
        while self.entries and len(messages) < kwargs["count"]:
            entry_id, fields = self.entries.pop(0)
            self.pending[entry_id] = {"fields": fields, "deliveries": 1}
            messages.append((entry_id.encode(), fields))
        return [(b"apishield:traffic", messages)] if messages else []

    async def xack(self, stream, group, *ids):
        self.acknowledgements.append((stream, group, ids))
        for entry_id in ids:
            self.pending.pop(entry_id, None)
        return len(ids)

    async def xadd(self, stream, fields, **kwargs):
        self.dead_letters.append((stream, fields, kwargs))
        return b"2-0"

    async def xpending(self, stream, group):
        return {"pending": len(self.pending)}

    async def ping(self):
        self.pings += 1
        return True

    async def aclose(self):
        self.closed = True


def build_consumer(redis, **kwargs):
    config = LearningConfig(
        event_stream="apishield:traffic",
        consumer_group="apishield-m3",
        consumer_name="m3-1",
        pseudonymization_key="a sufficiently long test key",
        batch_size=10,
        block_ms=0,
        min_idle_ms=0,
        **kwargs,
    )
    return RedisStreamConsumer.from_config(config, redis)


def test_group_creation_is_scoped_to_m3_and_handles_busygroup():
    async def scenario():
        redis = FakeRedis()
        consumer = build_consumer(redis)
        await consumer.ensure_group()
        consumer._group_ready = False
        await consumer.ensure_group()
        return redis, consumer

    redis, consumer = asyncio.run(scenario())

    assert redis.group_creates == [
        ("apishield:traffic", "apishield-m3", "0-0", True),
        ("apishield:traffic", "apishield-m3", "0-0", True),
    ]
    assert consumer._consumer_group == "apishield-m3"


def test_consumer_reads_one_data_field_and_acknowledges_after_callback_success():
    async def scenario():
        redis = FakeRedis(
            [("1-0", {b"data": VALID_EVENT})]
        )
        consumer = build_consumer(redis)
        received = []

        async def callback(envelope):
            received.append(envelope)

        count = await consumer.process_once(callback)
        return redis, consumer, received, count

    redis, consumer, received, count = asyncio.run(scenario())

    assert count == 1
    assert redis.read_calls[0]["groupname"] == "apishield-m3"
    assert redis.read_calls[-1]["streams"] == {"apishield:traffic": ">"}
    assert len(received) == 1
    assert isinstance(received[0], FeatureEnvelope)
    assert received[0].features.path_template == "/"
    assert redis.acknowledgements == [
        ("apishield:traffic", "apishield-m3", ("1-0",))
    ]
    assert consumer.stats.received == 1
    assert consumer.stats.processed == 1
    assert consumer.stats.pending == 0
    assert consumer.stats.last_processed_timestamp == "2026-11-12T10:00:00Z"


def test_failed_callback_is_not_acknowledged_and_is_dead_lettered_after_limit():
    async def scenario():
        redis = FakeRedis([("1-0", {b"data": VALID_EVENT})])
        consumer = build_consumer(
            redis, max_delivery_attempts=2, dead_letter_maxlen=25
        )

        async def callback(_envelope):
            raise RuntimeError("callback error containing private values")

        await consumer.process_once(callback)
        first_acknowledgements = list(redis.acknowledgements)
        await consumer.process_once(callback)
        return redis, consumer, first_acknowledgements

    redis, consumer, first_acknowledgements = asyncio.run(scenario())

    assert first_acknowledgements == []
    assert redis.acknowledgements == [
        ("apishield:traffic", "apishield-m3", ("1-0",))
    ]
    assert len(redis.dead_letters) == 1
    stream, record, options = redis.dead_letters[0]
    assert stream == "apishield:m3:dead-letter"
    assert record["failure_type"] == "RuntimeError"
    assert record["attempts"] == "2"
    assert "private" not in repr(record)
    assert options == {"maxlen": 25, "approximate": True}
    assert consumer.stats.failed == 2
    assert consumer.stats.processed == 0


@pytest.mark.parametrize(
    ("data", "failure_type"),
    [
        (b"{malformed", "EventValidationError"),
        (
            b'{"ts":"2026-11-12T10:00:00Z","req_id":"r1"}',
            "EventValidationError",
        ),
    ],
)
def test_malformed_and_invalid_events_are_dead_lettered_without_raw_content(
    data, failure_type
):
    async def scenario():
        redis = FakeRedis([("1-0", {b"data": data})])
        consumer = build_consumer(redis, max_delivery_attempts=1)
        await consumer.process_once(lambda _envelope: None)
        return redis, consumer

    redis, consumer = asyncio.run(scenario())

    assert consumer.stats.failed == 1
    assert consumer.stats.processed == 0
    assert redis.dead_letters[0][1]["failure_type"] == failure_type
    assert data.decode(errors="replace") not in repr(redis.dead_letters)
    assert redis.acknowledgements[-1][2] == ("1-0",)


def test_pending_message_recovery_uses_xautoclaim():
    async def scenario():
        redis = FakeRedis([("1-0", {b"data": VALID_EVENT})])
        consumer = build_consumer(redis)
        await consumer.ensure_group()
        await consumer._read_new_raw()
        recovered = await consumer.recover_pending()
        return redis, recovered

    redis, recovered = asyncio.run(scenario())

    assert len(recovered) == 1
    assert recovered[0][0] == "1-0"
    assert redis.pending["1-0"]["deliveries"] == 2


def test_pending_message_recovery_falls_back_to_xpending_and_xclaim():
    async def scenario():
        redis = FakeRedis(
            [("1-0", {b"data": VALID_EVENT})], supports_autoclaim=False
        )
        consumer = build_consumer(redis)
        await consumer.ensure_group()
        await consumer._read_new_raw()
        recovered = await consumer.recover_pending()
        return redis, recovered

    redis, recovered = asyncio.run(scenario())

    assert len(recovered) == 1
    assert recovered[0][0] == "1-0"
    assert redis.pending["1-0"]["deliveries"] == 2


def test_successful_callback_with_ack_failure_is_deduplicated_on_redelivery():
    class AckFailRedis(FakeRedis):
        def __init__(self):
            super().__init__([("1-0", {b"data": VALID_EVENT})])
            self.fail_ack_once = True

        async def xack(self, stream, group, *ids):
            if self.fail_ack_once:
                self.fail_ack_once = False
                raise ConnectionError("ack failed")
            return await super().xack(stream, group, *ids)

    async def scenario():
        redis = AckFailRedis()
        consumer = build_consumer(redis)
        callback_calls = []

        def callback(envelope):
            callback_calls.append(envelope.entry_id)

        with pytest.raises(ConnectionError):
            await consumer.process_once(callback)
        await consumer.process_once(callback)
        return redis, consumer, callback_calls

    redis, consumer, callback_calls = asyncio.run(scenario())

    assert callback_calls == ["1-0"]
    assert redis.acknowledgements == [
        ("apishield:traffic", "apishield-m3", ("1-0",))
    ]
    assert consumer.stats.processed == 1


def test_run_reconnects_after_redis_disconnect_and_shuts_down_gracefully():
    async def scenario():
        redis = FakeRedis([("1-0", {b"data": VALID_EVENT})], fail_reads=1)
        consumer = build_consumer(redis)
        stop = asyncio.Event()
        callback_calls = []

        async def callback(envelope):
            callback_calls.append(envelope.entry_id)
            stop.set()

        await consumer.run(
            callback, stop_event=stop, reconnect_delay_seconds=0
        )
        return redis, consumer, callback_calls

    redis, consumer, callback_calls = asyncio.run(scenario())

    assert redis.pings == 1
    assert callback_calls == ["1-0"]
    assert consumer._closed
    assert consumer.stats.processed == 1


def test_direct_config_requires_pseudonymization_key_before_processing():
    redis = FakeRedis([("1-0", {b"data": VALID_EVENT})])
    config = LearningConfig(
        event_stream="apishield:traffic",
        consumer_group="apishield-m3",
        consumer_name="m3-1",
        pseudonymization_key=None,
    )

    with pytest.raises(ValueError, match="required"):
        RedisStreamConsumer.from_config(config, redis)


def test_consumer_configuration_rejects_empty_group():
    with pytest.raises(ValueError, match="consumer_group"):
        RedisStreamConsumer(FakeRedis(), "stream", " ", "worker")
