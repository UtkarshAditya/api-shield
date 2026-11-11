"""Event emitter: one compact traffic event per request, never blocking the request path."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque

from .context import RequestContext

log = logging.getLogger("apishield.events")

EVENT_FIELDS = (
    "ts", "req_id", "caller", "ip", "method", "path_template", "status", "latency_ms",
    "req_size", "resp_size", "shape_hash", "rule_hits", "action",
)


def build_event(ctx: RequestContext, status: int, resp_size: int, latency_ms: float) -> dict:
    """The traffic-event contract from section 4 of the architecture plan."""
    return {
        "ts": ctx.ts,
        "req_id": ctx.req_id,
        "caller": ctx.caller or f"ip_{ctx.ip}",
        "ip": ctx.ip,
        "method": ctx.method,
        "path_template": ctx.path_template or ctx.raw_path,
        "status": status,
        "latency_ms": round(latency_ms, 2),
        "req_size": len(ctx.body),
        "resp_size": resp_size,
        "shape_hash": ctx.shape_hash,
        "rule_hits": list(ctx.rule_hits),
        "action": ctx.action,
    }


class MemorySink:
    """Keeps recent events in memory. Used in tests and when Redis is not reachable."""

    def __init__(self, maxlen: int = 1000):
        self.events: deque = deque(maxlen=maxlen)

    async def write(self, batch: list) -> None:
        self.events.extend(batch)


class RedisStreamSink:
    """XADD each event to a capped Redis Stream as a single JSON field named `data`."""

    def __init__(self, client, stream: str, maxlen: int):
        self._client, self._stream, self._maxlen = client, stream, maxlen

    async def write(self, batch: list) -> None:
        pipe = self._client.pipeline(transaction=False)
        for event in batch:
            pipe.xadd(self._stream, {"data": json.dumps(event, separators=(",", ":"))},
                      maxlen=self._maxlen, approximate=True)
        await pipe.execute()


class EventEmitter:
    """Requests call emit(), which only puts on a bounded queue. A background task
    drains the queue in batches. If the queue is full the event is dropped and
    counted, so a slow or dead Redis can never slow down traffic."""

    def __init__(self, sink, queue_size: int = 10_000, batch_size: int = 100):
        self.sink = sink
        self.dropped = 0
        self.failed = 0
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._batch_size = batch_size
        self._task: asyncio.Task | None = None

    def emit(self, event: dict) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="apishield-event-emitter")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._queue.put_nowait(None) if not self._queue.full() else self._task.cancel()
        try:
            await asyncio.wait_for(self._task, timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self._task.cancel()
        self._task = None

    async def flush(self) -> None:
        """Wait until everything queued so far has been handed to the sink."""
        await self._queue.join()

    async def _run(self) -> None:
        stopping = False
        while not stopping:
            batch = [await self._queue.get()]
            while len(batch) < self._batch_size and not self._queue.empty():
                batch.append(self._queue.get_nowait())
            if None in batch:
                stopping = True
            events = [e for e in batch if e is not None]
            try:
                if events:
                    await self.sink.write(events)
            except Exception as exc:  # never let the emitter die
                self.failed += len(events)
                log.warning("dropped %d traffic events: %s", len(events), exc)
                await asyncio.sleep(0.5)
            finally:
                for _ in batch:
                    self._queue.task_done()
