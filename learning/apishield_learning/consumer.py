"""Reliable Redis Streams consumption for the dedicated M3 consumer group."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Protocol

from .config import LearningConfig
from .events import EventValidationError, IdentifierPseudonymizer, TrafficEvent
from .features import TrafficFeatures, extract_features

log = logging.getLogger("apishield.learning.consumer")

_UNSUPPORTED_AUTOCLAIM_MARKERS = (
    "unknown command",
    "unsupported command",
    "syntax error",
    "not implemented",
)


class RedisStreamsClient(Protocol):
    """Subset of redis-py used by the M3 consumer."""

    async def xreadgroup(self, **kwargs: Any) -> Any:
        """Read entries from a consumer group."""
        ...

    async def xack(self, name: str, groupname: str, *ids: str) -> Any:
        """Acknowledge processed entry IDs."""
        ...


@dataclass(frozen=True)
class StreamEntry:
    """A validated event paired with its Redis stream entry ID."""

    entry_id: str
    event: TrafficEvent


@dataclass(frozen=True)
class FeatureEnvelope:
    """Safe feature record and Redis ID for idempotent downstream processing."""

    entry_id: str
    features: TrafficFeatures


@dataclass
class ProcessingStats:
    """Runtime counters for M3 consumer health reporting."""

    received: int = 0
    processed: int = 0
    failed: int = 0
    pending: int = 0
    last_processed_timestamp: str | None = None


FeatureCallback = Callable[[FeatureEnvelope], None | Awaitable[None]]


class RedisStreamConsumer:
    """Consume, validate, pseudonymize, and hand off M1 stream entries.

    Only the configured M3 group is ever created or read. Group creation
    includes ``MKSTREAM`` for an empty stream and treats ``BUSYGROUP`` as an
    already-provisioned group. Entries are acknowledged only after the
    callback succeeds, or after a failed entry has been safely recorded in
    the bounded dead-letter stream.
    """

    def __init__(
        self,
        client: RedisStreamsClient,
        stream: str,
        consumer_group: str,
        consumer_name: str,
        *,
        dead_letter_stream: str = "apishield:m3:dead-letter",
        max_delivery_attempts: int = 5,
        min_idle_ms: int = 30_000,
        dead_letter_maxlen: int = 10_000,
        dedupe_cache_size: int = 10_000,
        batch_size: int = 100,
        block_ms: int = 1000,
    ):
        for name, value in (
            ("stream", stream),
            ("consumer_group", consumer_group),
            ("consumer_name", consumer_name),
            ("dead_letter_stream", dead_letter_stream),
        ):
            if not value.strip():
                raise ValueError(f"{name} must not be empty")
        if max_delivery_attempts <= 0:
            raise ValueError("max_delivery_attempts must be positive")
        if min_idle_ms < 0:
            raise ValueError("min_idle_ms must be non-negative")
        if dead_letter_maxlen <= 0:
            raise ValueError("dead_letter_maxlen must be positive")
        if dedupe_cache_size <= 0:
            raise ValueError("dedupe_cache_size must be positive")
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if block_ms < 0:
            raise ValueError("block_ms must be non-negative")
        if stream == dead_letter_stream:
            raise ValueError("dead_letter_stream must differ from the event stream")

        self._client = client
        self._stream = stream
        self._consumer_group = consumer_group
        self._consumer_name = consumer_name
        self._dead_letter_stream = dead_letter_stream
        self._max_delivery_attempts = max_delivery_attempts
        self._min_idle_ms = min_idle_ms
        self._dead_letter_maxlen = dead_letter_maxlen
        self._dedupe_cache_size = dedupe_cache_size
        self.batch_size = batch_size
        self.block_ms = block_ms
        self.stats = ProcessingStats()
        self._processed_ids: OrderedDict[str, None] = OrderedDict()
        self._failure_counts: dict[str, int] = {}
        self._claim_cursor = "0-0"
        self._group_ready = False
        self._closed = False
        self._owned_client = False
        self._config: LearningConfig | None = None
        self._redis_factory: Callable[[], RedisStreamsClient] | None = None

    @classmethod
    def from_config(
        cls, config: LearningConfig, client: RedisStreamsClient | None = None
    ) -> RedisStreamConsumer:
        """Build a consumer from M3 settings, connecting lazily when needed."""
        config.require_pseudo_salt()
        owns_client = client is None
        redis_factory = None
        if client is None:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise RuntimeError(
                    "Redis client is required; install learning/requirements.txt"
                ) from exc
            redis_factory = lambda: Redis.from_url(
                config.redis_url, decode_responses=False
            )
            client = redis_factory()
        consumer = cls(
            client,
            config.event_stream,
            config.consumer_group,
            config.consumer_name,
            dead_letter_stream=config.dead_letter_stream,
            max_delivery_attempts=config.max_delivery_attempts,
            min_idle_ms=config.min_idle_ms,
            dead_letter_maxlen=config.dead_letter_maxlen,
            batch_size=config.batch_size,
            block_ms=config.block_ms,
        )
        consumer._owned_client = owns_client
        consumer._redis_factory = redis_factory
        consumer.use_config(config)
        return consumer

    async def ensure_group(self) -> None:
        """Create only this M3 group if absent; tolerate an existing group."""
        if self._group_ready:
            return
        try:
            await self._client.xgroup_create(
                self._stream,
                self._consumer_group,
                id="0-0",
                mkstream=True,
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc).upper():
                raise
        self._group_ready = True

    async def read_new(
        self, *, count: int | None = None, block_ms: int | None = None
    ) -> list[StreamEntry]:
        """Read and validate new entries; malformed entries remain pending."""
        raw_entries = await self._read_new_raw(count=count, block_ms=block_ms)
        entries = []
        for entry_id, fields in raw_entries:
            try:
                entries.append(
                    StreamEntry(
                        entry_id=entry_id,
                        event=_parse_fields(fields),
                    )
                )
            except EventValidationError:
                log.warning("invalid event retained pending stream_id=%s", entry_id)
                raise
        return entries

    async def _read_new_raw(
        self, *, count: int | None = None, block_ms: int | None = None
    ) -> list[tuple[str, dict[str, Any]]]:
        await self.ensure_group()
        response = await self._client.xreadgroup(
            groupname=self._consumer_group,
            consumername=self._consumer_name,
            streams={self._stream: ">"},
            count=self.batch_size if count is None else count,
            block=self.block_ms if block_ms is None else block_ms,
        )
        return _flatten_messages(response)

    async def recover_pending(self, *, count: int | None = None) -> list[tuple[str, dict[str, Any]]]:
        """Claim idle M3 pending messages with XAUTOCLAIM or XPENDING/XCLAIM."""
        await self.ensure_group()
        count = self.batch_size if count is None else count
        if count <= 0:
            raise ValueError("count must be positive")
        autoclaim = getattr(self._client, "xautoclaim", None)
        if autoclaim is not None:
            try:
                result = await autoclaim(
                    self._stream,
                    self._consumer_group,
                    self._consumer_name,
                    self._min_idle_ms,
                    start_id=self._claim_cursor,
                    count=count,
                )
                self._claim_cursor = _decode_text(result[0])
                if self._claim_cursor == "0-0":
                    self._claim_cursor = "0-0"
                return [
                    (_decode_text(entry_id), fields)
                    for entry_id, fields in result[1]
                ]
            except Exception as exc:
                if not _is_unsupported_autoclaim(exc):
                    raise
                log.info("XAUTOCLAIM unsupported; using XPENDING/XCLAIM fallback")
        return await self._recover_with_xclaim(count)

    async def _recover_with_xclaim(self, count: int) -> list[tuple[str, dict[str, Any]]]:
        pending = await self._client.xpending_range(
            self._stream,
            self._consumer_group,
            min="-",
            max="+",
            count=count,
            idle=self._min_idle_ms,
        )
        entry_ids = [_decode_text(item["message_id"]) for item in pending]
        if not entry_ids:
            return []
        claimed = await self._client.xclaim(
            self._stream,
            self._consumer_group,
            self._consumer_name,
            self._min_idle_ms,
            entry_ids,
        )
        return [(_decode_text(entry_id), fields) for entry_id, fields in claimed]

    async def acknowledge(self, *entry_ids: str) -> int:
        """Acknowledge entries after processing or successful dead-lettering."""
        if not entry_ids:
            return 0
        result = await self._client.xack(
            self._stream, self._consumer_group, *entry_ids
        )
        return int(result)

    async def process_once(self, callback: FeatureCallback) -> int:
        """Recover pending entries, read new entries, and process one batch."""
        await self.ensure_group()
        recovered = await self.recover_pending()
        new_entries = await self._read_new_raw()
        raw_entries = recovered + new_entries
        self.stats.received += len(raw_entries)
        for entry_id, fields in raw_entries:
            await self._process_entry(entry_id, fields, callback)
        await self.refresh_pending()
        return len(raw_entries)

    async def _process_entry(
        self, entry_id: str, fields: dict[str, Any], callback: FeatureCallback
    ) -> None:
        if entry_id in self._processed_ids:
            await self.acknowledge(entry_id)
            return
        try:
            event = _parse_fields(fields)
            config_key = self._config_key
            features = extract_features(event, config_key, config=self._config)
            envelope = FeatureEnvelope(entry_id=entry_id, features=features)
            result = callback(envelope)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            await self._handle_failure(entry_id, exc)
            return

        self._remember_processed(entry_id)
        self._failure_counts.pop(entry_id, None)
        self.stats.processed += 1
        self.stats.last_processed_timestamp = event.ts
        await self.acknowledge(entry_id)

    @property
    def _config_key(self) -> IdentifierPseudonymizer:
        config = self._config
        if config is None:
            raise RuntimeError(
                "consumer requires shared pseudonymization settings; construct it with from_config"
            )
        return IdentifierPseudonymizer(config.internal_pseudonymization_key())

    def use_config(self, config: LearningConfig) -> None:
        """Attach validated settings for feature extraction and run-loop limits."""
        if (
            config.event_stream != self._stream
            or config.consumer_group != self._consumer_group
            or config.consumer_name != self._consumer_name
        ):
            raise ValueError("consumer settings do not match LearningConfig")
        config.require_pseudo_salt()
        self._config = config
        self.batch_size = config.batch_size
        self.block_ms = config.block_ms

    async def _handle_failure(self, entry_id: str, exc: Exception) -> None:
        self.stats.failed += 1
        attempts = await self._delivery_attempts(entry_id)
        attempts = max(attempts, self._failure_counts.get(entry_id, 0) + 1)
        self._failure_counts[entry_id] = attempts
        log.error(
            "event processing failed stream_id=%s attempt=%d/%d error_type=%s",
            entry_id,
            attempts,
            self._max_delivery_attempts,
            type(exc).__name__,
        )
        if attempts < self._max_delivery_attempts:
            return
        await self._dead_letter(entry_id, type(exc).__name__, attempts)
        await self.acknowledge(entry_id)
        self._failure_counts.pop(entry_id, None)
        log.error("event moved to dead-letter stream stream_id=%s", entry_id)

    async def _delivery_attempts(self, entry_id: str) -> int:
        try:
            pending = await self._client.xpending_range(
                self._stream,
                self._consumer_group,
                min=entry_id,
                max=entry_id,
                count=1,
            )
            if pending:
                return int(pending[0].get("times_delivered", 1))
        except Exception:
            log.debug("delivery count unavailable stream_id=%s", entry_id)
        return 1

    async def _dead_letter(self, entry_id: str, failure_type: str, attempts: int) -> None:
        record = {
            "entry_id": entry_id,
            "failure_type": failure_type,
            "attempts": str(attempts),
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._client.xadd(
            self._dead_letter_stream,
            record,
            maxlen=self._dead_letter_maxlen,
            approximate=True,
        )

    async def refresh_pending(self) -> int:
        """Refresh pending-message count where Redis supports XPENDING summary."""
        try:
            summary = await self._client.xpending(
                self._stream, self._consumer_group
            )
            if isinstance(summary, dict):
                self.stats.pending = int(summary.get("pending", 0))
            elif isinstance(summary, (list, tuple)) and summary:
                self.stats.pending = int(summary[0])
        except Exception as exc:
            log.warning("unable to refresh pending count error_type=%s", type(exc).__name__)
        return self.stats.pending

    def _remember_processed(self, entry_id: str) -> None:
        self._processed_ids[entry_id] = None
        self._processed_ids.move_to_end(entry_id)
        while len(self._processed_ids) > self._dedupe_cache_size:
            self._processed_ids.popitem(last=False)

    async def run(
        self,
        callback: FeatureCallback,
        *,
        stop_event: asyncio.Event | None = None,
        reconnect_delay_seconds: float = 1.0,
    ) -> None:
        """Run until stopped, retrying transient Redis errors with bounded delay."""
        if reconnect_delay_seconds < 0:
            raise ValueError("reconnect_delay_seconds must be non-negative")
        stop_event = stop_event or asyncio.Event()
        try:
            while not stop_event.is_set() and not self._closed:
                try:
                    await self.ensure_group()
                    await self.process_once(callback)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.error(
                        "Redis consumer loop failed error_type=%s",
                        type(exc).__name__,
                    )
                    try:
                        await self._reconnect()
                        await self.ensure_group()
                    except asyncio.CancelledError:
                        raise
                    except Exception as reconnect_exc:
                        log.error(
                            "Redis reconnect failed error_type=%s",
                            type(reconnect_exc).__name__,
                        )
                    if reconnect_delay_seconds:
                        try:
                            await asyncio.wait_for(
                                stop_event.wait(), timeout=reconnect_delay_seconds
                            )
                        except asyncio.TimeoutError:
                            pass
        finally:
            await self.aclose()

    async def _reconnect(self) -> None:
        """Recreate owned Redis clients, or probe injected client's reconnection."""
        if self._owned_client and self._redis_factory is not None:
            old_client = self._client
            self._client = self._redis_factory()
            close = getattr(old_client, "aclose", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result
            self._group_ready = False
            await self._client.ping()
            return
        ping = getattr(self._client, "ping", None)
        if ping is not None:
            await ping()

    async def aclose(self) -> None:
        """Stop the consumer and close a Redis client created by from_config."""
        self._closed = True
        if self._owned_client:
            close = getattr(self._client, "aclose", None)
            if close is None:
                close = getattr(self._client, "close", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result


def _parse_fields(fields: dict[str | bytes, Any]) -> TrafficEvent:
    decoded_fields = {_decode_text(name): value for name, value in fields.items()}
    if len(decoded_fields) != 1 or "data" not in decoded_fields:
        raise EventValidationError(
            "stream entry must contain exactly one field named data"
        )
    return TrafficEvent.from_json(decoded_fields["data"])


def _flatten_messages(response: Any) -> list[tuple[str, dict[str, Any]]]:
    messages = []
    for _stream_name, entries in response or ():
        messages.extend(
            (_decode_text(entry_id), fields) for entry_id, fields in entries
        )
    return messages


def _decode_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def _is_unsupported_autoclaim(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(marker in message for marker in _UNSUPPORTED_AUTOCLAIM_MARKERS)
