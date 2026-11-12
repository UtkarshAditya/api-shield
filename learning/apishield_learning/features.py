"""Privacy-safe conversion of gateway events into baseline/model features."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .config import LearningConfig
from .events import IdentifierPseudonymizer, TrafficEvent

RATE_WINDOW_SECONDS = 60
MAX_EVENT_STATUS = 599
MAX_SIZE_BYTES = 2**63 - 1


@dataclass(frozen=True)
class TrafficFeatures:
    """Serializable model inputs with no raw identifiers or request contents."""

    ts: str
    caller_id: str
    ip_id: str
    method: str
    path_template: str
    status: int
    latency_ms: float
    req_size: int
    resp_size: int
    shape_hash: str
    rule_hit_count: int
    action: str
    hour_utc: int
    weekday_utc: int
    time_of_day_sin: float
    time_of_day_cos: float
    request_count: int
    rate_window_start: str
    endpoint_key: str
    caller_endpoint_key: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable record suitable for storage/model inputs."""
        return asdict(self)


def extract_features(
    event: TrafficEvent,
    pseudonymizer: IdentifierPseudonymizer | None = None,
    *,
    config: LearningConfig | None = None,
    rate_window_seconds: int = RATE_WINDOW_SECONDS,
) -> TrafficFeatures:
    """Create a deterministic, pseudonymized feature record from one M1 event.

    When the pseudonymizer is not injected, a configured HMAC key is mandatory.
    Raw caller/IP, the M1 request ID, and payload contents are never returned.
    """
    if pseudonymizer is None:
        config = config or LearningConfig.from_env()
        pseudonymizer = IdentifierPseudonymizer(
            config.require_pseudonymization_key()
        )
    if rate_window_seconds <= 0:
        raise ValueError("rate_window_seconds must be positive")
    if event.status < 100 or event.status > MAX_EVENT_STATUS:
        raise ValueError("status must be between 100 and 599")
    if not math.isfinite(event.latency_ms) or event.latency_ms < 0:
        raise ValueError("latency_ms must be a finite non-negative number")
    if not 0 <= event.req_size <= MAX_SIZE_BYTES:
        raise ValueError("req_size is outside the supported numeric range")
    if not 0 <= event.resp_size <= MAX_SIZE_BYTES:
        raise ValueError("resp_size is outside the supported numeric range")
    if not event.method.strip() or not event.path_template.strip():
        raise ValueError("method and path_template must not be empty")
    if not event.shape_hash:
        raise ValueError("shape_hash must not be empty")

    timestamp = _parse_timestamp(event.ts)
    fractional_hour = (
        timestamp.hour
        + timestamp.minute / 60
        + timestamp.second / 3600
        + timestamp.microsecond / 3_600_000_000
    )
    phase = 2 * math.pi * fractional_hour / 24
    window_epoch = int(timestamp.timestamp()) // rate_window_seconds * rate_window_seconds
    rate_window = datetime.fromtimestamp(window_epoch, tz=timezone.utc)
    caller_id = pseudonymizer.pseudonymize("caller", event.caller)
    ip_id = pseudonymizer.pseudonymize("ip", event.ip)
    endpoint_key = f"{event.method.upper()} {event.path_template}"

    return TrafficFeatures(
        ts=timestamp.isoformat().replace("+00:00", "Z"),
        caller_id=caller_id,
        ip_id=ip_id,
        method=event.method.upper(),
        path_template=event.path_template,
        status=event.status,
        latency_ms=float(event.latency_ms),
        req_size=event.req_size,
        resp_size=event.resp_size,
        shape_hash=event.shape_hash,
        rule_hit_count=len(event.rule_hits),
        action=event.action,
        hour_utc=timestamp.hour,
        weekday_utc=timestamp.weekday(),
        time_of_day_sin=math.sin(phase),
        time_of_day_cos=math.cos(phase),
        request_count=1,
        rate_window_start=rate_window.isoformat().replace("+00:00", "Z"),
        endpoint_key=endpoint_key,
        caller_endpoint_key=f"{caller_id}:{endpoint_key}",
    )


def _parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("ts must be a valid ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("ts must include a timezone")
    return timestamp.astimezone(timezone.utc)
