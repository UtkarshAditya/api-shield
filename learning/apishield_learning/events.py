"""Validation and privacy utilities for the M1 traffic-event contract."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping


EVENT_FIELDS = (
    "ts",
    "req_id",
    "caller",
    "ip",
    "method",
    "path_template",
    "status",
    "latency_ms",
    "req_size",
    "resp_size",
    "shape_hash",
    "rule_hits",
    "action",
)
EVENT_ACTIONS = frozenset({"allow", "log", "block", "throttle", "challenge"})


class EventValidationError(ValueError):
    """Raised when a stream entry does not match the M1 event contract."""


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@dataclass(frozen=True)
class TrafficEvent:
    """The exact event fields emitted by M1; raw identifiers are transient."""

    ts: str
    req_id: str
    caller: str
    ip: str
    method: str
    path_template: str
    status: int
    latency_ms: float
    req_size: int
    resp_size: int
    shape_hash: str
    rule_hits: tuple[str, ...]
    action: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> TrafficEvent:
        """Validate all event fields and reject missing or additional fields."""
        actual_order = tuple(value)
        expected_fields = set(EVENT_FIELDS)
        actual_fields = set(actual_order)
        missing = expected_fields - actual_fields
        extra = actual_fields - expected_fields
        if missing or extra:
            details = []
            if missing:
                details.append(f"missing fields: {', '.join(sorted(missing))}")
            if extra:
                details.append(f"unexpected fields: {', '.join(sorted(extra))}")
            raise EventValidationError("; ".join(details))
        if actual_order != EVENT_FIELDS:
            raise EventValidationError("event fields are not in the M1 producer order")

        string_fields = (
            "ts",
            "req_id",
            "caller",
            "ip",
            "method",
            "path_template",
            "shape_hash",
        )
        for name in string_fields:
            if not isinstance(value[name], str):
                raise EventValidationError(f"{name} must be a string")
        if not isinstance(value["status"], int) or isinstance(value["status"], bool):
            raise EventValidationError("status must be an integer")
        for name in ("req_size", "resp_size"):
            if not isinstance(value[name], int) or isinstance(value[name], bool):
                raise EventValidationError(f"{name} must be an integer")
            if value[name] < 0:
                raise EventValidationError(f"{name} must be non-negative")
        if (
            not _is_number(value["latency_ms"])
            or not math.isfinite(value["latency_ms"])
            or value["latency_ms"] < 0
        ):
            raise EventValidationError("latency_ms must be a non-negative number")
        if not isinstance(value["rule_hits"], list) or not all(
            isinstance(hit, str) for hit in value["rule_hits"]
        ):
            raise EventValidationError("rule_hits must be an array of strings")
        if not isinstance(value["action"], str) or value["action"] not in EVENT_ACTIONS:
            raise EventValidationError("action is not a valid gateway action")

        return cls(
            ts=value["ts"],
            req_id=value["req_id"],
            caller=value["caller"],
            ip=value["ip"],
            method=value["method"],
            path_template=value["path_template"],
            status=value["status"],
            latency_ms=float(value["latency_ms"]),
            req_size=value["req_size"],
            resp_size=value["resp_size"],
            shape_hash=value["shape_hash"],
            rule_hits=tuple(value["rule_hits"]),
            action=value["action"],
        )

    @classmethod
    def from_json(cls, data: str | bytes) -> TrafficEvent:
        """Parse and validate the JSON string held in the stream's `data` field."""
        try:
            decoded = data.decode("utf-8") if isinstance(data, bytes) else data
            value = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EventValidationError("data must contain valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise EventValidationError("event JSON must be an object")
        return cls.from_mapping(value)


class IdentifierPseudonymizer:
    """Generate stable, domain-separated HMAC identifiers for sensitive values."""

    def __init__(self, key: bytes):
        if len(key) < 16:
            raise ValueError("pseudonymization key must be at least 16 bytes")
        self._key = key

    def pseudonymize(self, kind: str, value: str) -> str:
        """Return a stable opaque identifier without exposing the input value."""
        if kind not in {"caller", "ip"}:
            raise ValueError("kind must be 'caller' or 'ip'")
        if not value:
            raise ValueError("identifier must not be empty")
        message = f"apishield:m3:{kind}:{value}".encode("utf-8")
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        return f"{kind}_{digest}"
