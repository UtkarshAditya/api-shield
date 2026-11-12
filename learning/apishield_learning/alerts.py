"""Privacy-safe alert scoring, grouping, and in-memory service operations."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol, Sequence

from .detectors.results import DetectorResult
from .features import TrafficFeatures
from .storage import InMemoryLearningStorage, LearningStorage

ALERT_STATUSES = frozenset({"new", "acknowledged", "resolved"})
_SENSITIVE_KEYS = frozenset(
    {
        "caller",
        "caller_id",
        "caller_id_raw",
        "caller_endpoint_key",
        "alert_caller_id",
        "ip",
        "ip_id",
        "ip_address",
        "authorization",
        "password",
        "token",
        "request_body",
        "response_body",
        "payload",
        "payload_value",
        "req_id",
        "request_id",
    }
)
_DETECTOR_REASONS = {
    "request_rate_spike": "Request rate exceeded the learned rate pattern.",
    "request_size": "Request size differed from the learned endpoint pattern.",
    "response_size": "Response size differed from the learned endpoint pattern.",
    "latency": "Response latency differed from the learned endpoint pattern.",
    "http_error_rate": "The observed response indicated an elevated error signal.",
    "new_payload_shape": (
        "The payload shape is not in the learned allow-list and warrants "
        "investigation."
    ),
    "unexpected_endpoint_method": (
        "The endpoint/method has no matching learned access baseline."
    ),
    "rule_hit_or_blocked_action": (
        "Gateway rule hits or an enforcement action were observed."
    ),
    "endpoint_sequence": (
        "The endpoint transition was not present in comparable sequence history."
    ),
    "isolation_forest": (
        "The multivariate feature vector was unusual relative to training data."
    ),
}


class EndpointRiskProvider(Protocol):
    """Source of M2 endpoint-risk scores; no risk value is inferred locally."""

    def get_risk_score(self, endpoint: str, method: str) -> float | None:
        """Return a normalized M2 score, or None when no score is available."""
        ...


@dataclass(frozen=True)
class AlertConfig:
    """Scoring, repeat, and severity policy for alert generation.

    Scores and endpoint risk use [0, 1]. Missing endpoint risk is explicitly
    represented as ``None`` and uses ``missing_risk_fallback`` only as the
    formula multiplier. The fallback is not written as an M2 risk score.
    """

    missing_risk_fallback: float = 0.5
    repeat_growth: float = 0.1
    maximum_repeat_factor: float = 2.0
    repeat_window_seconds: int = 900
    critical_threshold: float = 0.85
    high_threshold: float = 0.65
    medium_threshold: float = 0.4
    low_threshold: float = 0.15

    def __post_init__(self) -> None:
        for name in (
            "missing_risk_fallback",
            "critical_threshold",
            "high_threshold",
            "medium_threshold",
            "low_threshold",
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise ValueError(f"{name} must be finite and between 0 and 1")
        if (
            not isinstance(self.repeat_growth, (int, float))
            or isinstance(self.repeat_growth, bool)
            or not math.isfinite(self.repeat_growth)
            or self.repeat_growth < 0
        ):
            raise ValueError("repeat_growth must be finite and non-negative")
        if (
            not isinstance(self.maximum_repeat_factor, (int, float))
            or isinstance(self.maximum_repeat_factor, bool)
            or not math.isfinite(self.maximum_repeat_factor)
            or self.maximum_repeat_factor < 1
        ):
            raise ValueError("maximum_repeat_factor must be finite and at least 1")
        if (
            not isinstance(self.repeat_window_seconds, int)
            or isinstance(self.repeat_window_seconds, bool)
            or self.repeat_window_seconds <= 0
        ):
            raise ValueError("repeat_window_seconds must be a positive integer")
        if not (
            self.critical_threshold
            >= self.high_threshold
            >= self.medium_threshold
            >= self.low_threshold
        ):
            raise ValueError("severity thresholds must be in descending order")


@dataclass(frozen=True)
class Alert:
    """Alert record containing only endpoint data and pseudonymous identifiers."""

    alert_id: str
    timestamp: str
    endpoint: str
    method: str
    caller_id: str
    anomaly_score: float
    endpoint_risk_score: float | None
    repeat_factor: float
    priority_score: float
    severity: str
    status: str
    detector_names: tuple[str, ...]
    observed_values: Mapping[str, Any]
    expected_values: Mapping[str, Any]
    thresholds: Mapping[str, Any]
    explanation: str
    contributing_features: tuple[str, ...]
    feedback_status: str | None = None
    grouping_key: str = field(default="", repr=False)
    repeat_count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    last_observation_key: str = field(default="", repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Return a detached, JSON-compatible alert snapshot."""
        data = asdict(self)
        data["detector_names"] = list(self.detector_names)
        data["contributing_features"] = list(self.contributing_features)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Alert:
        """Restore an alert stored by a LearningStorage adapter."""
        values = dict(data)
        values["detector_names"] = tuple(values.get("detector_names", ()))
        values["contributing_features"] = tuple(
            values.get("contributing_features", ())
        )
        return cls(**values)


class AlertService:
    """Generate, deduplicate, rank, and update alerts using LearningStorage."""

    def __init__(
        self,
        *,
        storage: LearningStorage | None = None,
        endpoint_risk_provider: EndpointRiskProvider | None = None,
        config: AlertConfig | None = None,
    ) -> None:
        self.storage = storage or InMemoryLearningStorage()
        self.endpoint_risk_provider = endpoint_risk_provider
        self.config = config or AlertConfig()

    def generate_alerts(
        self,
        detector_results: Sequence[DetectorResult],
        feature_record: TrafficFeatures | Mapping[str, Any],
    ) -> list[Alert]:
        """Create or update one grouped alert from the detected results.

        All simultaneously detected detector results for a caller/endpoint are
        coalesced into one ``traffic_anomaly`` incident. An identical feature
        timestamp is treated idempotently and does not increase repeat count.
        """
        features = _coerce_features(feature_record)
        if any(not isinstance(result, DetectorResult) for result in detector_results):
            raise TypeError("detector_results must contain DetectorResult values")
        detected = [result for result in detector_results if result.detected]
        if not detected:
            return []
        if any(result.confirmed_attack for result in detected):
            raise ValueError("detector results must not confirm an attack")
        for result in detected:
            _validate_score(result.score, "anomaly score")

        anomaly_score = max(float(result.score) for result in detected)
        endpoint_risk = self._endpoint_risk(features.path_template, features.method)
        effective_risk = (
            endpoint_risk
            if endpoint_risk is not None
            else self.config.missing_risk_fallback
        )
        grouping_key = _grouping_key(
            features.alert_caller_id, features.endpoint_key, "traffic_anomaly"
        )
        current_timestamp = _normalize_timestamp(features.ts)
        since = _timestamp_minus(
            current_timestamp, self.config.repeat_window_seconds
        )
        previous_data = self.storage.find_recent_alert(grouping_key, since)
        previous = Alert.from_dict(previous_data) if previous_data else None
        duplicate_observation = bool(
            previous and previous.last_observation_key == current_timestamp
        )
        repeat_count = (
            previous.repeat_count
            if duplicate_observation
            else previous.repeat_count + 1
            if previous
            else 1
        )
        repeat_factor = min(
            1 + self.config.repeat_growth * max(0, repeat_count - 1),
            self.config.maximum_repeat_factor,
        )
        priority = min(1.0, anomaly_score * effective_risk * repeat_factor)

        results_by_name = {
            result.detector: result for result in sorted(detected, key=lambda item: item.detector)
        }
        observed_values = {
            name: _safe_json_value(result.observed)
            for name, result in results_by_name.items()
        }
        expected_values = {
            name: _safe_json_value(result.expected)
            for name, result in results_by_name.items()
        }
        thresholds = {
            name: _safe_json_value(result.threshold)
            for name, result in results_by_name.items()
        }
        detector_names = tuple(results_by_name)
        contributing_features = _top_features(detected)
        explanation = _explanation(
            detected,
            endpoint=features.endpoint_key,
            baseline_ready=all(result.baseline_ready for result in detected),
            duplicate=duplicate_observation,
        )
        alert = Alert(
            alert_id=previous.alert_id if previous else str(uuid.uuid4()),
            timestamp=previous.timestamp if previous else current_timestamp,
            endpoint=features.path_template,
            method=features.method,
            caller_id=features.alert_caller_id,
            anomaly_score=anomaly_score,
            endpoint_risk_score=endpoint_risk,
            repeat_factor=repeat_factor,
            priority_score=priority,
            severity=_severity(priority, self.config),
            status=previous.status if previous else "new",
            detector_names=tuple(
                sorted(set(previous.detector_names if previous else ()) | set(detector_names))
            ),
            observed_values=_merge(previous.observed_values if previous else {}, observed_values),
            expected_values=_merge(previous.expected_values if previous else {}, expected_values),
            thresholds=_merge(previous.thresholds if previous else {}, thresholds),
            explanation=explanation,
            contributing_features=contributing_features,
            feedback_status=previous.feedback_status if previous else None,
            grouping_key=grouping_key,
            repeat_count=repeat_count,
            first_seen=previous.first_seen if previous else current_timestamp,
            last_seen=current_timestamp,
            last_observation_key=current_timestamp,
        )
        if previous is None:
            self.storage.save_alert(alert.to_dict())
        else:
            self.storage.update_alert(alert.to_dict())
        return [alert]

    def get_alert(self, alert_id: str) -> Alert | None:
        """Retrieve an alert by its unique ID."""
        data = self.storage.get_alert(alert_id)
        return Alert.from_dict(data) if data else None

    def get_alerts(self, filters: Mapping[str, Any] | None = None) -> list[Alert]:
        """Retrieve alerts with optional exact-match field filters."""
        filters = filters or {}
        unknown = set(filters) - set(Alert.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown alert filter: {sorted(unknown)[0]}")
        records = self.storage.list_alerts()
        alerts = [Alert.from_dict(record) for record in records]
        return [
            alert
            for alert in alerts
            if all(_matches_filter(alert, key, value) for key, value in filters.items())
        ]

    def get_ranked_alerts(self, limit: int | None = None) -> list[Alert]:
        """Return alerts ranked by priority, then most recently seen."""
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")
        alerts = sorted(
            self.get_alerts(),
            key=lambda alert: (
                -alert.priority_score,
                -_timestamp_seconds(alert.last_seen),
                alert.alert_id,
            ),
        )
        return alerts if limit is None else alerts[:limit]

    def update_alert_status(self, alert_id: str, status: str) -> Alert:
        """Set an alert's workflow status, raising KeyError if not found."""
        if status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {sorted(ALERT_STATUSES)}")
        alert = self.get_alert(alert_id)
        if alert is None:
            raise KeyError(f"alert not found: {alert_id}")
        updated = Alert.from_dict({**alert.to_dict(), "status": status})
        self.storage.update_alert(updated.to_dict())
        return updated

    def get_alert_summary(self) -> dict[str, Any]:
        """Return deterministic counts by status and severity."""
        alerts = self.get_alerts()
        by_status = {status: 0 for status in sorted(ALERT_STATUSES)}
        by_severity = {
            severity: 0 for severity in ("critical", "high", "medium", "low", "info")
        }
        for alert in alerts:
            by_status[alert.status] = by_status.get(alert.status, 0) + 1
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
        return {
            "total": len(alerts),
            "by_status": by_status,
            "by_severity": by_severity,
        }

    def _endpoint_risk(self, endpoint: str, method: str) -> float | None:
        if self.endpoint_risk_provider is None:
            return None
        score = self.endpoint_risk_provider.get_risk_score(endpoint, method)
        if score is None:
            return None
        _validate_score(score, "endpoint risk score")
        return float(score)


def _validate_score(value: Any, label: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ValueError(f"{label} must be finite and between 0 and 1")


def _coerce_features(
    features: TrafficFeatures | Mapping[str, Any],
) -> TrafficFeatures:
    if isinstance(features, TrafficFeatures):
        record = features
    elif isinstance(features, Mapping):
        try:
            record = TrafficFeatures(**{
                name: features[name]
                for name in TrafficFeatures.__dataclass_fields__
                if name in features
            })
        except (KeyError, TypeError) as exc:
            raise ValueError("feature record does not match TrafficFeatures") from exc
    else:
        raise TypeError("feature_record must be TrafficFeatures or a mapping")
    if (
        not isinstance(record.path_template, str)
        or not record.path_template
        or not isinstance(record.method, str)
        or not record.method
        or record.endpoint_key != f"{record.method} {record.path_template}"
    ):
        raise ValueError("feature record has an invalid endpoint or method")
    if not _is_internal_caller_id(record.caller_id) or not _is_pseudonym(
        record.ip_id, "ip"
    ):
        raise ValueError("internal feature identifiers must be pseudonymous")
    if not _is_shared_caller_id(record.alert_caller_id):
        raise ValueError("alert caller identifier must use the shared pseudonym format")
    _normalize_timestamp(record.ts)
    return record


def _is_pseudonym(value: Any, kind: str) -> bool:
    if not isinstance(value, str):
        return False
    if kind == "caller":
        return re.fullmatch(
            r"(?:caller_[0-9a-f]{64}|(?:ip|user|key)_[0-9a-f]{8})",
            value,
        ) is not None
    return re.fullmatch(rf"{kind}_[0-9a-f]{{64}}", value) is not None


def _is_internal_caller_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"caller_[0-9a-f]{64}", value) is not None
    )


def _is_shared_caller_id(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"(?:ip|user|key)_[0-9a-f]{8}", value
    ) is not None


def _normalize_timestamp(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be a valid ISO-8601 string") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp_minus(timestamp: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (
        (parsed - timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


def _timestamp_seconds(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


def _grouping_key(caller_id: str, endpoint_key: str, anomaly_type: str) -> str:
    material = "\0".join((caller_id, endpoint_key, anomaly_type)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _safe_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("detector result contains a non-finite value")
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _safe_json_value(item)
            for key, item in value.items()
            if not _is_sensitive_key(str(key))
        }
    if isinstance(value, (tuple, list, set)):
        items = [_safe_json_value(item) for item in value]
        if isinstance(value, set):
            return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
        return items
    raise ValueError("detector result contains a non-serializable value")


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return normalized in _SENSITIVE_KEYS or any(
        marker in normalized
        for marker in ("payload", "password", "token", "authorization", "ip_address")
    )


def _top_features(results: Sequence[DetectorResult], limit: int = 5) -> tuple[str, ...]:
    scores: dict[str, float] = {}
    for result in results:
        for name in result.contributing_features:
            scores[name] = max(scores.get(name, 0.0), float(result.score))
    return tuple(
        name
        for name, _score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))[
            :limit
        ]
    )


def _explanation(
    results: Sequence[DetectorResult],
    *,
    endpoint: str,
    baseline_ready: bool,
    duplicate: bool,
) -> str:
    details = []
    for result in results:
        reason = _DETECTOR_REASONS.get(
            result.detector, "The detector reported an unusual signal."
        )
        details.append(
            f"{result.detector}: observed {_display_value(result.observed)}; "
            f"expected {_display_value(result.expected)}; "
            f"threshold {_display_value(result.threshold)}. {reason}"
        )
    readiness = (
        "The endpoint baseline was ready."
        if baseline_ready
        else "At least one contributing detector did not have a ready baseline."
    )
    repeat = " This was a duplicate observation and did not increase repeat count." if duplicate else ""
    return (
        f"Observed unusual API behavior for {endpoint}. "
        + " ".join(details)
        + f" Contributing features: {', '.join(_top_features(results)) or 'none'}. "
        + readiness
        + repeat
        + " This alert is not confirmation of an attack."
    )


def _display_value(value: Any) -> str:
    encoded = json.dumps(_safe_json_value(value), sort_keys=True, ensure_ascii=True)
    return encoded[:300]


def _merge(
    previous: Mapping[str, Any], current: Mapping[str, Any]
) -> dict[str, Any]:
    merged = dict(previous)
    merged.update(current)
    return merged


def _severity(priority: float, config: AlertConfig) -> str:
    if priority >= config.critical_threshold:
        return "critical"
    if priority >= config.high_threshold:
        return "high"
    if priority >= config.medium_threshold:
        return "medium"
    if priority >= config.low_threshold:
        return "low"
    return "info"


def _matches_filter(alert: Alert, key: str, value: Any) -> bool:
    return getattr(alert, key) == value
