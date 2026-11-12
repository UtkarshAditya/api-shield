"""Append-only analyst feedback and reviewable detector analysis."""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .storage import InMemoryLearningStorage, LearningStorage

FEEDBACK_LABELS = frozenset({"true_positive", "false_positive"})
_ANALYST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_ALERT_ID_LENGTH = 256
_MAX_ANALYST_ID_LENGTH = 128
_MAX_COMMENT_LENGTH = 1000


@dataclass(frozen=True)
class AnalystFeedback:
    """One immutable analyst decision; labels are not verified ground truth."""

    feedback_id: str
    alert_id: str
    label: str
    timestamp: str
    analyst_id: str | None = None
    comment: str | None = None
    previous_feedback_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a detached JSON-compatible feedback record."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AnalystFeedback:
        """Rehydrate a feedback record from a storage adapter."""
        return cls(**dict(data))


@dataclass(frozen=True)
class FeedbackAnalysisConfig:
    """Review thresholds for advisory detector performance analysis."""

    min_feedback_per_detector: int = 5
    high_false_positive_rate: float = 0.5
    suggested_threshold_increase: float = 0.1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.min_feedback_per_detector, int)
            or isinstance(self.min_feedback_per_detector, bool)
            or self.min_feedback_per_detector <= 0
        ):
            raise ValueError("min_feedback_per_detector must be a positive integer")
        for field_name in (
            "high_false_positive_rate",
            "suggested_threshold_increase",
        ):
            value = getattr(self, field_name)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise ValueError(f"{field_name} must be finite and between 0 and 1")


class FeedbackService:
    """Store feedback history and expose conservative, non-mutating analysis."""

    def __init__(
        self,
        *,
        storage: LearningStorage | None = None,
        analysis_config: FeedbackAnalysisConfig | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.storage = storage or InMemoryLearningStorage()
        self.analysis_config = analysis_config or FeedbackAnalysisConfig()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def submit_feedback(
        self,
        alert_id: str,
        label: str,
        analyst_id: str | None = None,
        comment: str | None = None,
    ) -> AnalystFeedback:
        """Append a feedback decision and update only the alert's feedback label.

        Every submission, including a duplicate label, is retained and linked
        to the prior decision. Detection evidence and alert scores are untouched.
        """
        alert_id = _validate_alert_id(alert_id)
        if not isinstance(label, str) or label not in FEEDBACK_LABELS:
            raise ValueError(f"label must be one of {sorted(FEEDBACK_LABELS)}")
        safe_analyst_id = _validate_analyst_id(analyst_id)
        safe_comment = _validate_comment(comment)
        alert = self.storage.get_alert(alert_id)
        if alert is None:
            raise KeyError(f"alert not found: {alert_id}")

        history = self.get_feedback_history(alert_id)
        previous = history[-1] if history else None
        record = AnalystFeedback(
            feedback_id=str(uuid.uuid4()),
            alert_id=alert_id,
            label=label,
            timestamp=_format_timestamp(self._clock()),
            analyst_id=safe_analyst_id,
            comment=safe_comment,
            previous_feedback_id=previous.feedback_id if previous else None,
        )
        self.storage.save_feedback(record.to_dict())
        self.storage.update_alert({**alert, "feedback_status": label})
        return record

    def get_feedback(self, alert_id: str) -> AnalystFeedback | None:
        """Return the latest decision for an alert, if it has feedback."""
        history = self.get_feedback_history(alert_id)
        return history[-1] if history else None

    def get_feedback_history(self, alert_id: str) -> list[AnalystFeedback]:
        """Return all decisions, oldest first, with stable ordering for ties."""
        alert_id = _validate_alert_id(alert_id)
        records = [
            AnalystFeedback.from_dict(record)
            for record in self.storage.list_feedback()
            if record.get("alert_id") == alert_id
        ]
        return sorted(records, key=lambda record: _timestamp_key(record.timestamp))

    def get_feedback_summary(self) -> dict[str, Any]:
        """Summarize latest decisions by label and the alert's current severity."""
        latest = self._latest_by_alert()
        by_label = {label: 0 for label in sorted(FEEDBACK_LABELS)}
        by_severity: dict[str, dict[str, int]] = {}
        for alert_id, feedback in latest.items():
            by_label[feedback.label] += 1
            alert = self.storage.get_alert(alert_id)
            severity = str(alert.get("severity", "unknown")) if alert else "unknown"
            by_severity.setdefault(
                severity, {label: 0 for label in sorted(FEEDBACK_LABELS)}
            )[feedback.label] += 1
        return {
            "latest_decision_count": len(latest),
            "submission_count": len(self.storage.list_feedback()),
            "by_label": by_label,
            "by_severity": dict(sorted(by_severity.items())),
            "ground_truth": False,
            "interpretation": "Analyst feedback is subjective review, not verified attack ground truth.",
        }

    def get_feedback_metrics(self) -> dict[str, Any]:
        """Return detector-level analyst-label metrics and review-only advice.

        A label applies to all detectors contributing to its alert. Detector
        false-positive rates are therefore association signals, not causal
        attribution or objective model quality measurements.
        """
        latest = self._latest_by_alert()
        counts: dict[str, dict[str, int]] = {}
        thresholds: dict[str, list[Any]] = {}
        for alert_id, feedback in latest.items():
            alert = self.storage.get_alert(alert_id)
            if alert is None:
                continue
            names = alert.get("detector_names", [])
            detector_thresholds = alert.get("thresholds", {})
            if not isinstance(names, list) or not isinstance(detector_thresholds, Mapping):
                continue
            for name in names:
                if not isinstance(name, str) or not name:
                    continue
                bucket = counts.setdefault(
                    name, {"true_positive": 0, "false_positive": 0}
                )
                bucket[feedback.label] += 1
                value = detector_thresholds.get(name)
                if value is not None:
                    thresholds.setdefault(name, []).append(value)

        detector_metrics: dict[str, dict[str, Any]] = {}
        recommendations: list[dict[str, Any]] = []
        for name, bucket in sorted(counts.items()):
            total = bucket["true_positive"] + bucket["false_positive"]
            fp_rate = bucket["false_positive"] / total if total else 0.0
            detector_metrics[name] = {
                **bucket,
                "sample_count": total,
                "false_positive_rate": fp_rate,
                "interpretation": "Analyst-label association, not verified ground truth.",
            }
            if (
                total >= self.analysis_config.min_feedback_per_detector
                and fp_rate >= self.analysis_config.high_false_positive_rate
            ):
                current = _merge_threshold_samples(thresholds.get(name, []))
                recommendations.append(
                    {
                        "detector": name,
                        "false_positive_rate": fp_rate,
                        "sample_count": total,
                        "action": "review_increasing_threshold",
                        "current_thresholds": current,
                        "suggested_thresholds": _suggest_thresholds(
                            current, self.analysis_config.suggested_threshold_increase
                        ),
                        "requires_human_review": True,
                        "automatic_change_applied": False,
                        "reason": (
                            "Analyst false-positive labels are frequent enough to "
                            "review detector sensitivity; labels are not verified "
                            "ground truth."
                        ),
                    }
                )
        return {
            "detectors": detector_metrics,
            "threshold_recommendations": recommendations,
            "automatic_threshold_changes": 0,
            "baseline_modified": False,
            "gateway_rules_modified": False,
            "ground_truth": False,
        }

    def _latest_by_alert(self) -> dict[str, AnalystFeedback]:
        latest: dict[str, AnalystFeedback] = {}
        for record in self.storage.list_feedback():
            feedback = AnalystFeedback.from_dict(record)
            current = latest.get(feedback.alert_id)
            if current is None or _timestamp_key(feedback.timestamp) >= _timestamp_key(
                current.timestamp
            ):
                latest[feedback.alert_id] = feedback
        return latest


def _validate_alert_id(alert_id: str) -> str:
    if not isinstance(alert_id, str):
        raise TypeError("alert_id must be a string")
    normalized = alert_id.strip()
    if not normalized or len(normalized) > _MAX_ALERT_ID_LENGTH:
        raise ValueError("alert_id must be non-empty and at most 256 characters")
    if _has_disallowed_control(normalized):
        raise ValueError("alert_id must not contain control characters")
    return normalized


def _validate_analyst_id(analyst_id: str | None) -> str | None:
    if analyst_id is None:
        return None
    if not isinstance(analyst_id, str):
        raise TypeError("analyst_id must be a string or None")
    value = analyst_id.strip()
    if not value or len(value) > _MAX_ANALYST_ID_LENGTH:
        raise ValueError("analyst_id must be non-empty and at most 128 characters")
    if not _ANALYST_ID_PATTERN.fullmatch(value):
        raise ValueError("analyst_id must be an opaque identifier")
    return value


def _validate_comment(comment: str | None) -> str | None:
    if comment is None:
        return None
    if not isinstance(comment, str):
        raise TypeError("comment must be a string or None")
    value = comment.strip()
    if not value:
        raise ValueError("comment must not be empty")
    if len(value) > _MAX_COMMENT_LENGTH:
        raise ValueError("comment must be at most 1000 characters")
    if any(ord(char) < 32 and char not in "\t\n" for char in value):
        raise ValueError("comment must not contain control characters")
    return value


def _has_disallowed_control(value: str) -> bool:
    return any(ord(char) < 32 for char in value)


def _format_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime):
        raise TypeError("clock must return a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("feedback timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp_key(value: str) -> tuple[float, str]:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("stored feedback timestamp is invalid") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("stored feedback timestamp must include a timezone")
    return timestamp.timestamp(), value


def _merge_threshold_samples(values: list[Any]) -> list[Any]:
    unique = []
    seen = set()
    for value in values:
        marker = repr(value)
        if marker not in seen:
            unique.append(value)
            seen.add(marker)
    return unique


def _suggest_thresholds(values: list[Any], increase: float) -> list[Any]:
    suggestions = []
    for value in values:
        suggestions.append(_map_numeric_threshold(value, increase))
    return suggestions


def _map_numeric_threshold(value: Any, increase: float) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _map_numeric_threshold(item, increase)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_map_numeric_threshold(item, increase) for item in value]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    if not math.isfinite(value) or value < 0:
        return value
    if value <= 1:
        return min(1.0, value + increase * (1.0 - value))
    return value * (1.0 + increase)
