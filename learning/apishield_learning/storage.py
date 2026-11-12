"""Storage interfaces; implementations await a platform database decision."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Mapping, Protocol


class LearningStorage(Protocol):
    """Persistence boundary for safe baselines, alerts, and analyst feedback.

    Implementations must accept only privacy-safe records. In particular, do
    not pass raw gateway events, raw caller/IP identifiers, payload values,
    request/response bodies, or credentials into these methods.
    """

    def save_baseline(self, upstream_id: str, baseline: Mapping[str, object]) -> None:
        """Persist a baseline snapshot using the platform-selected backend."""
        ...

    def load_baseline(self, upstream_id: str) -> Mapping[str, object] | None:
        """Load a baseline snapshot, or return None if it has not been learned."""
        ...

    def save_alert(self, alert: Mapping[str, object]) -> None:
        """Create or replace an alert by its unique alert ID."""
        ...

    def update_alert(self, alert: Mapping[str, object]) -> None:
        """Update an alert that already exists."""
        ...

    def get_alert(self, alert_id: str) -> Mapping[str, Any] | None:
        """Return one alert snapshot by ID."""
        ...

    def list_alerts(self) -> list[Mapping[str, Any]]:
        """Return detached alert snapshots."""
        ...

    def find_recent_alert(
        self, grouping_key: str, since_timestamp: str
    ) -> Mapping[str, Any] | None:
        """Return the most recently seen active alert matching the group key."""
        ...

    def save_feedback(self, feedback: Mapping[str, object]) -> None:
        """Append one immutable analyst-feedback record."""
        ...

    def list_feedback(self) -> list[Mapping[str, Any]]:
        """Return detached feedback records in submission order."""
        ...


class InMemoryLearningStorage:
    """JSON-copying development adapter with no external database dependency."""

    def __init__(self) -> None:
        self._baselines: dict[str, dict[str, object]] = {}
        self._alerts: dict[str, dict[str, object]] = {}
        self._feedback: list[dict[str, object]] = []

    def save_baseline(
        self, upstream_id: str, baseline: Mapping[str, object]
    ) -> None:
        """Store a detached JSON-safe snapshot keyed by upstream."""
        self._baselines[upstream_id] = json.loads(
            json.dumps(baseline, allow_nan=False)
        )

    def load_baseline(self, upstream_id: str) -> Mapping[str, object] | None:
        """Return a detached snapshot so callers cannot mutate stored state."""
        baseline = self._baselines.get(upstream_id)
        if baseline is None:
            return None
        return json.loads(json.dumps(baseline, allow_nan=False))

    def save_alert(self, alert: Mapping[str, object]) -> None:
        """Create or replace an alert while preserving ID-based identity."""
        alert_id = alert.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            raise ValueError("alert must include a non-empty alert_id")
        self._alerts[alert_id] = json.loads(json.dumps(alert, allow_nan=False))

    def update_alert(self, alert: Mapping[str, object]) -> None:
        """Replace an existing alert snapshot by ID."""
        alert_id = alert.get("alert_id")
        if not isinstance(alert_id, str) or alert_id not in self._alerts:
            raise KeyError(f"alert not found: {alert_id}")
        self.save_alert(alert)

    def get_alert(self, alert_id: str) -> Mapping[str, Any] | None:
        """Return a detached alert snapshot by ID."""
        alert = self._alerts.get(alert_id)
        if alert is None:
            return None
        return json.loads(json.dumps(alert, allow_nan=False))

    def list_alerts(self) -> list[Mapping[str, Any]]:
        """Return detached alert snapshots in insertion order."""
        return [
            json.loads(json.dumps(alert, allow_nan=False))
            for alert in self._alerts.values()
        ]

    def find_recent_alert(
        self, grouping_key: str, since_timestamp: str
    ) -> Mapping[str, Any] | None:
        """Find the newest non-resolved alert for a group within the repeat window."""
        eligible = [
            alert
            for alert in self._alerts.values()
            if alert.get("grouping_key") == grouping_key
            and alert.get("status") in {"new", "acknowledged"}
            and isinstance(alert.get("last_seen"), str)
            and _timestamp_value(alert["last_seen"])
            >= _timestamp_value(since_timestamp)
        ]
        if not eligible:
            return None
        alert = max(
            eligible,
            key=lambda item: _timestamp_value(str(item.get("last_seen", ""))),
        )
        return json.loads(json.dumps(alert, allow_nan=False))

    def save_feedback(self, feedback: Mapping[str, object]) -> None:
        """Append feedback without replacing prior decisions."""
        self._feedback.append(json.loads(json.dumps(feedback, allow_nan=False)))

    def list_feedback(self) -> list[Mapping[str, Any]]:
        """Return detached feedback records in submission order."""
        return [
            json.loads(json.dumps(feedback, allow_nan=False))
            for feedback in self._feedback
        ]


def _timestamp_value(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
