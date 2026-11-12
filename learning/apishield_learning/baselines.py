"""Privacy-safe EWMA and rolling baselines for API traffic features."""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .features import TrafficFeatures
from .storage import InMemoryLearningStorage, LearningStorage

WARMUP = "warmup"
ACTIVE = "active"
INSUFFICIENT_DATA = "insufficient_data"
SUSPICIOUS_ACTIONS = frozenset({"block", "throttle", "challenge"})


@dataclass(frozen=True)
class BaselineConfig:
    """Controls warm-up, rolling history, and conservative adaptation."""

    min_observations: int = 30
    warmup_period_seconds: float = 3600.0
    ewma_alpha: float = 0.2
    rolling_window_size: int = 1000
    max_shapes_per_endpoint: int = 128
    rate_window_seconds: int = 60
    min_update_samples: int = 5
    max_update_z_score: float = 6.0

    def __post_init__(self) -> None:
        if self.min_observations <= 0:
            raise ValueError("min_observations must be positive")
        if not math.isfinite(self.warmup_period_seconds) or self.warmup_period_seconds < 0:
            raise ValueError("warmup_period_seconds must be finite and non-negative")
        if not 0 < self.ewma_alpha <= 1:
            raise ValueError("ewma_alpha must be greater than 0 and at most 1")
        if self.rolling_window_size <= 0:
            raise ValueError("rolling_window_size must be positive")
        if self.max_shapes_per_endpoint <= 0:
            raise ValueError("max_shapes_per_endpoint must be positive")
        if self.rate_window_seconds <= 0:
            raise ValueError("rate_window_seconds must be positive")
        if self.min_update_samples < 2:
            raise ValueError("min_update_samples must be at least 2")
        if not math.isfinite(self.max_update_z_score) or self.max_update_z_score <= 0:
            raise ValueError("max_update_z_score must be finite and positive")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> BaselineConfig:
        """Read optional baseline tuning settings from the environment."""
        values = os.environ if env is None else env

        def integer(name: str, default: int) -> int:
            try:
                return int(values.get(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc

        def number(name: str, default: float) -> float:
            try:
                return float(values.get(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be numeric") from exc

        return cls(
            min_observations=integer("APISHIELD_LEARNING_MIN_OBSERVATIONS", 30),
            warmup_period_seconds=number(
                "APISHIELD_LEARNING_WARMUP_SECONDS", 3600.0
            ),
            ewma_alpha=number("APISHIELD_LEARNING_EWMA_ALPHA", 0.2),
            rolling_window_size=integer(
                "APISHIELD_LEARNING_ROLLING_WINDOW_SIZE", 1000
            ),
            max_shapes_per_endpoint=integer(
                "APISHIELD_LEARNING_MAX_SHAPES_PER_ENDPOINT", 128
            ),
            rate_window_seconds=integer(
                "APISHIELD_LEARNING_RATE_WINDOW_SECONDS", 60
            ),
            min_update_samples=integer(
                "APISHIELD_LEARNING_MIN_UPDATE_SAMPLES", 5
            ),
            max_update_z_score=number(
                "APISHIELD_LEARNING_MAX_UPDATE_Z_SCORE", 6.0
            ),
        )


def calculate_z_score(
    value: float,
    mean: float,
    standard_deviation: float,
    sample_count: int,
    *,
    min_samples: int = 2,
) -> float | None:
    """Return a finite Z-score, or None when evidence is insufficient/undefined.

    Zero-variance samples yield zero for an exact match and None otherwise;
    callers can treat the latter as a deviation without introducing infinity
    into persisted JSON.
    """
    if sample_count < min_samples:
        return None
    if not all(math.isfinite(x) for x in (value, mean, standard_deviation)):
        return None
    if standard_deviation < 0:
        raise ValueError("standard_deviation must be non-negative")
    if standard_deviation == 0:
        return 0.0 if value == mean else None
    score = (value - mean) / standard_deviation
    return score if math.isfinite(score) else None


@dataclass
class RollingMetric:
    """Rolling moments plus an EWMA for one numeric feature."""

    alpha: float
    window_size: int
    values: deque[float] = field(default_factory=deque)
    ewma: float | None = None
    last_z_score: float | None = None

    @property
    def count(self) -> int:
        return len(self.values)

    @property
    def mean(self) -> float | None:
        return sum(self.values) / len(self.values) if self.values else None

    @property
    def variance(self) -> float | None:
        if not self.values:
            return None
        average = self.mean
        assert average is not None
        return sum((value - average) ** 2 for value in self.values) / len(self.values)

    @property
    def standard_deviation(self) -> float | None:
        variance = self.variance
        return math.sqrt(variance) if variance is not None else None

    @property
    def minimum(self) -> float | None:
        return min(self.values) if self.values else None

    @property
    def maximum(self) -> float | None:
        return max(self.values) if self.values else None

    def observe(self, value: float) -> None:
        """Add a finite sample and update EWMA using the configured alpha."""
        if not math.isfinite(value):
            raise ValueError("metric sample must be finite")
        previous_mean = self.mean
        previous_std = self.standard_deviation
        if previous_mean is not None and previous_std is not None:
            self.last_z_score = calculate_z_score(
                value, previous_mean, previous_std, self.count
            )
        else:
            self.last_z_score = None
        if self.ewma is None:
            self.ewma = value
        else:
            self.ewma = self.alpha * value + (1 - self.alpha) * self.ewma
        if self.values.maxlen != self.window_size:
            self.values = deque(self.values, maxlen=self.window_size)
        self.values.append(value)

    def to_dict(self) -> dict[str, Any]:
        """Return finite JSON-friendly rolling and EWMA values."""
        return {
            "count": self.count,
            "mean": self.mean,
            "variance": self.variance,
            "standard_deviation": self.standard_deviation,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "ewma": self.ewma,
            "last_z_score": self.last_z_score,
            "values": list(self.values),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], config: BaselineConfig) -> RollingMetric:
        metric = cls(config.ewma_alpha, config.rolling_window_size)
        values = data.get("values", [])
        if not isinstance(values, list) or not all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            for value in values
        ):
            raise ValueError("invalid rolling metric values")
        metric.values.extend(float(value) for value in values[-config.rolling_window_size :])
        ewma = data.get("ewma")
        if ewma is not None:
            if not isinstance(ewma, (int, float)) or not math.isfinite(ewma):
                raise ValueError("invalid EWMA value")
            metric.ewma = float(ewma)
        last_z_score = data.get("last_z_score")
        if last_z_score is not None:
            if not isinstance(last_z_score, (int, float)) or not math.isfinite(last_z_score):
                raise ValueError("invalid last Z-score")
            metric.last_z_score = float(last_z_score)
        return metric


@dataclass
class _EndpointState:
    endpoint: str
    observations: int = 0
    accepted_observations: int = 0
    first_seen: str | None = None
    last_updated: str | None = None
    metrics: dict[str, RollingMetric] = field(default_factory=dict)
    status_counts: Counter[str] = field(default_factory=Counter)
    shapes: set[str] = field(default_factory=set)
    shape_counts: Counter[str] = field(default_factory=Counter)
    endpoint_frequency: int = 0
    rate_window_start: str | None = None
    rate_window_count: int = 0
    completed_rate_windows: set[str] = field(default_factory=set)

    def state(self, config: BaselineConfig) -> str:
        if self.first_seen is None:
            return INSUFFICIENT_DATA
        elapsed = _timestamp(self.last_updated) - _timestamp(self.first_seen)
        warmup_complete = elapsed >= config.warmup_period_seconds
        enough_samples = self.accepted_observations >= config.min_observations
        if warmup_complete and enough_samples:
            return ACTIVE
        if warmup_complete and not enough_samples:
            return INSUFFICIENT_DATA
        return WARMUP

    def to_dict(self, config: BaselineConfig) -> dict[str, Any]:
        metrics = {name: metric.to_dict() for name, metric in self.metrics.items()}
        return {
            "endpoint": self.endpoint,
            "observation_count": self.observations,
            "accepted_observation_count": self.accepted_observations,
            "state": self.state(config),
            "first_seen": self.first_seen,
            "last_updated": self.last_updated,
            "ewma": {name: metric.ewma for name, metric in self.metrics.items()},
            "rolling": metrics,
            "status_counts": dict(self.status_counts),
            "error_count": self.status_counts.get("error", 0),
            "learned_shape_hashes": sorted(self.shapes),
            "shape_counts": dict(self.shape_counts),
            "endpoint_frequency": self.endpoint_frequency,
            "rate_window_start": self.rate_window_start,
            "rate_window_count": self.rate_window_count,
            "current_rate_per_minute": (
                self.rate_window_count * 60 / config.rate_window_seconds
            ),
            "completed_rate_windows": sorted(self.completed_rate_windows),
        }

    @classmethod
    def from_dict(
        cls, data: Mapping[str, Any], config: BaselineConfig
    ) -> _EndpointState:
        endpoint = data.get("endpoint")
        if not isinstance(endpoint, str):
            raise ValueError("invalid endpoint baseline")
        state = cls(endpoint=endpoint)
        for field_name in ("observations", "accepted_observations", "endpoint_frequency", "rate_window_count"):
            field_value = data.get(
                {
                    "observations": "observation_count",
                    "accepted_observations": "accepted_observation_count",
                }.get(field_name, field_name),
                0,
            )
            if not isinstance(field_value, int) or field_value < 0:
                raise ValueError(f"invalid {field_name} in baseline")
            setattr(state, field_name, field_value)
        state.first_seen = _optional_string(data.get("first_seen"))
        state.last_updated = _optional_string(data.get("last_updated"))
        state.rate_window_start = _optional_string(data.get("rate_window_start"))
        completed_windows = data.get("completed_rate_windows", [])
        if not isinstance(completed_windows, list) or not all(
            isinstance(item, str) for item in completed_windows
        ):
            raise ValueError("invalid completed rate windows")
        state.completed_rate_windows = set(completed_windows)
        metrics = data.get("rolling", {})
        if not isinstance(metrics, dict):
            raise ValueError("invalid rolling metrics")
        state.metrics = {
            name: RollingMetric.from_dict(value, config)
            for name, value in metrics.items()
            if isinstance(value, dict)
        }
        for name in metrics:
            if name not in state.metrics:
                raise ValueError("invalid rolling metric")
        statuses = data.get("status_counts", {})
        shapes = data.get("learned_shape_hashes", [])
        shape_counts = data.get("shape_counts", {})
        if not isinstance(statuses, dict) or not isinstance(shape_counts, dict):
            raise ValueError("invalid baseline counters")
        if not isinstance(shapes, list) or not all(isinstance(item, str) for item in shapes):
            raise ValueError("invalid learned shape hashes")
        state.status_counts.update(_integer_counter(statuses))
        state.shapes.update(shapes)
        state.shape_counts.update(_integer_counter(shape_counts))
        return state


class BaselineLearner:
    """Learn endpoint and pseudonymous caller/endpoint normal-traffic profiles.

    Warm-up observations with block/throttle/challenge actions or rule hits are
    counted as seen, but excluded from statistical and shape baselines. Once
    active, adaptation is opt-in via ``trusted=True`` and only already-learned
    shapes are eligible. This prevents a single suspicious observation or
    novel shape from redefining normal behavior.
    """

    def __init__(
        self,
        config: BaselineConfig | None = None,
        *,
        storage: LearningStorage | None = None,
        upstream_id: str = "default",
    ):
        if not upstream_id:
            raise ValueError("upstream_id must not be empty")
        self.config = config or BaselineConfig.from_env()
        self.storage = storage or InMemoryLearningStorage()
        self.upstream_id = upstream_id
        self._endpoints: dict[str, _EndpointState] = {}
        self._callers: dict[str, _EndpointState] = {}
        self._sequences: Counter[str] = Counter()
        self._last_endpoint_by_caller: dict[str, str] = {}
        self._last_timestamp_by_caller: dict[str, str] = {}
        saved = self.storage.load_baseline(upstream_id)
        if saved is not None:
            self.restore(saved)

    def update(
        self, feature_record: TrafficFeatures | Mapping[str, Any], *, trusted: bool = False
    ) -> dict[str, Any]:
        """Observe one safe feature record and return its baseline-learning result."""
        if not isinstance(trusted, bool):
            raise TypeError("trusted must be a boolean")
        features = _coerce_features(feature_record)
        expected_rate_window = _rate_window_start(
            features.ts, self.config.rate_window_seconds
        )
        if features.rate_window_start != expected_rate_window:
            raise ValueError(
                "rate_window_start does not match configured rate_window_seconds"
            )
        endpoint = features.endpoint_key
        endpoint_state = self._endpoints.setdefault(
            endpoint, _EndpointState(endpoint=endpoint)
        )
        caller_key = features.caller_endpoint_key
        caller_state = self._callers.setdefault(
            caller_key, _EndpointState(endpoint=endpoint)
        )

        shape_is_new = features.shape_hash not in endpoint_state.shapes
        outlier = _is_statistical_outlier(features, endpoint_state, self.config)
        eligible = _is_safe_observation(features) and not outlier
        current_state = endpoint_state.state(self.config)
        if current_state == ACTIVE:
            eligible = eligible and trusted and not shape_is_new
        endpoint_state.observations += 1
        caller_state.observations += 1
        _update_seen_times(endpoint_state, features.ts)
        _update_seen_times(caller_state, features.ts)

        if eligible:
            self._observe_state(endpoint_state, features, shape_is_new)
            self._observe_state(caller_state, features, shape_is_new)
            self._update_rate(endpoint_state, features)
            self._update_rate(caller_state, features)
            self._update_sequence(features.caller_id, endpoint, features.ts)

        new_state = endpoint_state.state(self.config)
        result = {
            "endpoint": endpoint,
            "observation_count": endpoint_state.observations,
            "accepted_observation_count": endpoint_state.accepted_observations,
            "state": new_state,
            "warmup_progress": self._progress(endpoint_state),
            "shape_is_new": shape_is_new and current_state == ACTIVE,
            "accepted_for_baseline": eligible,
            "rejected_as_outlier": outlier,
            "sequence_supported": True,
        }
        self._persist()
        return result

    def get_baseline(
        self, endpoint: str, caller: str | None = None
    ) -> dict[str, Any]:
        """Get endpoint baseline, or a caller-specific baseline using pseudonymous caller ID."""
        state = (
            self._callers.get(f"{caller}:{endpoint}")
            if caller is not None
            else self._endpoints.get(endpoint)
        )
        return self._render_state(state, endpoint)

    def get_endpoint_baseline(self, endpoint: str) -> dict[str, Any]:
        """Get endpoint-wide rates, metric moments, counts, and shape allow-list."""
        return self.get_baseline(endpoint)

    def get_shape_allowlist(self, endpoint: str) -> list[str]:
        """Return learned shape fingerprints for an endpoint (never payload values)."""
        state = self._endpoints.get(endpoint)
        return sorted(state.shapes) if state else []

    def get_warmup_status(self) -> dict[str, Any]:
        """Summarize warm-up state and progress across known endpoints."""
        endpoints = [state.to_dict(self.config) for state in self._endpoints.values()]
        counts = Counter(item["state"] for item in endpoints)
        return {
            "mode": (
                ACTIVE
                if endpoints and counts[ACTIVE] == len(endpoints)
                else INSUFFICIENT_DATA
                if endpoints and counts[INSUFFICIENT_DATA] == len(endpoints)
                else WARMUP
            ),
            "endpoints": len(endpoints),
            "active": counts[ACTIVE],
            "warmup": counts[WARMUP],
            "insufficient_data": counts[INSUFFICIENT_DATA],
            "progress": (
                sum(self._progress(state) for state in self._endpoints.values())
                / len(self._endpoints)
                if self._endpoints
                else 0.0
            ),
        }

    def get_all_baselines(self) -> dict[str, Any]:
        """Return endpoint baselines keyed by the method-and-template endpoint key."""
        return {
            endpoint: state.to_dict(self.config)
            for endpoint, state in sorted(self._endpoints.items())
        }

    def get_sequence_frequencies(self) -> dict[str, int]:
        """Return endpoint transition counts observed in per-caller event order."""
        return dict(sorted(self._sequences.items()))

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable snapshot suitable for any storage adapter."""
        return {
            "version": 1,
            "config": {
                "min_observations": self.config.min_observations,
                "warmup_period_seconds": self.config.warmup_period_seconds,
                "ewma_alpha": self.config.ewma_alpha,
                "rolling_window_size": self.config.rolling_window_size,
                "max_shapes_per_endpoint": self.config.max_shapes_per_endpoint,
                "rate_window_seconds": self.config.rate_window_seconds,
                "min_update_samples": self.config.min_update_samples,
                "max_update_z_score": self.config.max_update_z_score,
            },
            "endpoints": self.get_all_baselines(),
            "callers": {
                key: state.to_dict(self.config)
                for key, state in sorted(self._callers.items())
            },
            "sequences": dict(sorted(self._sequences.items())),
            "last_endpoint_by_caller": dict(sorted(self._last_endpoint_by_caller.items())),
            "last_timestamp_by_caller": dict(sorted(self._last_timestamp_by_caller.items())),
        }

    def restore(self, snapshot: Mapping[str, Any]) -> None:
        """Restore a prior snapshot, rejecting malformed or privacy-unsafe keys."""
        if snapshot.get("version") != 1:
            raise ValueError("unsupported baseline snapshot version")
        endpoints = snapshot.get("endpoints")
        callers = snapshot.get("callers", {})
        sequences = snapshot.get("sequences", {})
        last_endpoints = snapshot.get("last_endpoint_by_caller", {})
        last_timestamps = snapshot.get("last_timestamp_by_caller", {})
        if not all(
            isinstance(value, dict)
            for value in (
                endpoints,
                callers,
                sequences,
                last_endpoints,
                last_timestamps,
            )
        ):
            raise ValueError("invalid baseline snapshot")
        restored_endpoints = {
            key: _EndpointState.from_dict(value, self.config)
            for key, value in endpoints.items()
        }
        restored_callers = {
            key: _EndpointState.from_dict(value, self.config)
            for key, value in callers.items()
        }
        if not all(
            re.fullmatch(r"caller_[0-9a-f]{64}:.+", key)
            for key in restored_callers
        ):
            raise ValueError("caller baseline keys must use pseudonymous identifiers")
        restored_sequences = _integer_counter(sequences)
        if not all(isinstance(key, str) for key in last_endpoints) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in last_timestamps.items()
        ):
            raise ValueError("invalid endpoint sequence keys")
        if not all(
            re.fullmatch(r"caller_[0-9a-f]{64}", key)
            for key in last_endpoints
        ) or set(last_endpoints) != set(last_timestamps):
            raise ValueError("endpoint sequence state must use pseudonymous callers")
        for timestamp in last_timestamps.values():
            _timestamp(timestamp)
        self._endpoints = restored_endpoints
        self._callers = restored_callers
        self._sequences = Counter(restored_sequences)
        self._last_endpoint_by_caller = dict(last_endpoints)
        self._last_timestamp_by_caller = dict(last_timestamps)

    def _observe_state(
        self, state: _EndpointState, features: TrafficFeatures, shape_is_new: bool
    ) -> None:
        if state.first_seen is None:
            state.first_seen = features.ts
        _update_seen_times(state, features.ts)
        state.accepted_observations += 1
        state.endpoint_frequency += features.request_count
        state.status_counts[str(features.status)] += 1
        if features.status >= 400:
            state.status_counts["error"] += 1
        numeric_samples = {
            "error": float(features.status >= 400),
            "request_size": float(features.req_size),
            "response_size": float(features.resp_size),
            "latency_ms": float(features.latency_ms),
        }
        for name, value in numeric_samples.items():
            state.metrics.setdefault(name, self._new_metric()).observe(value)
        if shape_is_new and len(state.shapes) < self.config.max_shapes_per_endpoint:
            state.shapes.add(features.shape_hash)
        if features.shape_hash in state.shapes:
            state.shape_counts[features.shape_hash] += 1

    def _update_rate(self, state: _EndpointState, features: TrafficFeatures) -> None:
        window = features.rate_window_start
        if state.rate_window_start is None:
            state.rate_window_start = window
            state.rate_window_count = features.request_count
            return
        if window == state.rate_window_start:
            state.rate_window_count += features.request_count
            return
        if window > state.rate_window_start:
            self._finalize_rate_window(state)
            window_gap = int(
                (_timestamp(window) - _timestamp(state.rate_window_start))
                // self.config.rate_window_seconds
            )
            for _ in range(min(max(0, window_gap - 1), self.config.rolling_window_size)):
                state.metrics.setdefault("request_rate", self._new_metric()).observe(0.0)
            state.rate_window_start = window
            state.rate_window_count = features.request_count

    def _finalize_rate_window(self, state: _EndpointState) -> None:
        window = state.rate_window_start
        if window is None or window in state.completed_rate_windows:
            return
        state.metrics.setdefault("request_rate", self._new_metric()).observe(
            state.rate_window_count * 60 / self.config.rate_window_seconds
        )
        state.completed_rate_windows.add(window)
        if len(state.completed_rate_windows) > self.config.rolling_window_size:
            state.completed_rate_windows = set(
                sorted(state.completed_rate_windows)[-self.config.rolling_window_size :]
            )

    def _update_sequence(self, caller_id: str, endpoint: str, timestamp: str) -> None:
        previous = self._last_endpoint_by_caller.get(caller_id)
        previous_timestamp = self._last_timestamp_by_caller.get(caller_id)
        if (
            previous is not None
            and previous_timestamp is not None
            and timestamp > previous_timestamp
        ):
            self._sequences[f"{previous} -> {endpoint}"] += 1
        if previous_timestamp is None or timestamp > previous_timestamp:
            self._last_endpoint_by_caller[caller_id] = endpoint
            self._last_timestamp_by_caller[caller_id] = timestamp

    def _new_metric(self) -> RollingMetric:
        return RollingMetric(
            alpha=self.config.ewma_alpha,
            window_size=self.config.rolling_window_size,
        )

    def _progress(self, state: _EndpointState) -> float:
        observation_progress = min(
            1.0, state.accepted_observations / self.config.min_observations
        )
        if self.config.warmup_period_seconds == 0:
            time_progress = 1.0
        elif state.first_seen is None or state.last_updated is None:
            time_progress = 0.0
        else:
            elapsed = _timestamp(state.last_updated) - _timestamp(state.first_seen)
            time_progress = min(1.0, elapsed / self.config.warmup_period_seconds)
        return min(observation_progress, time_progress)

    def _render_state(
        self, state: _EndpointState | None, endpoint: str
    ) -> dict[str, Any]:
        if state is None:
            return {
                "endpoint": endpoint,
                "observation_count": 0,
                "accepted_observation_count": 0,
                "state": INSUFFICIENT_DATA,
                "warmup_progress": 0.0,
                "ewma": {},
                "rolling": {},
                "status_counts": {},
                "error_count": 0,
                "learned_shape_hashes": [],
                "endpoint_frequency": 0,
                "current_rate_per_minute": 0.0,
                "last_updated": None,
                "metrics": {},
            }
        result = state.to_dict(self.config)
        result["warmup_progress"] = self._progress(state)
        result["metrics"] = {
            name: {
                **metric.to_dict(),
                "z_score": metric.last_z_score,
            }
            for name, metric in state.metrics.items()
        }
        return result

    def _persist(self) -> None:
        snapshot = self.snapshot()
        # Ensure the storage boundary only receives JSON-safe primitive data.
        json.dumps(snapshot, allow_nan=False)
        self.storage.save_baseline(self.upstream_id, snapshot)


def _is_safe_observation(features: TrafficFeatures) -> bool:
    return (
        features.action not in SUSPICIOUS_ACTIONS
        and features.rule_hit_count == 0
    )


def _is_statistical_outlier(
    features: TrafficFeatures,
    state: _EndpointState,
    config: BaselineConfig,
) -> bool:
    """Keep extreme observations out once a small comparison baseline exists."""
    candidates = {
        "error": float(features.status >= 400),
        "request_size": float(features.req_size),
        "response_size": float(features.resp_size),
        "latency_ms": float(features.latency_ms),
    }
    for name, value in candidates.items():
        metric = state.metrics.get(name)
        if metric is None or metric.count < config.min_update_samples:
            continue
        mean = metric.mean
        standard_deviation = metric.standard_deviation
        if mean is None or standard_deviation is None:
            continue
        z_score = calculate_z_score(value, mean, standard_deviation, metric.count)
        if z_score is None:
            if standard_deviation == 0 and value != mean:
                return True
        elif abs(z_score) > config.max_update_z_score:
            return True
    return False


def _coerce_features(value: TrafficFeatures | Mapping[str, Any]) -> TrafficFeatures:
    if isinstance(value, TrafficFeatures):
        _validate_features(value)
        return value
    if not isinstance(value, Mapping):
        raise TypeError("feature_record must be TrafficFeatures or a mapping")
    fields = TrafficFeatures.__dataclass_fields__
    try:
        features = TrafficFeatures(**{
            name: value[name] for name in fields if name in value
        })
    except TypeError as exc:
        raise ValueError("invalid feature record") from exc
    _validate_features(features)
    return features


def _validate_features(features: TrafficFeatures) -> None:
    if not isinstance(features.caller_id, str) or not re.fullmatch(
        r"caller_[0-9a-f]{64}", features.caller_id
    ):
        raise ValueError("caller_id must be pseudonymized")
    if not isinstance(features.ip_id, str) or not re.fullmatch(
        r"ip_[0-9a-f]{64}", features.ip_id
    ):
        raise ValueError("ip_id must be pseudonymized")
    if not isinstance(features.endpoint_key, str) or not isinstance(
        features.caller_endpoint_key, str
    ):
        raise ValueError("endpoint grouping keys must be strings")
    if not isinstance(features.method, str) or not isinstance(
        features.path_template, str
    ):
        raise ValueError("endpoint fields must be strings")
    if not features.endpoint_key or not features.path_template or not features.method:
        raise ValueError("endpoint fields must not be empty")
    if features.caller_endpoint_key != f"{features.caller_id}:{features.endpoint_key}":
        raise ValueError("caller_endpoint_key must use the pseudonymous caller ID")
    if features.endpoint_key != f"{features.method} {features.path_template}":
        raise ValueError("endpoint_key must match method and path_template")
    if not isinstance(features.shape_hash, str) or not features.shape_hash:
        raise ValueError("shape_hash must be a non-empty fingerprint")
    if (
        not isinstance(features.rule_hit_count, int)
        or isinstance(features.rule_hit_count, bool)
        or features.rule_hit_count < 0
    ):
        raise ValueError("rule_hit_count must be a non-negative integer")
    if (
        not isinstance(features.request_count, int)
        or isinstance(features.request_count, bool)
        or features.request_count <= 0
    ):
        raise ValueError("request_count must be positive")
    if (
        not isinstance(features.status, int)
        or isinstance(features.status, bool)
        or not 100 <= features.status <= 599
    ):
        raise ValueError("status must be between 100 and 599")
    if not isinstance(features.req_size, int) or isinstance(features.req_size, bool):
        raise ValueError("req_size must be an integer")
    if not isinstance(features.resp_size, int) or isinstance(features.resp_size, bool):
        raise ValueError("resp_size must be an integer")
    if not all(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        for value in (
            features.latency_ms,
            features.time_of_day_sin,
            features.time_of_day_cos,
        )
    ):
        raise ValueError("numeric features must be finite")
    if features.req_size < 0 or features.resp_size < 0:
        raise ValueError("sizes must be non-negative")
    if features.req_size > 2**63 - 1 or features.resp_size > 2**63 - 1:
        raise ValueError("sizes are outside the supported numeric range")
    if not isinstance(features.action, str) or features.action not in {
        "allow",
        "log",
        "block",
        "throttle",
        "challenge",
    }:
        raise ValueError("action is invalid")
    if not isinstance(features.ts, str) or not isinstance(
        features.rate_window_start, str
    ):
        raise ValueError("timestamps must be strings")
    _timestamp(features.ts)
    _timestamp(features.rate_window_start)


def _update_seen_times(state: _EndpointState, value: str) -> None:
    timestamp = _parse_datetime(value)
    normalized = timestamp.isoformat().replace("+00:00", "Z")
    if state.first_seen is None or timestamp < _parse_datetime(state.first_seen):
        state.first_seen = normalized
    if state.last_updated is None or timestamp > _parse_datetime(state.last_updated):
        state.last_updated = normalized


def _timestamp(value: str | None) -> float:
    if value is None:
        return 0.0
    return _parse_datetime(value).timestamp()


def _rate_window_start(value: str, window_seconds: int) -> str:
    timestamp = _timestamp(value)
    window_epoch = int(timestamp) // window_seconds * window_seconds
    return (
        datetime.fromtimestamp(window_epoch, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("baseline timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("baseline timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("invalid baseline timestamp")
    return value


def _integer_counter(value: Mapping[str, Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str) or not isinstance(count, int) or count < 0:
            raise ValueError("invalid baseline count")
        result[key] = count
    return result
