"""Deterministic Isolation Forest anomaly indicators for safe traffic features."""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from typing import Any, Protocol

import numpy as np
from sklearn.ensemble import IsolationForest

from ..baselines import ACTIVE
from ..features import TrafficFeatures
from .results import DetectorResult

FEATURE_NAMES = (
    "status",
    "latency_log1p",
    "request_size_log1p",
    "response_size_log1p",
    "hour_sin",
    "hour_cos",
    "rule_hit_count",
)


class ModelStore(Protocol):
    """Persistence boundary for trusted local model objects."""

    def save(
        self, key: str, model: IsolationForest, reference_scores: list[float]
    ) -> None:
        """Store model and training score calibration data."""
        ...

    def load(
        self, key: str
    ) -> tuple[IsolationForest, list[float]] | None:
        """Load a previously stored model and its calibration scores."""
        ...


class InMemoryModelStore:
    """Development-only model store; no database or serialized untrusted files."""

    def __init__(self) -> None:
        self._models: dict[str, tuple[IsolationForest, list[float]]] = {}

    def save(
        self, key: str, model: IsolationForest, reference_scores: list[float]
    ) -> None:
        self._models[key] = (model, list(reference_scores))

    def load(
        self, key: str
    ) -> tuple[IsolationForest, list[float]] | None:
        value = self._models.get(key)
        return (value[0], list(value[1])) if value else None


@dataclass(frozen=True)
class IsolationForestConfig:
    """Controls training size, retraining cadence, and sklearn parameters."""

    min_samples: int = 100
    retrain_every: int = 100
    max_samples: int | float | str = "auto"
    n_estimators: int = 100
    contamination: float = 0.05
    random_state: int = 42
    model_key: str = "apishield-m3"

    def __post_init__(self) -> None:
        if self.min_samples < 2:
            raise ValueError("min_samples must be at least 2")
        if self.retrain_every <= 0:
            raise ValueError("retrain_every must be positive")
        if self.n_estimators <= 0:
            raise ValueError("n_estimators must be positive")
        if not 0 < self.contamination <= 0.5:
            raise ValueError("contamination must be in (0, 0.5]")
        if not self.model_key.strip():
            raise ValueError("model_key must not be empty")


class IsolationForestDetector:
    """Train and score traffic anomaly indicators with scikit-learn.

    Scores are the empirical lower-tail percentile of sklearn's
    ``score_samples`` over the training data, normalized to [0, 1]; larger
    values mean more anomalous. Scores at or above ``1-contamination`` are
    model anomaly indicators, never attack confirmations.
    """

    def __init__(
        self,
        config: IsolationForestConfig | None = None,
        *,
        model_store: ModelStore | None = None,
    ):
        self.config = config or IsolationForestConfig()
        self.model_store = model_store or InMemoryModelStore()
        self._samples: deque[tuple[float, ...]] = deque()
        self._model: IsolationForest | None = None
        self._reference_scores: list[float] = []
        self._samples_since_fit = 0
        stored = self.model_store.load(self.config.model_key)
        if stored is not None:
            self._model, self._reference_scores = stored

    @property
    def trained(self) -> bool:
        return self._model is not None

    @property
    def sample_count(self) -> int:
        return len(self._samples)

    def fit(self, samples: list[TrafficFeatures]) -> bool:
        """Train only on valid, non-enforced feature records."""
        vectors = []
        for sample in samples:
            vector = _safe_vector(sample)
            if vector is not None and _is_normal_candidate(sample):
                vectors.append(vector)
        if len(vectors) < self.config.min_samples:
            return False
        self._samples.clear()
        self._samples.extend(vectors[-self._max_training_samples() :])
        return self._fit_current()

    def observe(self, features: TrafficFeatures, *, baseline_ready: bool = True) -> bool:
        """Collect eligible normal samples and retrain on a configured schedule."""
        if not baseline_ready or not _is_normal_candidate(features):
            return False
        vector = _safe_vector(features)
        if vector is None:
            return False
        self._samples.append(vector)
        while len(self._samples) > self._max_training_samples():
            self._samples.popleft()
        self._samples_since_fit += 1
        if len(self._samples) < self.config.min_samples:
            return False
        if self._model is None or self._samples_since_fit >= self.config.retrain_every:
            return self._fit_current()
        return False

    def score(self, features: TrafficFeatures) -> float | None:
        """Return a normalized anomaly indicator, or None before training/invalid input."""
        if self._model is None:
            return None
        vector = _safe_vector(features)
        if vector is None:
            return None
        score = float(self._model.score_samples(np.asarray([vector], dtype=float))[0])
        if not math.isfinite(score) or not self._reference_scores:
            return None
        # A low sklearn score is anomalous; map its empirical lower-tail rank.
        greater = sum(reference > score for reference in self._reference_scores)
        equal = sum(reference == score for reference in self._reference_scores)
        return (greater + 0.5 * equal) / len(self._reference_scores)

    def detect(
        self,
        features: TrafficFeatures,
        *,
        baseline_ready: bool,
        timestamp: str | None = None,
    ) -> DetectorResult:
        """Return a shared result object without implying security confirmation."""
        score = self.score(features)
        ready = baseline_ready and self._model is not None
        detected = (
            ready
            and score is not None
            and score >= 1 - self.config.contamination
        )
        return DetectorResult(
            detector="isolation_forest",
            detected=bool(detected),
            kind="statistical_anomaly",
            score=score if score is not None else 0.0,
            severity=(
                "high"
                if detected and score is not None and score >= 0.98
                else "medium"
                if detected
                else "info"
            ),
            observed={name: value for name, value in zip(FEATURE_NAMES, _safe_vector(features) or ())},
            expected="learned multivariate normal-traffic distribution",
            threshold=1 - self.config.contamination,
            explanation=(
                "The multivariate feature vector is unusual relative to training data; "
                "this is an anomaly indicator, not proof of an attack."
                if detected
                else "The model is not ready or the feature vector is within its learned distribution."
            ),
            contributing_features=FEATURE_NAMES,
            baseline_ready=ready,
            timestamp=timestamp or features.ts,
            confirmed_attack=False,
        )

    def save(self) -> None:
        """Persist the fitted model through the configured model-store abstraction."""
        if self._model is not None:
            self.model_store.save(
                self.config.model_key, self._model, self._reference_scores
            )

    def load(self) -> bool:
        """Load a model from the configured model-store abstraction."""
        stored = self.model_store.load(self.config.model_key)
        if stored is None:
            return False
        model, scores = stored
        if not scores or not all(math.isfinite(score) for score in scores):
            return False
        self._model = model
        self._reference_scores = list(scores)
        return True

    def _fit_current(self) -> bool:
        if len(self._samples) < self.config.min_samples:
            return False
        model = IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            contamination=self.config.contamination,
            random_state=self.config.random_state,
            n_jobs=1,
        )
        matrix = np.asarray(list(self._samples), dtype=float)
        if matrix.ndim != 2 or not np.isfinite(matrix).all():
            return False
        model.fit(matrix)
        scores = [float(score) for score in model.score_samples(matrix)]
        if not scores or not all(math.isfinite(score) for score in scores):
            return False
        self._model = model
        self._reference_scores = scores
        self._samples_since_fit = 0
        self.save()
        return True

    def _max_training_samples(self) -> int:
        if self.config.max_samples == "auto":
            return max(self.config.min_samples, 10_000)
        if isinstance(self.config.max_samples, int):
            return max(self.config.min_samples, self.config.max_samples)
        return max(self.config.min_samples, 10_000)


def _is_normal_candidate(features: TrafficFeatures) -> bool:
    return (
        isinstance(features.rule_hit_count, int)
        and not isinstance(features.rule_hit_count, bool)
        and features.rule_hit_count >= 0
        and isinstance(features.action, str)
        and features.action in {"allow", "log"}
    )


def _safe_vector(features: TrafficFeatures) -> tuple[float, ...] | None:
    """Build a bounded numeric vector; no caller or IP identifier enters ML."""
    try:
        if (
            not _valid_number(features.status, minimum=100, maximum=599)
            or not _valid_number(features.req_size, minimum=0)
            or not _valid_number(features.resp_size, minimum=0)
            or not _valid_number(features.latency_ms, minimum=0)
            or not _valid_number(features.rule_hit_count, minimum=0)
            or not _valid_number(features.time_of_day_sin, minimum=-1, maximum=1)
            or not _valid_number(features.time_of_day_cos, minimum=-1, maximum=1)
        ):
            return None
        values = (
            float(features.status),
            math.log1p(float(features.latency_ms)),
            math.log1p(float(features.req_size)),
            math.log1p(float(features.resp_size)),
            float(features.time_of_day_sin),
            float(features.time_of_day_cos),
            float(features.rule_hit_count),
        )
    except (TypeError, ValueError, OverflowError):
        return None
    if not all(math.isfinite(value) for value in values):
        return None
    return values


def _valid_number(
    value: Any, *, minimum: float, maximum: float | None = None
) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    numeric = float(value)
    return (
        math.isfinite(numeric)
        and numeric >= minimum
        and (maximum is None or numeric <= maximum)
    )
