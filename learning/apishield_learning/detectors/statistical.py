"""Statistical anomaly and suspicious-signal detectors for traffic features."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping

from ..baselines import ACTIVE, calculate_z_score
from ..features import TrafficFeatures
from .results import DetectorResult

SUSPICIOUS_ACTIONS = frozenset({"block", "throttle", "challenge"})


@dataclass(frozen=True)
class DetectorConfig:
    """Thresholds for statistical evidence; scores are normalized to [0, 1]."""

    min_samples: int = 5
    z_score_threshold: float = 3.0
    request_rate_ratio_threshold: float = 3.0
    suspicious_signal_score: float = 0.45
    outlier_score_cap: float = 1.0

    def __post_init__(self) -> None:
        if self.min_samples < 2:
            raise ValueError("min_samples must be at least 2")
        if not math.isfinite(self.z_score_threshold) or self.z_score_threshold <= 0:
            raise ValueError("z_score_threshold must be finite and positive")
        if (
            not math.isfinite(self.request_rate_ratio_threshold)
            or self.request_rate_ratio_threshold <= 1
        ):
            raise ValueError("request_rate_ratio_threshold must be greater than 1")
        if not 0 <= self.suspicious_signal_score <= 1:
            raise ValueError("suspicious_signal_score must be between 0 and 1")
        if not 0 < self.outlier_score_cap <= 1:
            raise ValueError("outlier_score_cap must be in (0, 1]")


class StatisticalDetector:
    """Evaluate one feature record against its existing baseline structure."""

    def __init__(self, config: DetectorConfig | None = None):
        self.config = config or DetectorConfig()

    def detect(
        self,
        features: TrafficFeatures,
        baseline: Mapping[str, Any],
        *,
        all_baselines: Mapping[str, Any] | None = None,
        sequence_frequencies: Mapping[str, int] | None = None,
        previous_endpoint: str | None = None,
    ) -> list[DetectorResult]:
        """Return one consistently shaped result for each supported detector."""
        ready = baseline.get("state") == ACTIVE
        metrics = _mapping(baseline.get("metrics"))
        results = [
            self._numeric_result(
                "request_rate_spike",
                observed=_finite_or_none(baseline.get("current_rate_per_minute")),
                metric=metrics.get("request_rate"),
                timestamp=features.ts,
                baseline_ready=ready,
                features=("request_count", "rate_window_start"),
                ratio_threshold=self.config.request_rate_ratio_threshold,
            ),
            self._numeric_result(
                "request_size",
                observed=_finite_or_none(features.req_size),
                metric=metrics.get("request_size"),
                timestamp=features.ts,
                baseline_ready=ready,
                features=("req_size",),
            ),
            self._numeric_result(
                "response_size",
                observed=_finite_or_none(features.resp_size),
                metric=metrics.get("response_size"),
                timestamp=features.ts,
                baseline_ready=ready,
                features=("resp_size",),
            ),
            self._numeric_result(
                "latency",
                observed=_finite_or_none(features.latency_ms),
                metric=metrics.get("latency_ms"),
                timestamp=features.ts,
                baseline_ready=ready,
                features=("latency_ms",),
                high_only=True,
            ),
            self._error_result(features, metrics.get("error"), ready),
            self._shape_result(features, baseline, ready),
            self._endpoint_result(features, baseline, all_baselines, ready),
            self._rule_action_result(features, ready),
            self._sequence_result(
                features,
                previous_endpoint,
                sequence_frequencies or {},
                ready,
            ),
        ]
        return results

    def _numeric_result(
        self,
        name: str,
        *,
        observed: float | None,
        metric: Any,
        timestamp: str,
        baseline_ready: bool,
        features: tuple[str, ...],
        high_only: bool = False,
        ratio_threshold: float | None = None,
    ) -> DetectorResult:
        stats = _mapping(metric)
        mean = _finite_or_none(stats.get("mean"))
        std = _finite_or_none(stats.get("standard_deviation"))
        ewma = _finite_or_none(stats.get("ewma"))
        count = _integer(stats.get("count"))
        sufficient = baseline_ready and count >= self.config.min_samples
        if observed is None or mean is None or std is None or not sufficient:
            return _result(
                name,
                detected=False,
                kind="statistical_anomaly",
                score=0.0,
                severity="info",
                observed=observed,
                expected=ewma if ewma is not None else mean,
                threshold=self.config.z_score_threshold,
                explanation="Baseline history is insufficient for a reliable comparison.",
                features=features,
                baseline_ready=baseline_ready,
                timestamp=timestamp,
            )

        z_score = calculate_z_score(observed, mean, std, count)
        ratio_trigger = (
            ratio_threshold is not None
            and (ewma or 0) > 0
            and observed >= (ewma or 0) * ratio_threshold
        )
        zero_variance_outlier = z_score is None and observed != mean and std == 0
        detected = (
            (z_score is not None and (z_score >= self.config.z_score_threshold if high_only
                                      else abs(z_score) >= self.config.z_score_threshold))
            or ratio_trigger
            or zero_variance_outlier
        )
        severity = _severity(_normalized_score(z_score, ratio_trigger, zero_variance_outlier,
                                               self.config.z_score_threshold))
        score = _normalized_score(
            z_score, ratio_trigger, zero_variance_outlier, self.config.z_score_threshold
        )
        return _result(
            name,
            detected=detected,
            kind="statistical_anomaly",
            score=score,
            severity=("low" if severity == "info" else severity) if detected else "info",
            observed=observed,
            expected={"mean": mean, "ewma": ewma, "standard_deviation": std},
            threshold={
                "z_score": self.config.z_score_threshold,
                "ratio": ratio_threshold,
            },
            explanation=(
                "Observed traffic differs materially from the learned baseline; "
                "this is an anomaly indicator, not proof of an attack."
                if detected
                else "Observed value is within the learned baseline range."
            ),
            features=features,
            baseline_ready=baseline_ready,
            timestamp=timestamp,
        )

    def _error_result(
        self, features: TrafficFeatures, metric: Any, baseline_ready: bool
    ) -> DetectorResult:
        stats = _mapping(metric)
        valid_status = (
            isinstance(features.status, int)
            and not isinstance(features.status, bool)
            and 100 <= features.status <= 599
        )
        observed = (
            float(features.status >= 400)
            if valid_status
            else None
        )
        result = self._numeric_result(
            "http_error_rate",
            observed=observed,
            metric=stats,
            timestamp=features.ts,
            baseline_ready=baseline_ready,
            features=("status",),
        )
        # A non-error response cannot represent an increased error ratio.
        if valid_status and features.status < 400 and result.detected:
            return _result(
                "http_error_rate",
                detected=False,
                kind="statistical_anomaly",
                score=0.0,
                severity="info",
                observed=observed,
                expected=result.expected,
                threshold=result.threshold,
                explanation="No 4xx or 5xx response was observed.",
                features=("status",),
                baseline_ready=baseline_ready,
                timestamp=features.ts,
            )
        return result

    def _shape_result(
        self, features: TrafficFeatures, baseline: Mapping[str, Any], ready: bool
    ) -> DetectorResult:
        shapes = baseline.get("learned_shape_hashes", [])
        if not isinstance(shapes, (list, tuple, set)):
            shapes = []
        is_new = ready and features.shape_hash not in shapes
        return _result(
            "new_payload_shape",
            detected=is_new,
            kind="suspicious_signal",
            score=self.config.suspicious_signal_score if is_new else 0.0,
            severity="low" if is_new else "info",
            observed=features.shape_hash,
            expected=sorted(shape for shape in shapes if isinstance(shape, str)),
            threshold="shape not in learned allow-list",
            explanation=(
                "Payload shape is not in the endpoint's learned allow-list; investigate "
                "without treating this as proof of malicious activity."
                if is_new
                else "Payload shape is known or the baseline is not active."
            ),
            features=("shape_hash",),
            baseline_ready=ready,
            timestamp=features.ts,
        )

    def _endpoint_result(
        self,
        features: TrafficFeatures,
        baseline: Mapping[str, Any],
        all_baselines: Mapping[str, Any] | None,
        ready: bool,
    ) -> DetectorResult:
        all_baselines = all_baselines or {}
        known = features.endpoint_key in all_baselines or (
            _integer(baseline.get("observation_count")) > 0
        )
        unexpected = not known and bool(all_baselines)
        return _result(
            "unexpected_endpoint_method",
            detected=unexpected,
            kind="suspicious_signal",
            score=self.config.suspicious_signal_score if unexpected else 0.0,
            severity="low" if unexpected else "info",
            observed=features.endpoint_key,
            expected=sorted(all_baselines),
            threshold="endpoint/method key not in learned baselines",
            explanation=(
                "Endpoint/method has no learned baseline; this may be new API usage "
                "and is not proof of an attack."
                if unexpected
                else "Endpoint/method is known or there is not enough global history."
            ),
            features=("method", "path_template"),
            baseline_ready=ready and known,
            timestamp=features.ts,
        )

    def _rule_action_result(
        self, features: TrafficFeatures, baseline_ready: bool
    ) -> DetectorResult:
        suspicious = (
            features.rule_hit_count > 0 or features.action in SUSPICIOUS_ACTIONS
        )
        observed = {
            "rule_hit_count": features.rule_hit_count,
            "action": features.action,
        }
        return _result(
            "rule_hit_or_blocked_action",
            detected=suspicious,
            kind="suspicious_signal",
            score=min(
                1.0,
                self.config.suspicious_signal_score
                + max(0, features.rule_hit_count - 1) * 0.1,
            )
            if suspicious
            else 0.0,
            severity="medium" if suspicious else "info",
            observed=observed,
            expected="allow/log with no rule hits",
            threshold={"rule_hit_count": 0, "action": ["allow", "log"]},
            explanation=(
                "Gateway enforcement or rule hits were observed; this is a suspicious "
                "signal and does not by itself confirm an attack."
                if suspicious
                else "No enforcement action or rule hit was observed."
            ),
            features=("rule_hit_count", "action"),
            baseline_ready=baseline_ready,
            timestamp=features.ts,
        )

    def _sequence_result(
        self,
        features: TrafficFeatures,
        previous_endpoint: str | None,
        sequence_frequencies: Mapping[str, int],
        baseline_ready: bool,
    ) -> DetectorResult:
        transition = (
            f"{previous_endpoint} -> {features.endpoint_key}"
            if previous_endpoint
            else None
        )
        comparable = bool(
            baseline_ready
            and previous_endpoint
            and any(key.startswith(f"{previous_endpoint} -> ") for key in sequence_frequencies)
        )
        unexpected = comparable and transition not in sequence_frequencies
        return _result(
            "endpoint_sequence",
            detected=unexpected,
            kind="suspicious_signal",
            score=self.config.suspicious_signal_score if unexpected else 0.0,
            severity="low" if unexpected else "info",
            observed=transition,
            expected=[
                key for key in sorted(sequence_frequencies)
                if previous_endpoint and key.startswith(f"{previous_endpoint} -> ")
            ],
            threshold="transition not observed in learned sequence history",
            explanation=(
                "This endpoint transition is not present in the learned sequence history; "
                "investigate as a signal, not proof of an attack."
                if unexpected
                else "No comparable unseen endpoint transition was observed."
            ),
            features=("caller_id", "endpoint_key", "ts"),
            baseline_ready=comparable,
            timestamp=features.ts,
        )


def _result(
    detector: str,
    *,
    detected: bool,
    kind: str,
    score: float,
    severity: str,
    observed: Any,
    expected: Any,
    threshold: Any,
    explanation: str,
    features: tuple[str, ...],
    baseline_ready: bool,
    timestamp: str,
) -> DetectorResult:
    return DetectorResult(
        detector=detector,
        detected=detected,
        kind=kind,
        score=max(0.0, min(1.0, float(score))),
        severity=severity,
        observed=observed,
        expected=expected,
        threshold=threshold,
        explanation=explanation,
        contributing_features=features,
        baseline_ready=baseline_ready,
        timestamp=timestamp,
        confirmed_attack=False,
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _finite_or_none(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _normalized_score(
    z_score: float | None,
    ratio_trigger: bool,
    zero_variance_outlier: bool,
    threshold: float,
) -> float:
    if zero_variance_outlier:
        return 1.0
    if ratio_trigger:
        return 1.0
    if z_score is None:
        return 0.0
    return max(0.0, min(1.0, abs(z_score) / (threshold * 2)))


def _severity(score: float) -> str:
    if score >= 0.9:
        return "high"
    if score >= 0.65:
        return "medium"
    if score >= 0.4:
        return "low"
    return "info"
