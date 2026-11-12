"""Deterministic replay evaluation through the M3 processing components."""

from __future__ import annotations

import argparse
import json
import math
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .alerts import AlertConfig, AlertService
from .baselines import ACTIVE, BaselineConfig, BaselineLearner
from .detectors.isolation_forest import (
    InMemoryModelStore,
    IsolationForestConfig,
    IsolationForestDetector,
)
from .detectors.results import DetectorResult
from .detectors.service import DetectionService
from .detectors.statistical import DetectorConfig
from .events import EVENT_FIELDS, IdentifierPseudonymizer, TrafficEvent
from .features import TrafficFeatures, extract_features
from .storage import InMemoryLearningStorage, LearningStorage

REPLAY_LABELS = frozenset({"normal", "abnormal"})
_DEMO_KEY = b"apishield-replay-demo-key-not-secret"
_TIME_SERIES = (
    "feature_extraction",
    "baseline_update",
    "statistical_detection",
    "isolation_forest_scoring",
    "alert_generation",
    "overall_processing",
)


@dataclass(frozen=True)
class ReplayRecord:
    """One event/feature input with independent fixture ground truth."""

    scenario: str
    expected_label: str
    event: TrafficEvent | Mapping[str, Any] | None = None
    features: TrafficFeatures | Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scenario, str) or not self.scenario.strip():
            raise ValueError("scenario must be a non-empty string")
        if self.expected_label not in REPLAY_LABELS:
            raise ValueError(f"expected_label must be one of {sorted(REPLAY_LABELS)}")
        if (self.event is None) == (self.features is None):
            raise ValueError("provide exactly one of event or features")


@dataclass(frozen=True)
class ReplayConfig:
    """Evaluation-only tuning; defaults keep the demo deterministic and quick."""

    baseline: BaselineConfig = field(
        default_factory=lambda: BaselineConfig(
            min_observations=5,
            warmup_period_seconds=180,
            ewma_alpha=0.25,
            min_update_samples=5,
        )
    )
    detectors: DetectorConfig = field(
        default_factory=lambda: DetectorConfig(min_samples=3)
    )
    isolation_forest: IsolationForestConfig | None = field(
        default_factory=lambda: IsolationForestConfig(
            min_samples=8,
            retrain_every=100,
            n_estimators=40,
            contamination=0.1,
            random_state=17,
            model_key="apishield-replay-demo",
        )
    )
    alerts: AlertConfig = field(default_factory=AlertConfig)


class ReplayEvaluator:
    """Run replay records through feature, baseline, detector, and alert code."""

    def __init__(
        self,
        *,
        config: ReplayConfig | None = None,
        storage: LearningStorage | None = None,
        pseudonymizer: IdentifierPseudonymizer | None = None,
        evaluation_timestamp: str | None = None,
    ) -> None:
        self.config = config or ReplayConfig()
        self.storage = storage or InMemoryLearningStorage()
        self.pseudonymizer = pseudonymizer or IdentifierPseudonymizer(_DEMO_KEY)
        self.baseline = BaselineLearner(
            self.config.baseline,
            storage=self.storage,
            upstream_id="replay-evaluation",
        )
        self.isolation_forest = (
            IsolationForestDetector(
                self.config.isolation_forest,
                model_store=InMemoryModelStore(),
            )
            if self.config.isolation_forest is not None
            else None
        )
        self.detectors = DetectionService(
            self.config.detectors,
            isolation_forest=self.isolation_forest,
        )
        self.alerts = AlertService(storage=self.storage, config=self.config.alerts)
        self.evaluation_timestamp = evaluation_timestamp or _utc_now()
        self._has_run = False

    def evaluate(self, records: Sequence[ReplayRecord]) -> dict[str, Any]:
        """Process records once and return a JSON-serializable evaluation report."""
        if self._has_run:
            raise RuntimeError("ReplayEvaluator instances can evaluate only once")
        if not records:
            raise ValueError("at least one replay record is required")
        self._has_run = True

        per_stage: dict[str, list[int]] = {name: [] for name in _TIME_SERIES}
        scenario_rows: dict[str, list[tuple[bool, bool]]] = {}
        detector_rows: dict[str, list[tuple[bool, bool]]] = {}
        expected_labels: list[bool] = []
        predictions: list[bool] = []
        normal_count = 0
        abnormal_count = 0
        cold_endpoint = _first_endpoint(records)
        cold_initial_state = (
            self.baseline.get_endpoint_baseline(cold_endpoint)["state"]
            if cold_endpoint
            else None
        )
        first_state: str | None = None
        active_timestamp: str | None = None
        normal_after_active_high_confidence = 0
        abnormal_after_active_detected = 0
        result_rows: list[dict[str, Any]] = []

        for index, record in enumerate(records):
            expected_anomaly = record.expected_label == "abnormal"
            normal_count += not expected_anomaly
            abnormal_count += expected_anomaly
            expected_labels.append(expected_anomaly)
            overall_started = time.perf_counter_ns()

            feature_started = time.perf_counter_ns()
            features = self._features_for(record)
            per_stage["feature_extraction"].append(
                time.perf_counter_ns() - feature_started
            )

            previous_endpoint = None
            endpoint_baseline = self.baseline.get_endpoint_baseline(
                features.endpoint_key
            )
            all_baselines = self.baseline.get_all_baselines()
            before_active = endpoint_baseline.get("state") == ACTIVE
            detector_timings: dict[str, int] = {}
            results = self.detectors.detect(
                features,
                endpoint_baseline,
                all_baselines=all_baselines,
                sequence_frequencies=self.baseline.get_sequence_frequencies(),
                previous_endpoint=previous_endpoint,
                timings_ns=detector_timings,
            )
            per_stage["statistical_detection"].append(
                detector_timings.get("statistical_detection", 0)
            )
            if self.isolation_forest is not None:
                per_stage["isolation_forest_scoring"].append(
                    detector_timings.get("isolation_forest_scoring", 0)
                )

            predicted_anomaly = any(result.detected for result in results)
            predictions.append(predicted_anomaly)
            scenario_rows.setdefault(record.scenario, []).append(
                (expected_anomaly, predicted_anomaly)
            )
            for result in results:
                detector_rows.setdefault(result.detector, []).append(
                    (expected_anomaly, result.detected)
                )

            alert_started = time.perf_counter_ns()
            generated_alerts = self.alerts.generate_alerts(results, features)
            per_stage["alert_generation"].append(
                time.perf_counter_ns() - alert_started
            )

            baseline_started = time.perf_counter_ns()
            baseline_update = self.baseline.update(
                features, trusted=not predicted_anomaly
            )
            per_stage["baseline_update"].append(
                time.perf_counter_ns() - baseline_started
            )
            if first_state is None and features.endpoint_key == cold_endpoint:
                first_state = baseline_update["state"]
            if (
                self.isolation_forest is not None
                and baseline_update["accepted_for_baseline"]
                and baseline_update["state"] == ACTIVE
            ):
                self.isolation_forest.observe(features, baseline_ready=True)

            if features.endpoint_key == cold_endpoint and active_timestamp is None:
                if baseline_update["state"] == ACTIVE:
                    active_timestamp = features.ts
            if before_active and record.expected_label == "normal":
                if any(alert.severity in {"high", "critical"} for alert in generated_alerts):
                    normal_after_active_high_confidence += 1
            if before_active and expected_anomaly and predicted_anomaly:
                abnormal_after_active_detected += 1

            overall_elapsed = time.perf_counter_ns() - overall_started
            per_stage["overall_processing"].append(overall_elapsed)
            result_rows.append(
                {
                    "scenario": record.scenario,
                    "expected_label": record.expected_label,
                    "predicted_anomaly": predicted_anomaly,
                    "detectors_triggered": sorted(
                        result.detector for result in results if result.detected
                    ),
                    "alert_created": bool(generated_alerts),
                    "alert_repeat_counts": [
                        alert.repeat_count for alert in generated_alerts
                    ],
                }
            )

        scenario_metrics = {
            scenario: _scope_metrics(rows)
            for scenario, rows in sorted(scenario_rows.items())
        }
        detector_metrics = {
            detector: _scope_metrics(rows)
            for detector, rows in sorted(detector_rows.items())
        }
        alerts = self.alerts.get_alerts()
        severity_counts = {
            severity: 0
            for severity in ("critical", "high", "medium", "low", "info")
        }
        for alert in alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

        active_baseline = (
            self.baseline.get_endpoint_baseline(cold_endpoint)
            if cold_endpoint
            else {}
        )
        report = {
            "evaluation_timestamp": self.evaluation_timestamp,
            "environment": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "isolation_forest_enabled": self.isolation_forest is not None,
                "live_redis_used": False,
            },
            "events_replayed": len(records),
            "normal_events": normal_count,
            "abnormal_events": abnormal_count,
            "ground_truth_source": "explicit synthetic replay fixture labels",
            "analyst_feedback_used_as_ground_truth": False,
            "confusion_matrix": _confusion_matrix(expected_labels, predictions),
            "metrics": calculate_metrics(expected_labels, predictions),
            "detection_rate_by_scenario": {
                scenario: values["recall"]
                for scenario, values in scenario_metrics.items()
                if values["positive_support"] > 0
            },
            "detection_rate_by_detector": {
                detector: values["recall"]
                for detector, values in detector_metrics.items()
                if values["positive_support"] > 0
            },
            "per_scenario": scenario_metrics,
            "per_detector": detector_metrics,
            "alert_count": len(alerts),
            "alert_severity_counts": severity_counts,
            "warmup": {
                "endpoint": cold_endpoint,
                "initial_state": cold_initial_state,
                "after_first_observation": first_state,
                "active_timestamp": active_timestamp,
                "became_active": active_timestamp is not None,
                "final_state": active_baseline.get("state"),
                "accepted_observations": active_baseline.get(
                    "accepted_observation_count", 0
                ),
                "normal_high_confidence_alerts_after_active": (
                    normal_after_active_high_confidence
                ),
                "abnormal_events_detected_after_active": (
                    abnormal_after_active_detected
                ),
            },
            "performance": {
                "processed_events": len(records),
                "units": "milliseconds",
                "stages": {
                    name: _latency_summary(values)
                    for name, values in per_stage.items()
                },
                "p95_target_ms": 20,
                "p95_target_achieved": (
                    _latency_summary(per_stage["overall_processing"])["p95"]
                    < 20
                ),
                "target_note": "Measured in this run only; synthetic single-process replay is not a production load test.",
            },
            "limitations": [
                "Synthetic replay results do not prove real-world attack detection accuracy.",
                "Ground-truth labels describe fixture intent, not analyst feedback or independently verified attacks.",
                "The replay processes one event at a time in a single process; it is not a throughput or concurrency benchmark.",
                "No live Redis integration was exercised.",
                "M2 endpoint risk and M4 API/feedback contracts are not integrated.",
                "Normalized path templates do not support sequential resource-ID enumeration detection.",
                "Isolation Forest model storage is in-memory for this replay.",
            ],
            "event_results": result_rows,
        }
        json.dumps(report, allow_nan=False)
        return report

    def _features_for(self, record: ReplayRecord) -> TrafficFeatures:
        if record.features is not None:
            if isinstance(record.features, TrafficFeatures):
                return record.features
            return TrafficFeatures(**dict(record.features))
        event = record.event
        if isinstance(event, TrafficEvent):
            parsed = event
        elif isinstance(event, Mapping):
            parsed = TrafficEvent.from_mapping(event)
        else:
            raise TypeError("event must be TrafficEvent or an M1 event mapping")
        return extract_features(parsed, self.pseudonymizer)


def build_demo_replay() -> list[ReplayRecord]:
    """Create reproducible normal, warm-up, and abnormal M1-shaped traffic."""
    records: list[ReplayRecord] = []
    start = datetime(2026, 11, 12, 9, 0, tzinfo=timezone.utc)
    normal_shapes = {
        "GET /items/{id}": "shape-get-v1",
        "POST /items": "shape-post-v1",
    }

    def append_event(
        scenario: str,
        expected_label: str,
        offset_seconds: int,
        *,
        method: str = "GET",
        path: str = "/items/{id}",
        caller: str = "demo-caller-a",
        status: int = 200,
        latency: float = 10.0,
        request_size: int = 24,
        response_size: int = 128,
        shape: str | None = None,
    ) -> None:
        event_data = {
            "ts": (start + timedelta(seconds=offset_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
            "req_id": f"replay-{len(records):06d}",
            "caller": caller,
            "ip": "192.0.2.10" if caller.endswith("a") else "192.0.2.11",
            "method": method,
            "path_template": path,
            "status": status,
            "latency_ms": latency,
            "req_size": request_size,
            "resp_size": response_size,
            "shape_hash": shape
            or normal_shapes.get(f"{method} {path}", "shape-standard-v1"),
            "rule_hits": [],
            "action": "allow",
        }
        ordered = {field_name: event_data[field_name] for field_name in EVENT_FIELDS}
        records.append(
            ReplayRecord(
                scenario=scenario,
                expected_label=expected_label,
                event=TrafficEvent.from_mapping(ordered),
            )
        )

    append_event("normal_warmup", "normal", 0)
    for index in range(1, 16):
        is_post = index % 2 == 0
        method, path = ("POST", "/items") if is_post else ("GET", "/items/{id}")
        caller = "demo-caller-a" if index % 3 else "demo-caller-b"
        statuses = (200, 201, 304, 200)
        append_event(
            "normal_warmup",
            "normal",
            index * 45,
            method=method,
            path=path,
            caller=caller,
            status=statuses[index % len(statuses)],
            latency=(8, 10, 12, 9)[index % 4],
            request_size=22 + index % 5,
            response_size=124 + index % 9,
        )

    for index in range(8):
        is_post = index % 2 == 1
        method, path = ("POST", "/items") if is_post else ("GET", "/items/{id}")
        append_event(
            "normal_after_warmup",
            "normal",
            720 + index * 30,
            method=method,
            path=path,
            caller="demo-caller-b" if index % 2 else "demo-caller-a",
            status=(200, 201, 304, 200)[index % 4],
            latency=(9, 11, 10, 8)[index % 4],
            request_size=23 + index % 4,
            response_size=126 + index % 7,
        )

    for index in range(5):
        append_event(
            "request_rate_spike",
            "abnormal",
            961 + index,
            caller="burst-caller",
        )

    append_event(
        "large_request",
        "abnormal",
        1020,
        caller="size-caller",
        request_size=500_000,
    )
    append_event(
        "large_response",
        "abnormal",
        1080,
        caller="response-caller",
        response_size=2_000_000,
    )
    append_event(
        "high_latency",
        "abnormal",
        1140,
        caller="latency-caller",
        latency=10_000,
    )
    for index, status in enumerate((429, 500, 503)):
        append_event(
            "abnormal_error_ratio",
            "abnormal",
            1200 + index * 10,
            caller="error-caller",
            status=status,
        )
    append_event(
        "new_payload_shape",
        "abnormal",
        1260,
        caller="shape-caller",
        shape="shape-unseen-v2",
    )
    append_event(
        "unexpected_endpoint_method",
        "abnormal",
        1320,
        method="DELETE",
        path="/admin/{id}",
        caller="new-route-caller",
        shape="shape-delete-admin",
    )
    for index in range(3):
        append_event(
            "repeated_anomaly",
            "abnormal",
            1380 + index * 10,
            caller="repeat-caller",
            latency=5000,
        )
    return records


def calculate_metrics(
    expected: Sequence[bool], predicted: Sequence[bool]
) -> dict[str, Any]:
    """Calculate confusion and binary classification metrics safely."""
    if len(expected) != len(predicted):
        raise ValueError("expected and predicted labels must have equal length")
    matrix = _confusion_matrix(expected, predicted)
    return _metrics_from_confusion(matrix)


def _scope_metrics(rows: Sequence[tuple[bool, bool]]) -> dict[str, Any]:
    expected = [item[0] for item in rows]
    predicted = [item[1] for item in rows]
    return {
        "events": len(rows),
        "positive_support": sum(expected),
        "negative_support": len(rows) - sum(expected),
        "detected_positive": sum(
            1 for truth, guess in rows if truth and guess
        ),
        **_metrics_from_confusion(_confusion_matrix(expected, predicted)),
    }


def _confusion_matrix(
    expected: Sequence[bool], predicted: Sequence[bool]
) -> dict[str, int]:
    if len(expected) != len(predicted):
        raise ValueError("expected and predicted labels must have equal length")
    return {
        "true_positives": sum(
            bool(truth) and bool(guess) for truth, guess in zip(expected, predicted)
        ),
        "false_positives": sum(
            not bool(truth) and bool(guess)
            for truth, guess in zip(expected, predicted)
        ),
        "true_negatives": sum(
            not bool(truth) and not bool(guess)
            for truth, guess in zip(expected, predicted)
        ),
        "false_negatives": sum(
            bool(truth) and not bool(guess)
            for truth, guess in zip(expected, predicted)
        ),
    }


def _metrics_from_confusion(matrix: Mapping[str, int]) -> dict[str, Any]:
    tp = matrix["true_positives"]
    fp = matrix["false_positives"]
    tn = matrix["true_negatives"]
    fn = matrix["false_negatives"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        **dict(matrix),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": false_positive_rate,
    }


def _latency_summary(values_ns: Sequence[int]) -> dict[str, Any]:
    if not values_ns:
        return {
            "count": 0,
            "average": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "maximum": 0.0,
        }
    values_ms = sorted(value / 1_000_000 for value in values_ns)
    p95_index = max(0, math.ceil(0.95 * len(values_ms)) - 1)
    return {
        "count": len(values_ms),
        "average": statistics.fmean(values_ms),
        "median": statistics.median(values_ms),
        "p95": values_ms[p95_index],
        "maximum": values_ms[-1],
    }


def _first_endpoint(records: Sequence[ReplayRecord]) -> str | None:
    first = records[0]
    if first.features is not None:
        value = first.features
        if isinstance(value, TrafficFeatures):
            return value.endpoint_key
        return str(value.get("endpoint_key", "")) or None
    event = first.event
    if isinstance(event, TrafficEvent):
        return f"{event.method.upper()} {event.path_template}"
    if isinstance(event, Mapping):
        return f"{str(event.get('method', '')).upper()} {event.get('path_template', '')}"
    return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the deterministic development replay and print or save JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="optional JSON report file path; otherwise print to stdout",
    )
    parser.add_argument(
        "--no-isolation-forest",
        action="store_true",
        help="disable Isolation Forest to compare statistical-only behavior",
    )
    args = parser.parse_args(argv)
    config = ReplayConfig(
        isolation_forest=(
            None
            if args.no_isolation_forest
            else ReplayConfig().isolation_forest
        )
    )
    report = ReplayEvaluator(config=config).evaluate(build_demo_replay())
    encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        sys.stdout.write(encoded)
    else:
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(f"Replay report written to {args.output}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
