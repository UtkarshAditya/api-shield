import json

import pytest

from apishield_learning.events import EVENT_FIELDS, TrafficEvent
from apishield_learning.replay import (
    ReplayConfig,
    ReplayEvaluator,
    ReplayRecord,
    build_demo_replay,
    calculate_metrics,
)


def test_metric_calculation_includes_confusion_precision_recall_f1_and_fpr():
    metrics = calculate_metrics(
        [True, True, False, False],
        [True, False, True, False],
    )

    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["true_negatives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1_score"] == 0.5
    assert metrics["false_positive_rate"] == 0.5


def test_metric_calculation_handles_zero_denominators():
    no_predictions = calculate_metrics([False, False], [False, False])
    no_negatives = calculate_metrics([True, True], [True, False])

    assert no_predictions["precision"] == 0
    assert no_predictions["recall"] == 0
    assert no_predictions["f1_score"] == 0
    assert no_predictions["false_positive_rate"] == 0
    assert no_negatives["false_positive_rate"] == 0


def test_metric_calculation_rejects_mismatched_labels():
    with pytest.raises(ValueError, match="equal length"):
        calculate_metrics([True], [True, False])


def test_replay_record_requires_explicit_scenario_label_and_one_input():
    with pytest.raises(ValueError, match="expected_label"):
        ReplayRecord(scenario="normal", expected_label="unknown", features={})
    with pytest.raises(ValueError, match="exactly one"):
        ReplayRecord(scenario="normal", expected_label="normal")


def test_demo_fixtures_use_the_exact_gateway_event_contract():
    records = build_demo_replay()

    assert records
    assert all(record.expected_label in {"normal", "abnormal"} for record in records)
    assert all(isinstance(record.event, TrafficEvent) for record in records)
    assert all(tuple(record.event.__dataclass_fields__) == EVENT_FIELDS for record in records)
    assert {record.scenario for record in records} >= {
        "normal_warmup",
        "normal_after_warmup",
        "request_rate_spike",
        "large_request",
        "large_response",
        "high_latency",
        "abnormal_error_ratio",
        "new_payload_shape",
        "unexpected_endpoint_method",
        "repeated_anomaly",
    }


def test_normal_and_abnormal_replay_runs_through_m3_and_generates_alerts():
    report = ReplayEvaluator().evaluate(build_demo_replay())

    assert report["events_replayed"] == 40
    assert report["normal_events"] == 24
    assert report["abnormal_events"] == 16
    assert report["ground_truth_source"] == "explicit synthetic replay fixture labels"
    assert report["analyst_feedback_used_as_ground_truth"] is False
    assert report["alert_count"] > 0
    assert any(row["alert_created"] for row in report["event_results"])
    assert report["per_scenario"]["normal_after_warmup"]["negative_support"] == 8
    assert report["per_scenario"]["large_request"]["recall"] == 1
    assert report["per_scenario"]["large_response"]["recall"] == 1
    assert report["per_scenario"]["high_latency"]["recall"] == 1
    assert report["per_scenario"]["abnormal_error_ratio"]["recall"] == 1
    assert report["per_scenario"]["new_payload_shape"]["recall"] == 1
    assert report["per_scenario"]["unexpected_endpoint_method"]["recall"] == 1
    assert report["per_scenario"]["repeated_anomaly"]["recall"] == 1
    assert report["detection_rate_by_scenario"]["request_rate_spike"] > 0
    assert "latency" in report["detection_rate_by_detector"]
    repeated = [
        row
        for row in report["event_results"]
        if row["scenario"] == "repeated_anomaly"
    ]
    assert repeated[-1]["alert_repeat_counts"] == [3]


def test_ground_truth_is_independent_from_detector_predictions():
    report = ReplayEvaluator().evaluate(build_demo_replay())
    positive = [
        row
        for row in report["event_results"]
        if row["expected_label"] == "abnormal"
    ]

    assert positive
    assert any(row["predicted_anomaly"] for row in positive)
    assert any(not row["predicted_anomaly"] for row in positive)
    assert report["analyst_feedback_used_as_ground_truth"] is False


def test_per_detector_and_per_scenario_metrics_are_reported():
    report = ReplayEvaluator().evaluate(build_demo_replay())

    assert "request_size" in report["per_detector"]
    assert "isolation_forest" in report["per_detector"]
    assert report["per_detector"]["request_size"]["positive_support"] == 16
    assert "normal_warmup" in report["per_scenario"]
    assert "false_positive_rate" in report["per_scenario"]["normal_warmup"]


def test_cold_start_warmup_activation_and_normal_post_warmup_behavior():
    report = ReplayEvaluator().evaluate(build_demo_replay())
    warmup = report["warmup"]

    assert warmup["initial_state"] == "insufficient_data"
    assert warmup["after_first_observation"] == "warmup"
    assert warmup["became_active"]
    assert warmup["active_timestamp"] is not None
    assert warmup["final_state"] == "active"
    assert warmup["accepted_observations"] >= 5
    assert warmup["normal_high_confidence_alerts_after_active"] == 0
    assert warmup["abnormal_events_detected_after_active"] > 0


def test_performance_metrics_include_each_requested_component():
    report = ReplayEvaluator().evaluate(build_demo_replay())
    performance = report["performance"]

    assert performance["processed_events"] == report["events_replayed"]
    assert performance["units"] == "milliseconds"
    assert performance["p95_target_ms"] == 20
    for stage in (
        "feature_extraction",
        "baseline_update",
        "statistical_detection",
        "isolation_forest_scoring",
        "alert_generation",
        "overall_processing",
    ):
        measurements = performance["stages"][stage]
        assert measurements["count"] == report["events_replayed"]
        assert measurements["average"] >= 0
        assert measurements["median"] >= 0
        assert measurements["p95"] >= 0
        assert measurements["maximum"] >= measurements["p95"]
    assert isinstance(performance["p95_target_achieved"], bool)
    assert "single-process replay" in performance["target_note"]


def test_report_is_json_serializable_and_contains_limitations_without_private_data():
    report = ReplayEvaluator(
        evaluation_timestamp="2026-11-12T12:00:00Z"
    ).evaluate(build_demo_replay())
    encoded = json.dumps(report, allow_nan=False)

    assert report["evaluation_timestamp"] == "2026-11-12T12:00:00Z"
    assert report["environment"]["live_redis_used"] is False
    assert "real-world attack detection accuracy" in encoded
    assert "resource-ID enumeration detection" in encoded
    assert "demo-caller-a" not in encoded
    assert "192.0.2.10" not in encoded
    assert "replay-000000" not in encoded


def test_replay_is_reproducible_in_predictions_and_metrics():
    config = ReplayConfig(isolation_forest=None)
    first = ReplayEvaluator(config=config).evaluate(build_demo_replay())
    second = ReplayEvaluator(config=config).evaluate(build_demo_replay())

    assert first["confusion_matrix"] == second["confusion_matrix"]
    assert first["metrics"] == second["metrics"]
    assert first["per_scenario"] == second["per_scenario"]
    assert first["per_detector"] == second["per_detector"]
    assert first["detection_rate_by_detector"] == second["detection_rate_by_detector"]
    assert first["alert_severity_counts"] == second["alert_severity_counts"]
    assert [
        (
            row["expected_label"],
            row["predicted_anomaly"],
            row["detectors_triggered"],
            row["alert_repeat_counts"],
        )
        for row in first["event_results"]
    ] == [
        (
            row["expected_label"],
            row["predicted_anomaly"],
            row["detectors_triggered"],
            row["alert_repeat_counts"],
        )
        for row in second["event_results"]
    ]


def test_replay_without_isolation_forest_reports_zero_scoring_samples():
    report = ReplayEvaluator(
        config=ReplayConfig(isolation_forest=None)
    ).evaluate(build_demo_replay())

    assert report["environment"]["isolation_forest_enabled"] is False
    assert "isolation_forest" not in report["per_detector"]
    assert report["performance"]["stages"]["isolation_forest_scoring"]["count"] == 0


def test_evaluator_instance_cannot_accidentally_replay_twice():
    evaluator = ReplayEvaluator(config=ReplayConfig(isolation_forest=None))
    evaluator.evaluate(build_demo_replay()[:1])

    with pytest.raises(RuntimeError, match="only once"):
        evaluator.evaluate(build_demo_replay()[:1])
