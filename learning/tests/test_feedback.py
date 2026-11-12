from datetime import datetime, timedelta, timezone
import json

import pytest

from apishield_learning.alerts import AlertService
from apishield_learning.baselines import BaselineConfig, BaselineLearner
from apishield_learning.detectors.results import DetectorResult
from apishield_learning.events import IdentifierPseudonymizer, TrafficEvent
from apishield_learning.feedback import (
    AnalystFeedback,
    FeedbackAnalysisConfig,
    FeedbackService,
)
from apishield_learning.features import extract_features
from apishield_learning.storage import InMemoryLearningStorage

PSEUDONYMIZER = IdentifierPseudonymizer(b"a sufficiently long key for feedback tests")


def make_features(*, minute=0, caller="caller-a"):
    event = TrafficEvent(
        ts=f"2026-11-12T10:{minute:02d}:00Z",
        req_id="raw-request-id",
        caller=caller,
        ip="203.0.113.9",
        method="GET",
        path_template="/items/{id}",
        status=200,
        latency_ms=10,
        req_size=20,
        resp_size=100,
        shape_hash="shape-a",
        rule_hits=(),
        action="allow",
    )
    return extract_features(event, PSEUDONYMIZER)


def detected_result(detector="latency", *, threshold=None):
    return DetectorResult(
        detector=detector,
        detected=True,
        kind="statistical_anomaly",
        score=0.8,
        severity="high",
        observed=100,
        expected=10,
        threshold=threshold if threshold is not None else {"z_score": 3.0},
        explanation="Observed latency exceeded baseline.",
        contributing_features=("latency_ms",),
        baseline_ready=True,
        timestamp="2026-11-12T10:00:00Z",
    )


class Clock:
    def __init__(self):
        self.value = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        current = self.value
        self.value += timedelta(seconds=1)
        return current


def setup_services(*, analysis_config=None):
    storage = InMemoryLearningStorage()
    alerts = AlertService(storage=storage)
    feedback = FeedbackService(
        storage=storage,
        analysis_config=analysis_config,
        clock=Clock(),
    )
    return storage, alerts, feedback


def make_alert(alerts, *, caller="caller-a", minute=0, detector="latency"):
    return alerts.generate_alerts(
        [detected_result(detector)],
        make_features(minute=minute, caller=caller),
    )[0]


def test_valid_true_positive_feedback_updates_alert_without_changing_detection():
    storage, alerts, service = setup_services()
    alert = make_alert(alerts)
    original_score = alert.priority_score

    feedback = service.submit_feedback(
        alert.alert_id, "true_positive", analyst_id="analyst_42", comment="Reviewed."
    )
    updated = alerts.get_alert(alert.alert_id)

    assert feedback.label == "true_positive"
    assert feedback.analyst_id == "analyst_42"
    assert feedback.comment == "Reviewed."
    assert updated.feedback_status == "true_positive"
    assert updated.priority_score == original_score
    assert updated.observed_values == alert.observed_values
    assert len(storage.list_feedback()) == 1


def test_valid_false_positive_feedback_is_available_as_latest_decision():
    _, alerts, service = setup_services()
    alert = make_alert(alerts)

    submitted = service.submit_feedback(alert.alert_id, "false_positive")

    assert submitted.label == "false_positive"
    assert service.get_feedback(alert.alert_id) == submitted
    assert alerts.get_alert(alert.alert_id).feedback_status == "false_positive"


@pytest.mark.parametrize("label", ["unknown", "", None, True, 1])
def test_invalid_feedback_labels_are_rejected(label):
    _, alerts, service = setup_services()
    alert = make_alert(alerts)

    with pytest.raises(ValueError, match="label"):
        service.submit_feedback(alert.alert_id, label)


@pytest.mark.parametrize("alert_id", ["", "  ", "x" * 257, None])
def test_missing_or_invalid_alert_id_is_rejected(alert_id):
    _, _, service = setup_services()
    expected_error = TypeError if alert_id is None else ValueError

    with pytest.raises(expected_error, match="alert_id"):
        service.submit_feedback(alert_id, "true_positive")


def test_unknown_alert_cannot_receive_feedback():
    _, _, service = setup_services()

    with pytest.raises(KeyError, match="alert not found"):
        service.submit_feedback("missing-alert", "true_positive")


def test_duplicate_feedback_is_appended_with_audit_link():
    storage, alerts, service = setup_services()
    alert = make_alert(alerts)

    first = service.submit_feedback(alert.alert_id, "false_positive")
    duplicate = service.submit_feedback(alert.alert_id, "false_positive")

    assert first.feedback_id != duplicate.feedback_id
    assert duplicate.previous_feedback_id == first.feedback_id
    assert len(storage.list_feedback()) == 2
    assert service.get_feedback(alert.alert_id) == duplicate


def test_changed_feedback_preserves_both_decisions_and_latest_alert_status():
    storage, alerts, service = setup_services()
    alert = make_alert(alerts)

    false_positive = service.submit_feedback(alert.alert_id, "false_positive")
    true_positive = service.submit_feedback(alert.alert_id, "true_positive")
    history = service.get_feedback_history(alert.alert_id)

    assert [record.label for record in history] == [
        "false_positive",
        "true_positive",
    ]
    assert true_positive.previous_feedback_id == false_positive.feedback_id
    assert service.get_feedback(alert.alert_id) == true_positive
    assert alerts.get_alert(alert.alert_id).feedback_status == "true_positive"
    assert len(storage.list_feedback()) == 2


def test_feedback_history_has_deterministic_timestamp_ordering():
    _, alerts, service = setup_services()
    first = make_alert(alerts, caller="caller-a")
    second = make_alert(alerts, caller="caller-b")

    old = service.submit_feedback(first.alert_id, "false_positive")
    later = service.submit_feedback(second.alert_id, "true_positive")

    assert service.get_feedback_history(first.alert_id) == [old]
    assert service.get_feedback_history(second.alert_id) == [later]
    assert old.timestamp < later.timestamp


def test_feedback_history_survives_service_recreation_for_same_storage():
    storage, alerts, service = setup_services()
    alert = make_alert(alerts)
    submitted = service.submit_feedback(alert.alert_id, "false_positive")
    restored_service = FeedbackService(storage=storage, clock=Clock())

    assert restored_service.get_feedback_history(alert.alert_id) == [submitted]
    assert restored_service.get_feedback(alert.alert_id) == submitted


def test_summary_counts_latest_decisions_by_label_and_severity():
    _, alerts, service = setup_services()
    first = make_alert(alerts, caller="caller-a")
    second = make_alert(alerts, caller="caller-b")

    service.submit_feedback(first.alert_id, "false_positive")
    service.submit_feedback(first.alert_id, "true_positive")
    service.submit_feedback(second.alert_id, "false_positive")
    summary = service.get_feedback_summary()

    assert summary["submission_count"] == 3
    assert summary["latest_decision_count"] == 2
    assert summary["by_label"] == {"false_positive": 1, "true_positive": 1}
    assert summary["by_severity"]["medium"] == {
        "false_positive": 1,
        "true_positive": 1,
    }
    assert summary["ground_truth"] is False


def test_detector_metrics_and_threshold_recommendation_are_review_only():
    config = FeedbackAnalysisConfig(
        min_feedback_per_detector=2,
        high_false_positive_rate=0.5,
        suggested_threshold_increase=0.1,
    )
    _, alerts, service = setup_services(analysis_config=config)
    first = make_alert(alerts, caller="caller-a")
    second = make_alert(alerts, caller="caller-b")

    service.submit_feedback(first.alert_id, "false_positive")
    service.submit_feedback(second.alert_id, "false_positive")
    metrics = service.get_feedback_metrics()
    detector = metrics["detectors"]["latency"]
    recommendation = metrics["threshold_recommendations"][0]

    assert detector["false_positive"] == 2
    assert detector["true_positive"] == 0
    assert detector["false_positive_rate"] == 1
    assert recommendation["action"] == "review_increasing_threshold"
    assert recommendation["current_thresholds"] == [{"z_score": 3.0}]
    assert recommendation["suggested_thresholds"] == [{"z_score": pytest.approx(3.3)}]
    assert recommendation["requires_human_review"] is True
    assert recommendation["automatic_change_applied"] is False
    assert metrics["automatic_threshold_changes"] == 0
    assert metrics["baseline_modified"] is False
    assert metrics["gateway_rules_modified"] is False
    assert metrics["ground_truth"] is False


def test_feedback_does_not_change_trusted_baselines():
    learner = BaselineLearner(
        BaselineConfig(min_observations=1, warmup_period_seconds=0)
    )
    feature = make_features()
    learner.update(feature)
    before = learner.snapshot()
    storage = InMemoryLearningStorage()
    alerts = AlertService(storage=storage)
    alert = alerts.generate_alerts(
        [detected_result()], feature
    )[0]
    service = FeedbackService(storage=storage, clock=Clock())

    service.submit_feedback(alert.alert_id, "false_positive")

    assert learner.snapshot() == before


def test_feedback_does_not_change_gateway_rules_or_alert_detection_scores():
    _, alerts, service = setup_services()
    alert = make_alert(alerts)
    before = alert.to_dict()

    service.submit_feedback(alert.alert_id, "false_positive")
    after = alerts.get_alert(alert.alert_id).to_dict()

    assert after["feedback_status"] == "false_positive"
    for field in (
        "anomaly_score",
        "endpoint_risk_score",
        "repeat_factor",
        "priority_score",
        "detector_names",
        "observed_values",
        "expected_values",
        "thresholds",
    ):
        assert after[field] == before[field]
    assert service.get_feedback_metrics()["gateway_rules_modified"] is False


@pytest.mark.parametrize(
    ("analyst_id", "comment", "expected_error"),
    [
        ("analyst@example.com", None, ValueError),
        ("x" * 129, None, ValueError),
        ("analyst\nid", None, ValueError),
        (None, "", ValueError),
        (None, "x" * 1001, ValueError),
        (None, "bad\x00comment", ValueError),
        (42, None, TypeError),
        (None, 42, TypeError),
    ],
)
def test_analyst_and_comment_input_validation(
    analyst_id, comment, expected_error
):
    _, alerts, service = setup_services()
    alert = make_alert(alerts)

    with pytest.raises(expected_error):
        service.submit_feedback(
            alert.alert_id,
            "true_positive",
            analyst_id=analyst_id,
            comment=comment,
        )


def test_feedback_records_do_not_store_raw_caller_ip_or_request_id():
    storage, alerts, service = setup_services()
    alert = make_alert(alerts)
    service.submit_feedback(alert.alert_id, "true_positive", analyst_id="operator_1")

    serialized = json.dumps(storage.list_feedback())

    assert "caller-a" not in serialized
    assert "203.0.113.9" not in serialized
    assert "raw-request-id" not in serialized


def test_feedback_requires_alert_update_storage_and_preserves_audit():
    storage, alerts, service = setup_services()
    alert = make_alert(alerts)
    service.submit_feedback(alert.alert_id, "true_positive")

    assert len(storage.list_feedback()) == 1
    assert isinstance(service.get_feedback(alert.alert_id), AnalystFeedback)
