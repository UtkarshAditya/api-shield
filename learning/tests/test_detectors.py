import json
from dataclasses import replace

import pytest

from apishield_learning.baselines import ACTIVE, BaselineConfig, BaselineLearner
from apishield_learning.detectors.isolation_forest import (
    InMemoryModelStore,
    IsolationForestConfig,
    IsolationForestDetector,
)
from apishield_learning.detectors.results import DetectorResult
from apishield_learning.detectors.service import DetectionService
from apishield_learning.detectors.statistical import (
    DetectorConfig,
    StatisticalDetector,
)
from apishield_learning.events import IdentifierPseudonymizer, TrafficEvent
from apishield_learning.features import TrafficFeatures, extract_features

PSEUDONYMIZER = IdentifierPseudonymizer(b"a sufficiently long key for detector tests")


def make_features(
    *,
    minute=0,
    second=0,
    caller="caller-a",
    endpoint="/items/{id}",
    method="GET",
    status=200,
    latency=10.0,
    req_size=20,
    resp_size=100,
    shape="shape-a",
    action="allow",
    rule_hits=(),
):
    event = TrafficEvent(
        ts=f"2026-11-12T10:{minute:02d}:{second:02d}Z",
        req_id=f"request-{minute}-{second}",
        caller=PSEUDONYMIZER.pseudonymize("caller", caller),
        ip=PSEUDONYMIZER.pseudonymize("ip", "192.0.2.1"),
        method=method,
        path_template=endpoint,
        status=status,
        latency_ms=latency,
        req_size=req_size,
        resp_size=resp_size,
        shape_hash=shape,
        rule_hits=tuple(rule_hits),
        action=action,
    )
    return extract_features(event, PSEUDONYMIZER)


def active_baseline(
    *, metrics_samples=6, sizes=None, latencies=None, statuses=None
):
    sizes = sizes or [20] * metrics_samples
    latencies = latencies or [10] * metrics_samples
    statuses = statuses or [200] * metrics_samples
    engine = BaselineLearner(
        BaselineConfig(
            min_observations=2,
            warmup_period_seconds=0,
            min_update_samples=2,
            ewma_alpha=0.5,
        )
    )
    for index in range(metrics_samples + 1):
        size_index = min(index, len(sizes) - 1)
        latency_index = min(index, len(latencies) - 1)
        status_index = min(index, len(statuses) - 1)
        features = make_features(
            minute=index,
            req_size=sizes[size_index],
            latency=latencies[latency_index],
            status=statuses[status_index],
        )
        engine.update(features, trusted=index >= 2)
    return engine


def results_by_name(results):
    return {result.detector: result for result in results}


def test_normal_traffic_has_no_high_confidence_statistical_anomaly():
    engine = active_baseline(
        sizes=[20, 21, 19, 20, 22, 18],
        latencies=[10, 11, 9, 10, 12, 8],
    )
    features = make_features(minute=8, req_size=20, latency=10)
    results = StatisticalDetector(
        DetectorConfig(min_samples=3)
    ).detect(features, engine.get_endpoint_baseline(features.endpoint_key))

    assert not [
        result
        for result in results
        if result.detected and result.severity in {"high", "critical"}
    ]
    assert all(result.confirmed_attack is False for result in results)


def test_request_rate_spike_uses_ewma_ratio_and_rolling_history():
    engine = active_baseline()
    features = make_features(minute=8)
    baseline = engine.get_endpoint_baseline(features.endpoint_key)
    baseline["current_rate_per_minute"] = 20
    result = results_by_name(
        StatisticalDetector(DetectorConfig(min_samples=3)).detect(features, baseline)
    )["request_rate_spike"]

    assert result.detected
    assert result.observed == 20
    assert result.expected["ewma"] == 1
    assert result.score == 1


@pytest.mark.parametrize(
    ("field", "detector", "value"),
    [
        ("req_size", "request_size", 100_000),
        ("resp_size", "response_size", 1_000_000),
        ("latency_ms", "latency", 1000),
    ],
)
def test_size_and_latency_outliers_are_detected(field, detector, value):
    engine = active_baseline()
    features = replace(make_features(minute=8), **{field: value})
    baseline = engine.get_endpoint_baseline(features.endpoint_key)
    result = results_by_name(
        StatisticalDetector(DetectorConfig(min_samples=3)).detect(features, baseline)
    )[detector]

    assert result.detected
    assert result.kind == "statistical_anomaly"
    assert result.confirmed_attack is False
    assert 0 <= result.score <= 1


def test_error_event_is_anomaly_against_zero_error_baseline():
    engine = active_baseline(statuses=[200] * 6)
    features = make_features(minute=8, status=500)
    result = results_by_name(
        StatisticalDetector(DetectorConfig(min_samples=3)).detect(
            features, engine.get_endpoint_baseline(features.endpoint_key)
        )
    )["http_error_rate"]

    assert result.detected
    assert result.observed == 1
    assert result.expected["mean"] == 0


def test_new_shape_is_an_investigation_signal_not_attack_confirmation():
    engine = active_baseline()
    features = make_features(minute=8, shape="unseen-shape")
    result = results_by_name(
        StatisticalDetector(DetectorConfig(min_samples=3)).detect(
            features, engine.get_endpoint_baseline(features.endpoint_key)
        )
    )["new_payload_shape"]

    assert result.detected
    assert result.kind == "suspicious_signal"
    assert result.confirmed_attack is False
    assert result.severity == "low"
    assert "proof of malicious activity" in result.explanation


def test_new_endpoint_and_method_is_a_suspicious_signal():
    features = make_features(minute=8, endpoint="/admin/{id}", method="DELETE")
    result = results_by_name(
        StatisticalDetector().detect(
            features,
            {"state": ACTIVE, "observation_count": 0},
            all_baselines={"GET /items/{id}": {}},
        )
    )["unexpected_endpoint_method"]

    assert result.detected
    assert result.kind == "suspicious_signal"
    assert result.observed == "DELETE /admin/{id}"


def test_rule_hits_and_enforcement_actions_are_signals():
    features = make_features(minute=8, action="block", rule_hits=("rule-1",))
    result = results_by_name(
        StatisticalDetector().detect(features, {"state": ACTIVE})
    )["rule_hit_or_blocked_action"]

    assert result.detected
    assert result.kind == "suspicious_signal"
    assert result.observed == {"rule_hit_count": 1, "action": "block"}


def test_unseen_endpoint_sequence_is_only_reported_with_comparable_history():
    features = make_features(minute=8, endpoint="/orders/{id}")
    detector = StatisticalDetector()

    no_history = results_by_name(
        detector.detect(
            features,
            {"state": ACTIVE},
            previous_endpoint="GET /items/{id}",
            sequence_frequencies={},
        )
    )["endpoint_sequence"]
    new_transition = results_by_name(
        detector.detect(
            features,
            {"state": ACTIVE},
            previous_endpoint="GET /items/{id}",
            sequence_frequencies={"GET /items/{id} -> GET /users": 3},
        )
    )["endpoint_sequence"]

    assert not no_history.detected
    assert new_transition.detected
    assert new_transition.kind == "suspicious_signal"


def test_warmup_and_insufficient_history_gate_numeric_detectors():
    features = make_features()
    baseline = {
        "state": "warmup",
        "metrics": {
            "latency_ms": {
                "count": 100,
                "mean": 1,
                "standard_deviation": 0,
                "ewma": 1,
            }
        },
    }

    result = results_by_name(StatisticalDetector().detect(features, baseline))[
        "latency"
    ]

    assert not result.detected
    assert not result.baseline_ready


def test_zero_variance_and_invalid_metric_values_are_safe():
    features = make_features(latency=100)
    detector = StatisticalDetector(DetectorConfig(min_samples=2))
    zero_variance = {
        "state": ACTIVE,
        "metrics": {
            "latency_ms": {
                "count": 5,
                "mean": 10,
                "standard_deviation": 0,
                "ewma": 10,
            }
        },
    }
    invalid = {
        "state": ACTIVE,
        "metrics": {
            "latency_ms": {
                "count": "many",
                "mean": float("nan"),
                "standard_deviation": float("inf"),
                "ewma": None,
            }
        },
    }

    detected = results_by_name(detector.detect(features, zero_variance))["latency"]
    skipped = results_by_name(detector.detect(features, invalid))["latency"]

    assert detected.detected
    assert detected.score == 1
    assert not skipped.detected


def test_detector_result_has_common_json_serializable_shape():
    features = make_features()
    results = StatisticalDetector().detect(features, {"state": "warmup"})
    encoded = json.dumps([result.to_dict() for result in results], allow_nan=False)

    assert results
    assert all(isinstance(result, DetectorResult) for result in results)
    assert '"confirmed_attack": false' in encoded
    assert all(0 <= result.score <= 1 for result in results)


def training_samples(count=30):
    samples = []
    for index in range(count):
        samples.append(
            make_features(
                minute=index,
                second=(index * 7) % 60,
                latency=15 + (index % 4),
                req_size=30 + (index % 5),
                resp_size=150 + (index % 7),
                status=200 if index % 8 else 201,
                shape="shape-a",
            )
        )
    return samples


def test_isolation_forest_handles_insufficient_training_data():
    detector = IsolationForestDetector(
        IsolationForestConfig(min_samples=10, n_estimators=20)
    )

    assert not detector.fit(training_samples(9))
    assert not detector.trained
    assert detector.score(training_samples(1)[0]) is None


def test_isolation_forest_trains_scores_and_rejects_suspicious_training_data():
    detector = IsolationForestDetector(
        IsolationForestConfig(
            min_samples=10,
            n_estimators=30,
            random_state=11,
            contamination=0.1,
        )
    )
    samples = training_samples()
    samples[-1] = replace(samples[-1], action="block")
    assert detector.fit(samples)

    score = detector.score(make_features(minute=35, latency=5000, req_size=500_000))
    result = detector.detect(
        make_features(minute=35, latency=5000, req_size=500_000),
        baseline_ready=True,
    )

    assert detector.trained
    assert detector.sample_count == 29
    assert score is not None and 0 <= score <= 1
    assert result.detected
    assert result.confirmed_attack is False


def test_isolation_forest_is_reproducible_with_fixed_random_state():
    samples = training_samples()
    config = IsolationForestConfig(
        min_samples=10,
        n_estimators=40,
        random_state=7,
        contamination=0.1,
    )
    first = IsolationForestDetector(config)
    second = IsolationForestDetector(config)
    assert first.fit(samples)
    assert second.fit(samples)

    candidate = make_features(minute=35, latency=300, req_size=100_000)

    assert first.score(candidate) == second.score(candidate)


def test_isolation_forest_tied_normal_scores_are_not_all_flagged():
    detector = IsolationForestDetector(
        IsolationForestConfig(min_samples=10, n_estimators=20, contamination=0.1)
    )
    sample = make_features(latency=15, req_size=30, resp_size=150)
    assert detector.fit([sample] * 20)

    assert detector.score(sample) == 0.5
    assert not detector.detect(sample, baseline_ready=True).detected


def test_isolation_forest_retrains_on_threshold_and_persists_via_model_store():
    store = InMemoryModelStore()
    config = IsolationForestConfig(
        min_samples=10,
        retrain_every=5,
        n_estimators=20,
        random_state=3,
    )
    detector = IsolationForestDetector(config, model_store=store)
    samples = training_samples(10)
    assert detector.fit(samples)
    before = detector.score(samples[0])

    fresh = IsolationForestDetector(config, model_store=store)
    assert fresh.load()
    assert fresh.score(samples[0]) == before

    retrained = sum(
        detector.observe(sample, baseline_ready=True)
        for sample in samples[:5]
    )
    assert retrained == 1


def test_isolation_forest_skips_invalid_nonfinite_and_enforced_samples():
    detector = IsolationForestDetector(
        IsolationForestConfig(min_samples=5, n_estimators=10)
    )
    samples = training_samples(10)
    samples[0] = replace(samples[0], latency_ms=float("inf"))
    samples[1] = replace(samples[1], rule_hit_count=1, action="log")
    samples[2] = replace(samples[2], action="challenge")

    assert detector.fit(samples)
    assert detector.sample_count == 8
    invalid = replace(samples[3], req_size="invalid")
    assert detector.score(invalid) is None


@pytest.mark.parametrize(
    ("action", "expected_eligible"),
    [
        ("allow", True),
        ("log", True),
        ("throttle", False),
        ("challenge", False),
        ("block", False),
    ],
)
def test_isolation_forest_training_eligibility_by_action(action, expected_eligible):
    detector = IsolationForestDetector(
        IsolationForestConfig(min_samples=5, n_estimators=10)
    )
    sample = replace(
        training_samples(1)[0],
        action=action,
        rule_hit_count=1,
    )

    trained = detector.fit([sample] * 5)

    assert trained is expected_eligible
    assert detector.sample_count == (5 if expected_eligible else 0)

    observer = IsolationForestDetector(
        IsolationForestConfig(min_samples=5, n_estimators=10)
    )
    observer.observe(sample, baseline_ready=True)
    assert observer.sample_count == (1 if expected_eligible else 0)


def test_combined_detection_service_returns_all_detectors_without_io():
    engine = active_baseline()
    features = make_features(minute=8, shape="new-shape", action="log")
    model = IsolationForestDetector(
        IsolationForestConfig(min_samples=10, n_estimators=10)
    )
    model.fit(training_samples())
    service = DetectionService(
        DetectorConfig(min_samples=3),
        isolation_forest=model,
    )
    results = service.detect(
        features,
        engine.get_endpoint_baseline(features.endpoint_key),
        caller_baseline=engine.get_baseline(features.endpoint_key, features.caller_id),
        all_baselines=engine.get_all_baselines(),
        sequence_frequencies=engine.get_sequence_frequencies(),
        previous_endpoint="GET /orders/{id}",
    )

    assert len(results) == 10
    assert {result.detector for result in results} >= {
        "request_rate_spike",
        "request_size",
        "response_size",
        "latency",
        "http_error_rate",
        "new_payload_shape",
        "unexpected_endpoint_method",
        "rule_hit_or_blocked_action",
        "endpoint_sequence",
        "isolation_forest",
    }
    assert all(result.confirmed_attack is False for result in results)


def test_iforest_does_not_train_before_baseline_is_ready():
    detector = IsolationForestDetector(
        IsolationForestConfig(min_samples=5, n_estimators=10)
    )

    assert not detector.observe(make_features(), baseline_ready=False)
    assert detector.sample_count == 0
