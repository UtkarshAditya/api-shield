import json

import pytest

from apishield_learning.baselines import (
    ACTIVE,
    INSUFFICIENT_DATA,
    WARMUP,
    BaselineConfig,
    BaselineLearner,
    RollingMetric,
    calculate_z_score,
)
from apishield_learning.events import IdentifierPseudonymizer, TrafficEvent
from apishield_learning.features import extract_features
from apishield_learning.storage import InMemoryLearningStorage

PSEUDONYMIZER = IdentifierPseudonymizer(b"a sufficiently long key for baseline tests")


def make_features(
    *,
    second=0,
    caller="caller-one",
    endpoint="/items/{id}",
    method="GET",
    shape="shape-a",
    status=200,
    latency=10.0,
    req_size=20,
    resp_size=100,
    action="allow",
    rule_hits=(),
):
    event = TrafficEvent(
        ts=f"2026-11-12T10:{second // 60:02d}:{second % 60:02d}Z",
        req_id=f"request-{caller}-{second}",
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


def learner(**kwargs):
    return BaselineLearner(
        BaselineConfig(
            min_observations=kwargs.pop("min_observations", 3),
            warmup_period_seconds=kwargs.pop("warmup_period_seconds", 120),
            ewma_alpha=kwargs.pop("ewma_alpha", 0.5),
            rolling_window_size=kwargs.pop("rolling_window_size", 10),
            **kwargs,
        )
    )


def test_ewma_uses_configured_alpha():
    metric = RollingMetric(alpha=0.5, window_size=10)
    metric.observe(10)
    metric.observe(20)
    metric.observe(30)

    assert metric.ewma == pytest.approx(22.5)


def test_baseline_config_reads_warmup_and_ewma_settings():
    config = BaselineConfig.from_env(
        {
            "APISHIELD_LEARNING_MIN_OBSERVATIONS": "8",
            "APISHIELD_LEARNING_WARMUP_SECONDS": "120",
            "APISHIELD_LEARNING_EWMA_ALPHA": "0.4",
            "APISHIELD_LEARNING_ROLLING_WINDOW_SIZE": "24",
            "APISHIELD_LEARNING_MAX_SHAPES_PER_ENDPOINT": "12",
        }
    )

    assert config.min_observations == 8
    assert config.warmup_period_seconds == 120
    assert config.ewma_alpha == 0.4
    assert config.rolling_window_size == 24
    assert config.max_shapes_per_endpoint == 12


def test_rolling_mean_population_standard_deviation_min_max_and_count():
    metric = RollingMetric(alpha=0.25, window_size=3)
    for value in (10, 20, 30, 40):
        metric.observe(value)

    assert metric.count == 3
    assert metric.mean == pytest.approx(30)
    assert metric.variance == pytest.approx(200 / 3)
    assert metric.standard_deviation == pytest.approx((200 / 3) ** 0.5)
    assert metric.minimum == 20
    assert metric.maximum == 40


def test_z_score_handles_normal_values_insufficient_samples_and_zero_variance():
    assert calculate_z_score(12, 10, 2, 4) == pytest.approx(1)
    assert calculate_z_score(12, 10, 2, 1) is None
    assert calculate_z_score(10, 10, 0, 3) == 0
    assert calculate_z_score(12, 10, 0, 3) is None
    assert calculate_z_score(float("nan"), 10, 2, 3) is None


def test_warmup_activates_after_observation_and_time_requirements():
    engine = learner()
    endpoint = "GET /items/{id}"

    first = engine.update(make_features(second=0))
    second = engine.update(make_features(second=60, latency=12))
    third = engine.update(make_features(second=120, latency=14))

    assert first["state"] == WARMUP
    assert first["warmup_progress"] == pytest.approx(0)
    assert second["state"] == WARMUP
    assert second["warmup_progress"] == pytest.approx(0.5)
    assert third["state"] == ACTIVE
    baseline = engine.get_endpoint_baseline(endpoint)
    assert baseline["observation_count"] == 3
    assert baseline["accepted_observation_count"] == 3
    assert baseline["last_updated"] == "2026-11-12T10:02:00Z"


def test_new_and_sparse_endpoints_do_not_claim_active_baselines():
    engine = learner(min_observations=3, warmup_period_seconds=60)

    missing = engine.get_endpoint_baseline("GET /never-seen")
    engine.update(make_features(second=0))
    sparse = engine.update(make_features(second=60))

    assert missing["state"] == INSUFFICIENT_DATA
    assert sparse["state"] == INSUFFICIENT_DATA
    assert sparse["accepted_observation_count"] == 2
    assert engine.get_warmup_status()["insufficient_data"] == 1


def test_shape_allowlist_learns_only_during_warmup_and_reports_novel_shape():
    engine = learner(warmup_period_seconds=60)
    endpoint = "GET /items/{id}"
    engine.update(make_features(second=0, shape="shape-a"))
    engine.update(make_features(second=60, shape="shape-a"))
    engine.update(make_features(second=120, shape="shape-a"))

    novel = engine.update(
        make_features(second=180, shape="shape-new", latency=1000)
    )

    assert engine.get_shape_allowlist(endpoint) == ["shape-a"]
    assert novel["shape_is_new"]
    assert not novel["accepted_for_baseline"]
    assert engine.get_endpoint_baseline(endpoint)["metrics"]["latency_ms"]["mean"] == 10


def test_suspicious_warmup_observations_do_not_contaminate_statistics_or_shapes():
    engine = learner(warmup_period_seconds=300)

    result = engine.update(
        make_features(second=0, shape="suspicious-shape", action="block", latency=9999)
    )
    baseline = engine.get_endpoint_baseline("GET /items/{id}")

    assert not result["accepted_for_baseline"]
    assert baseline["observation_count"] == 1
    assert baseline["accepted_observation_count"] == 0
    assert baseline["learned_shape_hashes"] == []
    assert baseline["metrics"] == {}


def test_active_baseline_updates_only_with_explicitly_trusted_known_shape():
    engine = learner(warmup_period_seconds=60)
    for second in (0, 60, 120):
        engine.update(make_features(second=second, latency=10))

    untrusted = engine.update(make_features(second=180, latency=500))
    trusted = engine.update(
        make_features(second=240, latency=10), trusted=True
    )
    baseline = engine.get_endpoint_baseline("GET /items/{id}")

    assert not untrusted["accepted_for_baseline"]
    assert trusted["accepted_for_baseline"]
    assert baseline["metrics"]["latency_ms"]["count"] == 4
    assert baseline["metrics"]["latency_ms"]["maximum"] == 10


def test_extreme_numeric_observation_does_not_contaminate_warmup():
    engine = learner(
        min_observations=10,
        warmup_period_seconds=600,
        min_update_samples=5,
        max_update_z_score=4,
    )
    for second in (0, 10, 20, 30, 40):
        engine.update(make_features(second=second, latency=10, req_size=20))

    result = engine.update(make_features(second=50, latency=100_000, req_size=20))
    baseline = engine.get_endpoint_baseline("GET /items/{id}")

    assert result["rejected_as_outlier"]
    assert not result["accepted_for_baseline"]
    assert baseline["metrics"]["latency_ms"]["mean"] == 10
    assert baseline["accepted_observation_count"] == 5


def test_endpoint_and_pseudonymous_caller_baselines_are_separate():
    engine = learner(warmup_period_seconds=300)
    first = make_features(second=0, caller="caller-one", latency=10)
    second = make_features(second=60, caller="caller-two", latency=100)
    engine.update(first)
    engine.update(second)
    endpoint = first.endpoint_key

    endpoint_baseline = engine.get_baseline(endpoint)
    caller_one = engine.get_baseline(endpoint, first.caller_id)
    caller_two = engine.get_baseline(endpoint, second.caller_id)

    assert endpoint_baseline["observation_count"] == 2
    assert endpoint_baseline["metrics"]["latency_ms"]["mean"] == 55
    assert caller_one["metrics"]["latency_ms"]["mean"] == 10
    assert caller_two["metrics"]["latency_ms"]["mean"] == 100
    assert "caller-one" not in json.dumps(engine.snapshot())
    assert "caller-two" not in json.dumps(engine.snapshot())


def test_status_error_sizes_latency_and_shapes_are_learned():
    engine = learner(warmup_period_seconds=300)
    engine.update(make_features(second=0, status=200, shape="shape-a"))
    engine.update(
        make_features(second=30, status=404, shape="shape-b", req_size=40, resp_size=200)
    )

    baseline = engine.get_endpoint_baseline("GET /items/{id}")

    assert baseline["status_counts"] == {"200": 1, "404": 1, "error": 1}
    assert baseline["metrics"]["error"]["mean"] == 0.5
    assert baseline["metrics"]["request_size"]["mean"] == 30
    assert baseline["metrics"]["response_size"]["mean"] == 150
    assert baseline["learned_shape_hashes"] == ["shape-a", "shape-b"]


def test_endpoint_sequences_use_available_pseudonymous_caller_order():
    engine = learner(warmup_period_seconds=600)
    engine.update(make_features(second=0, endpoint="/items/{id}"))
    engine.update(make_features(second=30, endpoint="/orders/{id}"))
    engine.update(make_features(second=60, endpoint="/items/{id}"))

    assert engine.get_sequence_frequencies() == {
        "GET /items/{id} -> GET /orders/{id}": 1,
        "GET /orders/{id} -> GET /items/{id}": 1,
    }


def test_out_of_order_events_do_not_create_sequence_transitions():
    engine = learner(warmup_period_seconds=600)
    engine.update(make_features(second=60, endpoint="/items/{id}"))
    engine.update(make_features(second=30, endpoint="/orders/{id}"))

    assert engine.get_sequence_frequencies() == {}


def test_endpoint_request_rate_counts_and_zero_windows():
    engine = learner(warmup_period_seconds=600)
    engine.update(make_features(second=0))
    engine.update(make_features(second=10))
    engine.update(make_features(second=180))

    baseline = engine.get_endpoint_baseline("GET /items/{id}")

    assert baseline["current_rate_per_minute"] == 1
    rate = baseline["metrics"]["request_rate"]
    assert rate["values"] == [2.0, 0.0, 0.0]
    assert rate["mean"] == pytest.approx(2 / 3)
    assert rate["ewma"] == pytest.approx(0.5)


def test_snapshot_is_json_serializable_and_restores_through_storage():
    storage = InMemoryLearningStorage()
    config = BaselineConfig(
        min_observations=3,
        warmup_period_seconds=120,
        ewma_alpha=0.25,
        rolling_window_size=4,
    )
    engine = BaselineLearner(config, storage=storage, upstream_id="shop")
    for second, latency in ((0, 10), (60, 20), (120, 30)):
        engine.update(make_features(second=second, latency=latency))
    expected = engine.get_all_baselines()
    serialized = json.dumps(engine.snapshot(), allow_nan=False)

    restored = BaselineLearner(config, storage=storage, upstream_id="shop")

    assert json.loads(serialized)["version"] == 1
    assert restored.get_all_baselines() == expected


def test_storage_snapshots_are_detached_and_restore_can_be_explicit():
    storage = InMemoryLearningStorage()
    engine = learner(warmup_period_seconds=60)
    engine.update(make_features(second=0))
    engine.update(make_features(second=60))
    snapshot = engine.snapshot()
    storage.save_baseline("api", snapshot)
    loaded = storage.load_baseline("api")
    assert loaded is not None
    loaded["endpoints"].clear()
    assert storage.load_baseline("api")["endpoints"]

    other = learner(warmup_period_seconds=60)
    other.restore(snapshot)
    assert other.get_all_baselines() == engine.get_all_baselines()


def test_mapping_input_must_have_pseudonymized_ids():
    engine = learner()
    record = make_features(second=0).to_dict()
    record["caller_id"] = "raw-caller"
    record["caller_endpoint_key"] = f"raw-caller:{record['endpoint_key']}"

    with pytest.raises(ValueError, match="pseudonymized"):
        engine.update(record)


def test_ewma_and_rolling_values_survive_round_trip():
    engine = learner(warmup_period_seconds=300)
    for second, latency in ((0, 10), (60, 20), (120, 30)):
        engine.update(make_features(second=second, latency=latency))
    snapshot = engine.snapshot()
    restored = learner(warmup_period_seconds=300)
    restored.restore(snapshot)
    before = engine.get_endpoint_baseline("GET /items/{id}")
    after = restored.get_endpoint_baseline("GET /items/{id}")

    assert after["ewma"] == before["ewma"]
    assert after["rolling"] == before["rolling"]
