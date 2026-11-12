import json
from dataclasses import replace

import pytest
from admin_api.privacy import pseudonymize

from apishield_learning.alerts import (
    AlertConfig,
    AlertService,
)
from apishield_learning.events import IdentifierPseudonymizer, TrafficEvent
from apishield_learning.features import extract_features
from apishield_learning.storage import InMemoryLearningStorage
from apishield_learning.detectors.results import DetectorResult

PSEUDONYMIZER = IdentifierPseudonymizer(b"a sufficiently long key for alert tests")


def make_features(*, ts="2026-11-12T10:00:00Z", caller="caller-a", endpoint="/items/{id}"):
    event = TrafficEvent(
        ts=ts,
        req_id="must-not-be-persisted",
        caller=caller,
        ip="192.0.2.10",
        method="GET",
        path_template=endpoint,
        status=200,
        latency_ms=10,
        req_size=20,
        resp_size=100,
        shape_hash="shape-a",
        rule_hits=(),
        action="allow",
    )
    return extract_features(event, PSEUDONYMIZER)


def result(
    detector="latency",
    *,
    score=0.8,
    detected=True,
    baseline_ready=True,
    observed=100,
    expected=10,
    features=("latency_ms",),
):
    return DetectorResult(
        detector=detector,
        detected=detected,
        kind="statistical_anomaly",
        score=score,
        severity="high",
        observed=observed,
        expected=expected,
        threshold=3,
        explanation="Observed latency exceeded the learned baseline.",
        contributing_features=features,
        baseline_ready=baseline_ready,
        timestamp="2026-11-12T10:00:00Z",
    )


class RiskProvider:
    def __init__(self, value):
        self.value = value
        self.calls = []

    def get_risk_score(self, endpoint, method):
        self.calls.append((endpoint, method))
        return self.value


def test_score_calculation_and_endpoint_risk_are_separately_visible():
    risk = RiskProvider(0.75)
    service = AlertService(endpoint_risk_provider=risk)

    alert = service.generate_alerts([result(score=0.8)], make_features())[0]

    assert alert.anomaly_score == 0.8
    assert alert.endpoint_risk_score == 0.75
    assert alert.repeat_factor == 1
    assert alert.priority_score == pytest.approx(0.6)
    assert alert.severity == "medium"
    assert risk.calls == [("/items/{id}", "GET")]


def test_missing_endpoint_risk_uses_explicit_fallback_without_claiming_risk():
    service = AlertService(config=AlertConfig(missing_risk_fallback=0.4))

    alert = service.generate_alerts([result(score=0.5)], make_features())[0]

    assert alert.endpoint_risk_score is None
    assert alert.priority_score == pytest.approx(0.2)
    assert alert.severity == "low"


@pytest.mark.parametrize("risk", [-0.1, 1.1, float("nan"), float("inf"), "high", True])
def test_invalid_endpoint_risk_is_rejected(risk):
    service = AlertService(endpoint_risk_provider=RiskProvider(risk))

    with pytest.raises(ValueError, match="endpoint risk score"):
        service.generate_alerts([result()], make_features())


@pytest.mark.parametrize("score", [-0.01, 1.01, float("nan"), float("inf"), True])
def test_invalid_anomaly_score_is_rejected(score):
    with pytest.raises(ValueError, match="anomaly score"):
        AlertService().generate_alerts([result(score=score)], make_features())


def test_severity_thresholds_are_configurable():
    service = AlertService(
        endpoint_risk_provider=RiskProvider(1),
        config=AlertConfig(
            critical_threshold=0.9,
            high_threshold=0.7,
            medium_threshold=0.5,
            low_threshold=0.2,
        ),
    )

    alert = service.generate_alerts([result(score=0.75)], make_features())[0]

    assert alert.severity == "high"
    with pytest.raises(ValueError, match="descending"):
        AlertConfig(
            critical_threshold=0.4,
            high_threshold=0.7,
            medium_threshold=0.5,
            low_threshold=0.2,
        )


def test_repeat_factor_is_bounded_and_same_group_updates_existing_alert():
    storage = InMemoryLearningStorage()
    service = AlertService(
        storage=storage,
        endpoint_risk_provider=RiskProvider(1),
        config=AlertConfig(repeat_growth=0.5, maximum_repeat_factor=2),
    )
    first = service.generate_alerts([result()], make_features())[0]
    current = first
    for second in range(1, 5):
        current = service.generate_alerts(
            [result()],
            make_features(ts=f"2026-11-12T10:00:{second:02d}Z"),
        )[0]

    assert current.alert_id == first.alert_id
    assert current.repeat_count == 5
    assert current.repeat_factor == 2
    assert len(service.get_alerts()) == 1


def test_identical_timestamp_is_deduplicated_without_increasing_repeat_count():
    service = AlertService(endpoint_risk_provider=RiskProvider(1))
    features = make_features()

    first = service.generate_alerts([result()], features)[0]
    duplicate = service.generate_alerts([result()], features)[0]

    assert duplicate.alert_id == first.alert_id
    assert duplicate.repeat_count == 1
    assert duplicate.repeat_factor == 1


def test_multiple_detectors_contribute_to_one_alert_with_stable_grouping():
    service = AlertService(endpoint_risk_provider=RiskProvider(0.8))

    alert = service.generate_alerts(
        [
            result("latency", score=0.6, features=("latency_ms",)),
            result("request_size", score=0.9, features=("req_size",)),
        ],
        make_features(),
    )[0]

    assert alert.detector_names == ("latency", "request_size")
    assert alert.anomaly_score == 0.9
    assert alert.contributing_features == ("req_size", "latency_ms")
    assert len(service.get_alerts()) == 1


def test_grouping_is_scoped_to_pseudonymous_caller_and_endpoint():
    service = AlertService()

    first = service.generate_alerts([result()], make_features())[0]
    same = service.generate_alerts(
        [result()], make_features(ts="2026-11-12T10:00:05Z")
    )[0]
    other_caller = service.generate_alerts(
        [result()], make_features(ts="2026-11-12T10:00:06Z", caller="caller-b")
    )[0]
    other_endpoint = service.generate_alerts(
        [result()],
        make_features(ts="2026-11-12T10:00:07Z", endpoint="/accounts/{id}"),
    )[0]

    assert first.alert_id == same.alert_id
    assert len({first.alert_id, other_caller.alert_id, other_endpoint.alert_id}) == 3


def test_alert_grouping_uses_shared_caller_identity_not_internal_baseline_id():
    service = AlertService()
    first_features = make_features()
    second_features = replace(
        first_features,
        ts="2026-11-12T10:00:05Z",
        caller_id="caller_" + "f" * 64,
        caller_endpoint_key="caller_" + "f" * 64 + ":" + first_features.endpoint_key,
    )

    first = service.generate_alerts([result()], first_features)[0]
    second = service.generate_alerts([result()], second_features)[0]

    assert first.caller_id == second.caller_id == first_features.alert_caller_id
    assert first.alert_id == second.alert_id
    assert second.repeat_count == 2


def test_alert_is_not_deduplicated_after_repeat_window_expires():
    service = AlertService(config=AlertConfig(repeat_window_seconds=60))
    first = service.generate_alerts([result()], make_features())[0]

    later = service.generate_alerts(
        [result()], make_features(ts="2026-11-12T10:02:00Z")
    )[0]

    assert later.alert_id != first.alert_id
    assert len(service.get_alerts()) == 2


def test_explanation_describes_observed_expected_features_baseline_and_uncertainty():
    alert = AlertService().generate_alerts(
        [result(baseline_ready=False)], make_features()
    )[0]

    assert "observed 100" in alert.explanation
    assert "expected 10" in alert.explanation
    assert "latency_ms" in alert.explanation
    assert "did not have a ready baseline" in alert.explanation
    assert "not confirmation of an attack" in alert.explanation


def test_storage_retrieval_filtering_ranking_status_and_summary():
    service = AlertService(
        endpoint_risk_provider=RiskProvider(1),
    )
    lower = service.generate_alerts(
        [result(score=0.4)], make_features(caller="caller-a")
    )[0]
    higher = service.generate_alerts(
        [result(score=0.7)], make_features(caller="caller-b")
    )[0]

    assert service.get_alert(lower.alert_id) == lower
    assert service.get_alert("missing") is None
    assert [a.alert_id for a in service.get_alerts({"severity": "high"})] == [
        higher.alert_id
    ]
    assert service.get_ranked_alerts(limit=1) == [higher]
    changed = service.update_alert_status(lower.alert_id, "acknowledged")
    assert changed.status == "acknowledged"
    assert service.get_alert_summary()["by_status"]["acknowledged"] == 1
    with pytest.raises(ValueError, match="status"):
        service.update_alert_status(lower.alert_id, "invalid")
    with pytest.raises(KeyError):
        service.update_alert_status("missing", "resolved")


def test_privacy_safe_alert_excludes_raw_identifiers_and_payload_like_keys():
    storage = InMemoryLearningStorage()
    features = make_features()
    raw_caller = "caller-a"
    raw_ip = "192.0.2.10"
    unsafe_result = replace(
        result(),
        explanation="raw caller-a password secret-token request payload",
        observed={
            "latency_ms": 100,
            "authorization": "secret-token",
            "request_body": {"password": "secret"},
            "ip": raw_ip,
            "caller": raw_caller,
        },
    )
    alert = AlertService(storage=storage).generate_alerts(
        [unsafe_result], features
    )[0]
    serialized = json.dumps(storage.list_alerts())

    assert alert.caller_id == features.alert_caller_id
    assert alert.caller_id == pseudonymize("caller-a", "dev-only-pseudo-salt")
    assert features.caller_id != raw_caller
    assert raw_caller not in serialized
    assert raw_ip not in serialized
    assert "secret-token" not in serialized
    assert "secret" not in serialized
    assert "raw caller-a" not in serialized
    assert "authorization" not in serialized
    assert "request_body" not in serialized


def test_raw_identifiers_cannot_enter_alert_feature_record():
    features = make_features()
    unsafe_features = replace(features, caller_id="caller-a")

    with pytest.raises(ValueError, match="pseudonymous"):
        AlertService().generate_alerts([result()], unsafe_features)


def test_shared_id_is_not_substituted_for_internal_baseline_identifier():
    features = replace(make_features(), caller_id="ip_ca884e30")

    with pytest.raises(ValueError, match="internal feature identifiers"):
        AlertService().generate_alerts([result()], features)


@pytest.mark.parametrize(
    "caller_id",
    ["ip_ca884e30", "user_3644e45c", "key_929bf132"],
)
def test_shared_admin_caller_pseudonym_formats_are_accepted(caller_id):
    features = replace(make_features(), alert_caller_id=caller_id)

    alert = AlertService().generate_alerts([result()], features)[0]

    assert alert.caller_id == caller_id


@pytest.mark.parametrize(
    "caller_id",
    [
        ("host_ca884e30"),
        ("ip_ca884e3"),
        ("user_3644e3000"),
        ("ip_CA884E30"),
        ("192.0.2.10"),
        ("caller-a"),
        ("key_929bf13g"),
    ],
)
def test_invalid_or_raw_caller_identifiers_are_rejected(caller_id):
    features = replace(make_features(), alert_caller_id=caller_id)

    with pytest.raises(ValueError, match="shared pseudonym"):
        AlertService().generate_alerts([result()], features)


def test_no_detected_results_create_no_alert_and_unknown_filter_is_rejected():
    service = AlertService()

    assert service.generate_alerts(
        [result(detected=False)], make_features()
    ) == []
    with pytest.raises(ValueError, match="unknown alert filter"):
        service.get_alerts({"not_a_field": "x"})


def test_only_active_alerts_deduplicate_and_status_change_persists():
    service = AlertService()
    first = service.generate_alerts([result()], make_features())[0]
    service.update_alert_status(first.alert_id, "resolved")

    later = service.generate_alerts(
        [result()], make_features(ts="2026-11-12T10:00:05Z")
    )[0]

    assert later.alert_id != first.alert_id
