import json

import pytest

from admin_api.privacy import pseudonymize

from apishield_learning.config import ConfigurationError, LearningConfig
from apishield_learning.events import IdentifierPseudonymizer, TrafficEvent
from apishield_learning.features import extract_features

EVENT_DATA = {
    "ts": "2026-11-12T10:15:30.250Z",
    "req_id": "request-id-private",
    "caller": "caller-private",
    "ip": "192.0.2.44",
    "method": "get",
    "path_template": "/items/{id}",
    "status": 201,
    "latency_ms": 25.75,
    "req_size": 12,
    "resp_size": 64,
    "shape_hash": "shape-hash-only",
    "rule_hits": ["limit-one", "shape-check"],
    "action": "allow",
}


@pytest.fixture
def event():
    return TrafficEvent.from_mapping(EVENT_DATA)


def test_extract_features_adds_rate_grouping_and_time_features(event):
    features = extract_features(
        event, IdentifierPseudonymizer(b"a sufficiently long key for tests")
    )

    assert features.method == "GET"
    assert features.path_template == "/items/{id}"
    assert features.status == 201
    assert features.latency_ms == 25.75
    assert features.req_size == 12
    assert features.resp_size == 64
    assert features.shape_hash == "shape-hash-only"
    assert features.rule_hit_count == 2
    assert features.action == "allow"
    assert features.hour_utc == 10
    assert features.weekday_utc == 3
    assert features.request_count == 1
    assert features.rate_window_start == "2026-11-12T10:15:00Z"
    assert features.endpoint_key == "GET /items/{id}"
    assert features.caller_endpoint_key == f"{features.caller_id}:GET /items/{{id}}"
    assert features.alert_caller_id == pseudonymize(
        event.caller, "dev-only-pseudo-salt"
    )
    assert features.time_of_day_sin == pytest.approx(0.441, abs=0.01)
    assert features.time_of_day_cos == pytest.approx(-0.898, abs=0.01)


def test_feature_record_serializes_to_json_without_raw_identifiers(event):
    features = extract_features(
        event, IdentifierPseudonymizer(b"a sufficiently long key for tests")
    )
    serialized = json.dumps(features.to_dict(), sort_keys=True)

    assert "caller-private" not in serialized
    assert "192.0.2.44" not in serialized
    assert "request-id-private" not in serialized
    assert "password" not in serialized
    assert '"rule_hit_count": 2' in serialized
    assert '"request_count": 1' in serialized


@pytest.mark.parametrize(
    ("caller", "expected_prefix"),
    [
        ("key_929bf132", "key_929bf132"),
        ("user_alice", "user_"),
        ("ip_127.0.0.1", "ip_"),
        ("127.0.0.1", "ip_"),
    ],
)
def test_alert_caller_id_matches_shared_admin_api(event, caller, expected_prefix):
    source = TrafficEvent.from_mapping({**EVENT_DATA, "caller": caller})
    salt = "same-shared-salt"
    features = extract_features(
        source,
        IdentifierPseudonymizer(b"a sufficiently long key for tests"),
        config=LearningConfig(pseudo_salt=salt),
    )

    expected = pseudonymize(caller, salt)
    assert features.alert_caller_id == expected
    if expected_prefix.endswith("_"):
        assert expected.startswith(expected_prefix)
        assert len(expected.removeprefix(expected_prefix)) == 8
    else:
        assert expected == expected_prefix


def test_shared_caller_identity_does_not_change_internal_baseline_identity(event):
    first = extract_features(
        event,
        IdentifierPseudonymizer(b"a sufficiently long key for tests"),
        config=LearningConfig(pseudo_salt="salt-one"),
    )
    second = extract_features(
        event,
        IdentifierPseudonymizer(b"a sufficiently long key for tests"),
        config=LearningConfig(pseudo_salt="salt-two"),
    )

    assert first.caller_id == second.caller_id
    assert first.caller_endpoint_key == second.caller_endpoint_key
    assert first.alert_caller_id != second.alert_caller_id


def test_internal_baseline_pseudonyms_are_stable_for_the_same_shared_salt(event):
    config = LearningConfig(pseudo_salt="stable-shared-salt")

    first = extract_features(event, config=config)
    second = extract_features(event, config=config)

    assert first.caller_id == second.caller_id
    assert first.ip_id == second.ip_id
    assert first.alert_caller_id == second.alert_caller_id


def test_empty_shared_salt_fails_before_features_are_created(event):
    with pytest.raises(ConfigurationError, match="must not be empty"):
        extract_features(
            event,
            IdentifierPseudonymizer(b"a sufficiently long key for tests"),
            config=LearningConfig(pseudo_salt=""),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("ts", "2026-11-12T10:00:00", "timezone"),
        ("ts", "not-a-timestamp", "ISO-8601"),
        ("status", 99, "status"),
        ("status", 600, "status"),
        ("latency_ms", float("inf"), "latency_ms"),
        ("req_size", -1, "req_size"),
        ("resp_size", 2**64, "resp_size"),
        ("method", " ", "method and path_template"),
        ("shape_hash", "", "shape_hash"),
    ],
)
def test_feature_extraction_validates_event_ranges_and_missing_values(
    field, value, message
):
    data = dict(EVENT_DATA)
    data[field] = value

    with pytest.raises(ValueError, match=message):
        event = TrafficEvent.from_mapping(data)
        extract_features(
            event, IdentifierPseudonymizer(b"a sufficiently long key for tests")
        )


def test_feature_output_is_deterministic(event):
    pseudonymizer = IdentifierPseudonymizer(b"a sufficiently long key for tests")

    assert extract_features(event, pseudonymizer) == extract_features(
        event, pseudonymizer
    )
