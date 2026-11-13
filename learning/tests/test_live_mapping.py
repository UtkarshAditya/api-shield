"""Learner alert -> Admin `alerts` row mapping (alert_mapping.py)."""

from datetime import datetime, timezone

from apishield_learning.alert_mapping import (
    MARKER_PREFIX,
    TIMELINE_BUCKETS,
    build_reasons,
    detector_for_label,
    timeline_add,
    timeline_view,
    to_alert_row,
)


def learner_alert(**overrides):
    alert = {
        "alert_id": "0b8f3f9e-1111-4222-8333-944445555666",
        "timestamp": "2026-11-13T18:00:00Z",
        "endpoint": "/login",
        "method": "POST",
        "caller_id": "key_929bf132",
        "anomaly_score": 1.0,
        "endpoint_risk_score": None,
        "repeat_factor": 1.5,
        "priority_score": 0.75,
        "severity": "high",
        "status": "new",
        "detector_names": ["http_error_rate", "request_rate_spike", "rule_hit_or_blocked_action"],
        "observed_values": {
            "http_error_rate": 1.0,
            "request_rate_spike": 40.0,
            "rule_hit_or_blocked_action": {"rule_hit_count": 1, "action": "throttle"},
        },
        "expected_values": {
            "http_error_rate": {"mean": 0.0, "ewma": 0.0, "standard_deviation": 0.0},
            "request_rate_spike": {"mean": 6.0, "ewma": 5.0, "standard_deviation": 2.0},
            "rule_hit_or_blocked_action": "allow/log with no rule hits",
        },
        "thresholds": {"http_error_rate": {"z_score": 3.0, "ratio": None}},
        "explanation": "http_error_rate: observed 1.0; expected ... technical text",
        "contributing_features": ["status"],
        "feedback_status": None,
        "grouping_key": "1dc76f4ee734" + "0" * 52,
        "repeat_count": 6,
        "first_seen": "2026-11-13T18:00:00Z",
        "last_seen": "2026-11-13T18:00:03Z",
        "last_observation_key": "2026-11-13T18:00:03Z",
    }
    alert.update(overrides)
    return alert


def test_row_fields():
    row = to_alert_row(learner_alert(), "up_shop", [{"ts": "2026-11-13T18:00:00Z", "count": 6}])
    assert row["id"] == "0b8f3f9e-1111-4222-8333-944445555666"
    assert row["upstream_id"] == "up_shop"
    assert row["ts"] == datetime(2026, 11, 13, 18, 0, 3, tzinfo=timezone.utc)  # last_seen
    assert row["caller"] == "key_929bf132"
    assert row["endpoint"] == "POST /login"
    assert row["score"] == 0.75
    assert row["severity"] == "high"
    assert row["group_id"] == "grp_1dc76f4ee734"
    assert row["timeline"] == [{"ts": "2026-11-13T18:00:00Z", "count": 6}]
    assert "status" not in row and "rank" not in row  # owned by the Admin API / re-ranking


def test_info_alerts_are_not_mapped():
    assert to_alert_row(learner_alert(severity="info", priority_score=0.1), "up_shop", None) is None


def test_reasons_are_human_and_sorted_by_z():
    reasons = build_reasons(learner_alert())
    assert [r["feature"] for r in reasons] == ["Failed logins", "Request rate", "Rule hits / blocked"]
    rate = reasons[1]
    assert rate == {"feature": "Request rate", "observed": "40 req/min", "baseline": "typically 5 req/min",
                    "z": 17.0}
    assert reasons[0]["z"] == 99.0  # zero-variance baseline: any failure is maximal
    assert reasons[2]["observed"] == "1 rule hit(s), action throttle"
    assert all(set(r) <= {"feature", "observed", "baseline", "z"} for r in reasons)


def test_reason_strings_never_echo_shape_hashes_or_sequences():
    alert = learner_alert(
        endpoint="/search", method="GET",
        detector_names=["new_payload_shape", "endpoint_sequence"],
        observed_values={"new_payload_shape": "shape-secret-hash", "endpoint_sequence": "GET /a -> GET /search"},
        expected_values={"new_payload_shape": ["shape-1", "shape-2"], "endpoint_sequence": ["GET /a -> GET /b"]},
    )
    text = str(build_reasons(alert))
    assert "shape-secret-hash" not in text and "GET /a" not in text
    assert "2 learned shape(s)" in text


def test_explanation_is_plain_and_marked():
    row = to_alert_row(learner_alert(), "up_shop", None)
    text = row["explanation"]
    assert text.startswith("This caller made 6 unusual requests to POST /login")
    assert "logins kept failing" in text
    assert "not proof of an attack" in text
    assert MARKER_PREFIX in text and "Demo replay" not in text
    assert "observed 1.0" not in text  # not the learner's technical string
    assert text.count(". ") <= 4


def test_explanation_mentions_scan_risk_when_high():
    text = to_alert_row(learner_alert(endpoint_risk_score=0.9), "up_shop", None)["explanation"]
    assert "last scan rated this endpoint high risk" in text
    assert "endpoint risk 0.90" in text


def test_labels_map_back_to_detectors():
    assert detector_for_label("Failed logins") == "http_error_rate"
    assert detector_for_label("Request rate") == "request_rate_spike"
    assert detector_for_label("latency") == "latency"
    assert detector_for_label("Distinct usernames") is None
    assert detector_for_label(None) is None


def test_timeline_is_bounded_and_zero_filled():
    buckets = {}
    for second in range(0, 600, 5):  # 10 minutes, one observation every 5 s
        timeline_add(buckets, f"2026-11-13T18:{second // 60:02d}:{second % 60:02d}Z")
    assert len(buckets) == TIMELINE_BUCKETS
    view = timeline_view(buckets, "2026-11-13T18:09:55Z")
    assert len(view) == TIMELINE_BUCKETS
    assert view[-1] == {"ts": "2026-11-13T18:09:45Z", "count": 3}
    sparse = timeline_view({}, "2026-11-13T18:09:55Z")
    assert [b["count"] for b in sparse] == [0] * TIMELINE_BUCKETS
