import json

import pytest

from apishield_learning.events import (
    EVENT_FIELDS,
    EventValidationError,
    IdentifierPseudonymizer,
    TrafficEvent,
)
from apishield_learning.features import extract_features


@pytest.fixture
def event_payload():
    return {
        "ts": "2026-11-12T10:00:00Z",
        "req_id": "request-123",
        "caller": "user-raw-subject",
        "ip": "192.0.2.10",
        "method": "GET",
        "path_template": "/items/{id}",
        "status": 200,
        "latency_ms": 12.5,
        "req_size": 0,
        "resp_size": 350,
        "shape_hash": "shape-abc",
        "rule_hits": [],
        "action": "allow",
    }


def test_event_parses_the_exact_gateway_contract(event_payload):
    event = TrafficEvent.from_json(
        json.dumps(event_payload, separators=(",", ":")).encode("utf-8")
    )

    assert tuple(event.__dict__) == EVENT_FIELDS
    assert event.path_template == "/items/{id}"
    assert event.latency_ms == 12.5
    assert event.rule_hits == ()


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.pop("ip"), "missing fields: ip"),
        (lambda value: value.update(payload={"password": "secret"}), "unexpected fields"),
        (lambda value: value.update(status=True), "status must be an integer"),
        (lambda value: value.update(req_size=-1), "req_size must be non-negative"),
        (lambda value: value.update(latency_ms=float("nan")), "latency_ms must be"),
        (lambda value: value.update(rule_hits=["ok", 1]), "rule_hits must be"),
        (lambda value: value.update(action="drop"), "action is not"),
    ],
)
def test_event_rejects_invalid_or_unapproved_fields(event_payload, mutate, message):
    mutate(event_payload)
    with pytest.raises(EventValidationError, match=message):
        TrafficEvent.from_mapping(event_payload)


def test_event_rejects_invalid_json():
    with pytest.raises(EventValidationError, match="valid UTF-8 JSON"):
        TrafficEvent.from_json(b"{")


def test_event_rejects_fields_outside_producer_order(event_payload):
    reordered = dict(reversed(list(event_payload.items())))

    with pytest.raises(EventValidationError, match="M1 producer order"):
        TrafficEvent.from_mapping(reordered)


def test_features_pseudonymize_identifiers_and_omit_request_id(event_payload):
    event = TrafficEvent.from_mapping(event_payload)
    features = extract_features(
        event, IdentifierPseudonymizer(b"a sufficiently long test key")
    )

    assert features.caller_id != event_payload["caller"]
    assert features.ip_id != event_payload["ip"]
    assert event_payload["caller"] not in repr(features)
    assert event_payload["ip"] not in repr(features)
    assert "request-123" not in repr(features)
    assert not hasattr(features, "req_id")


def test_pseudonyms_are_stable_and_domain_separated():
    pseudonymizer = IdentifierPseudonymizer(b"a sufficiently long test key")

    caller_id = pseudonymizer.pseudonymize("caller", "same-value")
    ip_id = pseudonymizer.pseudonymize("ip", "same-value")

    assert caller_id == pseudonymizer.pseudonymize("caller", "same-value")
    assert caller_id != ip_id
    assert "same-value" not in caller_id


def test_pseudonymizer_rejects_empty_or_unknown_identifiers():
    pseudonymizer = IdentifierPseudonymizer(b"a sufficiently long test key")

    with pytest.raises(ValueError, match="kind"):
        pseudonymizer.pseudonymize("request", "value")
    with pytest.raises(ValueError, match="empty"):
        pseudonymizer.pseudonymize("ip", "")
