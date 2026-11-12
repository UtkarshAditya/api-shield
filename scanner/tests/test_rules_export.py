from scanner.apishield_scanner.models import Finding
from scanner.apishield_scanner.rules import export_rules


def _finding_with_rule(rule):
    return Finding(id="f", endpoint="/x", method="GET", owasp_cat="c", title="t",
                    severity="high", risk_score=5, evidence={}, fix="f", suggested_rule=rule)


def test_require_auth_maps_to_challenge():
    f = _finding_with_rule({"id": "r1", "match": {"path": "/admin"}, "action": "require_auth", "source": "scanner"})
    rules = export_rules([f])
    assert rules[0]["action"] == "challenge"


def test_rate_limit_maps_to_throttle_with_dict():
    f = _finding_with_rule({"id": "r2", "match": {"path": "/login", "method": "POST"},
                              "action": "rate_limit", "limit": "5/min", "source": "scanner"})
    rules = export_rules([f])
    assert rules[0]["action"] == "throttle"
    assert isinstance(rules[0]["throttle"], dict)


def test_injection_uses_builtin_sqli_signature():
    f = _finding_with_rule({"id": "r3", "match": {"path": "/search", "method": "GET"},
                              "action": "block", "pattern": "sql_injection", "source": "scanner"})
    rules = export_rules([f])
    assert rules[0]["match"]["signature"] == "sqli"
    assert rules[0]["action"] == "block"


def test_unsupported_action_downgrades_to_log():
    f = _finding_with_rule({"id": "r4", "match": {"path": "/users/{id}"},
                              "action": "enforce_ownership", "source": "scanner"})
    rules = export_rules([f])
    assert rules[0]["action"] == "log"


def test_dedup_by_id():
    rule = {"id": "r5", "match": {"path": "/x"}, "action": "block", "source": "scanner"}
    f1, f2 = _finding_with_rule(rule), _finding_with_rule(rule)
    assert len(export_rules([f1, f2])) == 1