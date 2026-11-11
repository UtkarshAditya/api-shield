import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gateway.apishield_gateway.ratelimit import MemoryBucketStore
from gateway.apishield_gateway.rules import Condition, Rule, RuleSet, RulesStage

from .helpers import make_ctx, run

BUILTIN = Path(__file__).resolve().parents[1] / "rules"


def _builtin_stage():
    ruleset = RuleSet(BUILTIN)
    ruleset.maybe_reload()
    assert ruleset.errors == []
    return RulesStage(ruleset, MemoryBucketStore())


def _hit(stage, **kw):
    decision = run(stage.on_request(make_ctx(**kw)))
    return decision.hit if decision else None


@pytest.mark.parametrize("query", [
    "q=' OR '1'='1",
    "q=%27%20OR%20%271%27%3D%271",
    "q=%2527%2520OR%25201%253D1--%20",      # double-encoded
    "q=x' UNION SELECT username, password FROM users--",
    "q=1; DROP TABLE users",
    "q=admin'--",
])
def test_sql_injection_is_blocked(query):
    assert _hit(_builtin_stage(), path="/search", query=query) == "builtin-sqli"


@pytest.mark.parametrize("kw,rule", [
    ({"path": "/search", "query": "q=<script>alert(1)</script>"}, "builtin-xss"),
    ({"method": "POST", "path": "/comments", "json_body": {"text": "<img src=x onerror=alert(1)>"}}, "builtin-xss"),
    ({"path": "/files/..%2f..%2fetc%2fpasswd"}, "builtin-path-traversal"),
    ({"path": "/download", "query": "file=../../secret.txt"}, "builtin-path-traversal"),
    ({"method": "POST", "path": "/login", "json_body": {"username": {"$ne": None}, "password": {"$gt": ""}}}, "builtin-nosqli"),
    ({"path": "/search", "headers": {"User-Agent": "sqlmap/1.7.2#stable"}}, "builtin-bad-user-agent"),
    ({"path": "/search", "ip": "203.0.113.9"}, "builtin-ip-denylist"),
])
def test_other_builtin_signatures(kw, rule):
    assert _hit(_builtin_stage(), **kw) == rule


@pytest.mark.parametrize("kw", [
    {"path": "/search", "query": "q=alice"},
    {"path": "/search", "query": "q=o'brien"},
    {"path": "/search", "query": "q=rock and roll"},
    {"method": "POST", "path": "/comments", "json_body": {"text": "Select the best option and order it. Cost: $5 #deal"}},
    {"method": "POST", "path": "/login", "json_body": {"username": "alice", "password": "alice123"}},
    {"path": "/users/3", "headers": {"User-Agent": "Mozilla/5.0"}},
])
def test_normal_traffic_is_not_blocked(kw):
    assert _hit(_builtin_stage(), **kw) is None


def _rule(**kw):
    return Rule.from_dict({"id": "r1", "action": "block", "match": {"path": "/x"}, **kw})


def test_match_fields_are_anded():
    rule = _rule(match={"path": "/admin/*", "method": ["POST", "DELETE"], "header": {"x-env": "^prod$"}})
    assert rule.matches(make_ctx(method="POST", path="/admin/users", headers={"X-Env": "prod"}))
    assert not rule.matches(make_ctx(method="GET", path="/admin/users", headers={"X-Env": "prod"}))
    assert not rule.matches(make_ctx(method="POST", path="/public", headers={"X-Env": "prod"}))
    assert not rule.matches(make_ctx(method="POST", path="/admin/users", headers={"X-Env": "dev"}))


def test_path_template_and_custom_regex_signature():
    assert _rule(match={"path": "/users/{id}"}).matches(make_ctx(path="/users/77"))
    custom = _rule(match={"signature": "regex:\\bcanary-\\d+\\b"})
    assert custom.matches(make_ctx(path="/a", query="t=canary-42"))
    assert not custom.matches(make_ctx(path="/a", query="t=canary"))


def test_conditions():
    big = Condition("req_size > 20 and method == 'POST'")
    assert big.evaluate(make_ctx(method="POST", path="/c", body=b"x" * 30))
    assert not big.evaluate(make_ctx(method="POST", path="/c", body=b"x"))
    assert Condition("matches(query['q'], '^adm') or header['x-debug'] == '1'").evaluate(
        make_ctx(path="/s", query="q=admin"))
    assert Condition("body.role == 'admin' and not authenticated").evaluate(
        make_ctx(method="POST", path="/c", json_body={"role": "admin"}))
    assert not Condition("query['missing'] > 5").evaluate(make_ctx(path="/s"))  # type mismatch = no match


@pytest.mark.parametrize("source", [
    "__import__('os').system('id')",
    "open('/etc/passwd')",
    "body.__class__",
    "[x for x in payload]",
    "lambda: 1",
    "unknown_name == 1",
])
def test_conditions_cannot_run_code(source):
    if source == "body.__class__":  # parses, but attribute access is only a dict lookup
        assert Condition(source).evaluate(make_ctx(method="POST", path="/c", json_body={"a": 1})) is False
    else:
        with pytest.raises(ValueError):
            Condition(source)


@pytest.mark.parametrize("bad", [
    {"action": "block", "match": {"path": "/x"}},                      # no id
    {"id": "r", "action": "explode", "match": {"path": "/x"}},         # bad action
    {"id": "r", "action": "block", "match": {}},                       # would match everything
    {"id": "r", "action": "block", "match": {"signature": "nope"}},    # unknown signature
    {"id": "r", "action": "block", "match": {"header": {"x": "("}}},   # bad regex
    {"id": "r", "action": "block", "match": {"ip": "999.1.1.1"}},      # bad address
])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(ValueError):
        Rule.from_dict(bad)


def _stage_with(tmp_path, *rules):
    (tmp_path / "rules.json").write_text(json.dumps({"rules": list(rules)}))
    ruleset = RuleSet(tmp_path)
    ruleset.maybe_reload()
    assert ruleset.errors == []
    return RulesStage(ruleset, MemoryBucketStore())


def test_actions_log_allow_block(tmp_path):
    stage = _stage_with(
        tmp_path,
        {"id": "allow-health", "action": "allow", "match": {"path": "/health"}, "priority": 1},
        {"id": "watch-admin", "action": "log", "match": {"path": "/admin/*"}},
        {"id": "block-all-deletes", "action": "block", "match": {"method": "DELETE"}},
    )
    logged = make_ctx(path="/admin/stats")
    assert run(stage.on_request(logged)) is None
    assert logged.rule_hits == ["watch-admin"] and logged.action == "log"

    both = make_ctx(method="DELETE", path="/admin/users")
    decision = run(stage.on_request(both))
    assert decision.status == 403 and decision.hit == "block-all-deletes" and "watch-admin" in both.rule_hits

    allowed = make_ctx(method="DELETE", path="/health")  # allow rule runs first and stops evaluation
    assert run(stage.on_request(allowed)) is None and allowed.action == "allow"


def test_challenge_requires_credentials_and_accepts_scanner_alias(tmp_path):
    # This is the draft shape the scanner's missing-auth check emits.
    stage = _stage_with(tmp_path, {"id": "rule-require-auth-admin-stats", "action": "require_auth",
                                   "source": "scanner", "match": {"path": "/admin/stats", "method": "GET"}})
    decision = run(stage.on_request(make_ctx(path="/admin/stats")))
    assert decision.status == 401 and decision.action == "challenge"
    signed_in = make_ctx(path="/admin/stats")
    signed_in.authenticated = True
    assert run(stage.on_request(signed_in)) is None


def test_throttle_rule_returns_429(tmp_path):
    stage = _stage_with(tmp_path, {"id": "slow-login", "action": "throttle", "throttle": {"limit": 2, "per": 60},
                                   "match": {"path": "/login", "method": "POST"}})
    results = [run(stage.on_request(make_ctx(method="POST", path="/login"))) for _ in range(3)]
    assert results[:2] == [None, None]
    assert results[2].status == 429 and results[2].action == "throttle" and "Retry-After" in results[2].headers


def test_expired_and_disabled_rules_are_skipped(tmp_path):
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    stage = _stage_with(
        tmp_path,
        {"id": "expired", "action": "block", "match": {"path": "/a"}, "expires_at": past},
        {"id": "disabled", "action": "block", "match": {"path": "/b"}, "enabled": False},
        {"id": "live", "action": "block", "match": {"path": "/c"}, "expires_at": future},
    )
    assert _hit(stage, path="/a") is None
    assert _hit(stage, path="/b") is None
    assert _hit(stage, path="/c") == "live"


def _touch(path: Path, seconds: int) -> None:
    stat = path.stat()
    os.utime(path, (stat.st_atime + seconds, stat.st_mtime + seconds))


def test_hot_reload_picks_up_changes_and_survives_a_broken_file(tmp_path):
    path = tmp_path / "team.yaml"
    path.write_text("rules:\n  - {id: one, action: block, match: {path: /one}}\n")
    ruleset = RuleSet(tmp_path)
    assert ruleset.maybe_reload() is True
    assert ruleset.maybe_reload() is False  # nothing changed
    assert [r.id for r in ruleset.rules] == ["one"]

    path.write_text("rules:\n  - {id: one, action: block, match: {path: /one}}\n"
                    "  - {id: two, action: log, match: {path: /two}}\n"
                    "  - {id: broken, action: nope, match: {path: /x}}\n")
    _touch(path, 5)
    assert ruleset.maybe_reload() is True
    assert [r.id for r in ruleset.rules] == ["one", "two"]  # the bad rule is skipped, not fatal
    assert len(ruleset.errors) == 1 and "broken" in ruleset.errors[0]

    path.write_text("rules: [this is: not: valid yaml")
    _touch(path, 10)
    ruleset.maybe_reload()
    assert [r.id for r in ruleset.rules] == ["one", "two"]  # last good version stays active
    assert ruleset.errors


def test_runtime_upsert_and_remove(tmp_path):
    ruleset = RuleSet(tmp_path)
    ruleset.maybe_reload()
    ruleset.upsert([{"id": "from-scanner", "action": "block", "source": "scanner", "match": {"path": "/search", "signature": "sqli"}}])
    assert [r.id for r in ruleset.rules] == ["from-scanner"]
    with pytest.raises(ValueError):
        ruleset.upsert([{"id": "bad", "action": "block", "match": {}}])
    assert ruleset.remove("from-scanner") is True and ruleset.rules == []
    assert ruleset.remove("from-scanner") is False
