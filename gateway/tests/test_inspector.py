import json

from gateway.apishield_gateway.config import Settings
from gateway.apishield_gateway.inspector import ResponseInspector

from .helpers import make_ctx

TRACE = 'Traceback (most recent call last):\n  File "/app/main.py", line 117, in debug\n    1 / 0\nZeroDivisionError: division by zero\n'
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"


def _inspect(payload, settings=None, ctype="application/json", may_mask=True, **ctx_kw):
    ctx = make_ctx(**ctx_kw)
    body = json.dumps(payload).encode() if not isinstance(payload, (bytes, str)) else (
        payload.encode() if isinstance(payload, str) else payload)
    out = ResponseInspector(settings or Settings(inspector_detectors={})).inspect(ctx, body, ctype, may_mask)
    return ctx, out.decode()


def test_clean_response_is_returned_byte_for_byte():
    ctx, out = _inspect('{"users":  3,"revenue":125000}')
    assert out == '{"users":  3,"revenue":125000}' and ctx.rule_hits == []


def test_api_key_is_masked_inside_json():
    ctx, out = _inspect({"user_id": "1", "api_key": "sk_live_51H8abc123DEMOKEY"})
    assert json.loads(out) == {"user_id": "1", "api_key": "[REDACTED:api_key]"}
    assert ctx.rule_hits == ["resp.secret.api_key"] and ctx.action == "log"


def test_other_key_formats():
    for secret in ("AKIAIOSFODNN7EXAMPLE", "ghp_" + "a" * 36, "xoxb-123456789012-abcdefghij"):
        _, out = _inspect({"note": f"key is {secret} ok"})
        assert secret not in out and "key is [REDACTED:api_key] ok" in out


def test_stack_trace_value_is_replaced_whole():
    ctx, out = _inspect({"trace": TRACE, "ok": False})
    assert json.loads(out) == {"trace": "[REDACTED:stack_trace]", "ok": False}
    assert "resp.error.stack_trace" in ctx.rule_hits


def test_sql_error_text_is_masked():
    ctx, out = _inspect({"error": 'near "1": syntax error', "trace": TRACE})
    assert json.loads(out) == {"error": "[REDACTED:sql]", "trace": "[REDACTED:stack_trace]"}
    assert set(ctx.rule_hits) == {"resp.error.sql", "resp.error.stack_trace"}


def test_private_key_and_plain_text_trace():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    _, out = _inspect({"key": pem})
    assert json.loads(out)["key"] == "[REDACTED:private_key]"
    ctx, out = _inspect("Internal Server Error\n" + TRACE, ctype="text/plain")
    assert "ZeroDivisionError" not in out and out.startswith("[REDACTED:stack_trace]")


def test_java_and_node_traces_are_detected():
    java = "java.lang.NullPointerException\n\tat com.shop.OrderService.find(OrderService.java:42)"
    node = "TypeError: x is undefined\n    at handler (/srv/app/routes/user.js:10:15)"
    for trace in (java, node):
        ctx, _ = _inspect({"detail": trace})
        assert "resp.error.stack_trace" in ctx.rule_hits


def test_jwt_masked_by_default_but_alert_only_when_configured():
    _, out = _inspect({"token": JWT})
    assert JWT not in out
    ctx, out = _inspect({"token": JWT}, settings=Settings(inspector_detectors={"secret.jwt": "alert"}))
    assert JWT in out and ctx.rule_hits == ["resp.secret.jwt"]


def test_allow_list_skips_detector_for_one_route_only():
    settings = Settings(inspector_detectors={},
                        inspector_allow=[{"method": "POST", "path": "/login", "detectors": ["secret.jwt"]}])
    ctx, out = _inspect({"token": JWT}, settings=settings, method="POST", path="/login")
    assert JWT in out and ctx.rule_hits == []
    _, out = _inspect({"token": JWT}, settings=settings, path="/profile")
    assert JWT not in out


def test_alert_mode_and_monitor_mode_record_but_do_not_rewrite():
    payload = {"api_key": "sk_live_51H8abc123DEMOKEY"}
    for kw in ({"settings": Settings(inspector_mode="alert")}, {"may_mask": False}):
        ctx, out = _inspect(payload, **kw)
        assert "sk_live_51H8abc123DEMOKEY" in out and ctx.rule_hits == ["resp.secret.api_key"]


def test_wants_only_text_under_the_size_cap():
    insp = ResponseInspector(Settings(inspector_max_bytes=100))
    assert insp.wants("application/json", "", "50")
    assert not insp.wants("application/json", "", "5000")
    assert not insp.wants("image/png", "", "50")
    assert not insp.wants("application/json", "gzip", "50")
    assert not ResponseInspector(Settings(inspector_mode="off")).wants("application/json", "", "50")
