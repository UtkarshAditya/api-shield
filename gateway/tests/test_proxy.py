import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.testclient import TestClient

from gateway.apishield_gateway.config import Settings
from gateway.apishield_gateway.events import EVENT_FIELDS, MemorySink
from gateway.apishield_gateway.main import create_app

from .helpers import make_gateway, wait_for_events

upstream = FastAPI(openapi_url=None)
calls = []


@upstream.api_route("/echo/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def echo(request: Request):
    calls.append(request.url.path)
    return {"method": request.method, "path": request.url.path, "query": request.url.query,
            "headers": dict(request.headers), "body": (await request.body()).decode()}


@upstream.get("/cookies")
async def cookies():
    response = JSONResponse({"ok": True}, status_code=201)
    response.set_cookie("a", "1")
    response.set_cookie("b", "2")
    response.headers["x-upstream"] = "yes"
    return response


@upstream.get("/binary")
async def binary():
    return Response(content=bytes(range(256)) * 8, media_type="application/octet-stream")


@upstream.get("/big")
async def big():
    return Response(content="sk_live_51H8abc123DEMOKEY " + "x" * 5000, media_type="text/plain")


@upstream.get("/boom")
async def boom():
    return JSONResponse({"detail": "nope"}, status_code=418)


def _client(tmp_path, **overrides):
    app, sink = make_gateway(tmp_path, upstream, **overrides)
    return TestClient(app), sink


def test_forwards_method_path_query_body_and_headers(tmp_path):
    client, _ = _client(tmp_path)
    with client:
        r = client.post("/echo/a/b?x=1&y=two", content=b'{"k": "v"}',
                        headers={"Content-Type": "application/json", "X-Custom": "kept", "Authorization": "Basic abc"})
    seen = r.json()
    assert r.status_code == 200
    assert (seen["method"], seen["path"], seen["query"], seen["body"]) == ("POST", "/echo/a/b", "x=1&y=two", '{"k": "v"}')
    assert seen["headers"]["x-custom"] == "kept" and seen["headers"]["authorization"] == "Basic abc"


def test_adds_the_same_request_id_upstream_and_downstream(tmp_path):
    client, sink = _client(tmp_path)
    with client:
        r = client.get("/echo/x", headers={"X-Request-ID": "client-chosen"})
        event = wait_for_events(sink)[0]
    req_id = r.headers["x-request-id"]
    assert len(req_id) == 32 and req_id != "client-chosen"
    assert r.json()["headers"]["x-request-id"] == req_id == event["req_id"]


def test_hop_by_hop_headers_are_not_forwarded_and_forwarded_for_is_set(tmp_path):
    client, _ = _client(tmp_path)
    with client:
        r = client.get("/echo/x", headers={"Connection": "keep-alive, X-Hop", "X-Hop": "1",
                                           "X-Forwarded-For": "6.6.6.6"})
    headers = r.json()["headers"]
    assert "x-hop" not in headers
    assert headers["x-forwarded-for"] == "testclient"  # a spoofed value is replaced
    assert headers["x-forwarded-proto"] == "http" and headers["x-forwarded-host"] == "testserver"


def test_forwarded_for_is_trusted_only_when_configured(tmp_path):
    client, sink = _client(tmp_path, trust_forwarded_for=True)
    with client:
        client.get("/echo/x", headers={"X-Forwarded-For": "198.51.100.7, 10.0.0.1"})
        assert wait_for_events(sink)[0]["ip"] == "198.51.100.7"


def test_upstream_status_and_headers_are_preserved(tmp_path):
    client, _ = _client(tmp_path)
    with client:
        r = client.get("/cookies")
        teapot = client.get("/boom")
    assert r.status_code == 201 and r.headers["x-upstream"] == "yes"
    assert sorted(v.split("=")[0] for v in r.headers.get_list("set-cookie")) == ["a", "b"]
    assert "server-timing" in r.headers
    assert teapot.status_code == 418 and teapot.json() == {"detail": "nope"}


def test_binary_and_oversized_responses_stream_through_untouched(tmp_path):
    client, sink = _client(tmp_path, inspector_max_bytes=1000)
    with client:
        b = client.get("/binary")
        t = client.get("/big")
        events = wait_for_events(sink, 2)
    assert b.content == bytes(range(256)) * 8
    assert len(t.text) == 5026 and t.text.startswith("sk_live_")  # too big to inspect: passed through
    assert [e["resp_size"] for e in events] == [2048, 5026]


def test_small_text_response_is_inspected(tmp_path):
    client, sink = _client(tmp_path)
    with client:
        r = client.get("/big")
        event = wait_for_events(sink)[0]
    assert r.text.startswith("[REDACTED:api_key] xxx")
    assert int(r.headers["content-length"]) == len(r.content)
    assert event["rule_hits"] == ["resp.secret.api_key"] and event["action"] == "log"


def test_oversized_request_body_is_413_and_never_reaches_upstream(tmp_path):
    client, sink = _client(tmp_path, max_body_bytes=100)
    calls.clear()
    with client:
        r = client.post("/echo/upload", content=b"x" * 101)
        event = wait_for_events(sink)[0]
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"
    assert calls == [] and event["action"] == "block"


class _Down(httpx.AsyncBaseTransport):
    def __init__(self, error):
        self.error = error

    async def handle_async_request(self, request):
        raise self.error


def test_upstream_down_is_502_and_timeout_is_504(tmp_path):
    for error, status, code in ((httpx.ConnectError("refused"), 502, "upstream_unreachable"),
                                (httpx.ReadTimeout("slow"), 504, "upstream_timeout")):
        sink = MemorySink()
        settings = Settings(redis_url=None, rules_dir=str(tmp_path), rules_reload_seconds=0)
        with TestClient(create_app(settings, upstream_transport=_Down(error), event_sink=sink)) as client:
            r = client.get("/anything")
            event = wait_for_events(sink)[0]
        assert r.status_code == status and r.json()["error"]["code"] == code
        assert r.json()["request_id"] == r.headers["x-request-id"]
        assert event["status"] == status


def test_every_request_emits_one_contract_event(tmp_path):
    client, sink = _client(tmp_path)
    with client:
        client.get("/echo/items/123?page=2")
        client.post("/echo/items", json={"name": "pen", "qty": 2})
        events = wait_for_events(sink, 2)
    assert len(events) == 2
    first, second = events
    assert tuple(first) == EVENT_FIELDS
    assert first["path_template"] == "/echo/items/{id}" and first["caller"] == "ip_testclient"
    assert first["status"] == 200 and first["action"] == "allow" and first["rule_hits"] == []
    assert second["req_size"] > 0 and second["shape_hash"] != first["shape_hash"]


RULE = {"id": "block-sqli", "action": "block", "source": "scanner", "match": {"signature": "sqli"}}
ADMIN = {"X-APIShield-Admin-Token": "s3cret"}


def test_control_endpoints_are_hidden_without_a_token_and_never_proxied(tmp_path):
    client, _ = _client(tmp_path)
    calls.clear()
    with client:
        assert client.get("/_apishield/health").json()["status"] == "ok"
        assert client.get("/_apishield/rules").status_code == 404
        assert client.get("/_apishield/echo/x").status_code == 404
    assert calls == []


def test_rule_pushed_at_runtime_blocks_and_can_be_removed(tmp_path):
    client, sink = _client(tmp_path, admin_token="s3cret")
    attack = "/echo/search?q=' OR '1'='1"
    with client:
        assert client.get(attack).status_code == 200
        assert client.post("/_apishield/rules", json=RULE).status_code == 401
        assert client.post("/_apishield/rules", json={"id": "x", "action": "block", "match": {}}, headers=ADMIN).status_code == 400
        assert client.post("/_apishield/rules", json=RULE, headers=ADMIN).status_code == 200
        blocked = client.get(attack)
        listed = client.get("/_apishield/rules", headers=ADMIN).json()["rules"]
        assert client.delete("/_apishield/rules/block-sqli", headers=ADMIN).status_code == 200
        assert client.get(attack).status_code == 200
        events = wait_for_events(sink, 3)
    assert blocked.status_code == 403 and blocked.json()["error"]["code"] == "blocked_by_rule"
    assert listed[0]["id"] == "block-sqli" and listed[0]["hits"] == 1
    assert [e["action"] for e in events] == ["allow", "block", "allow"]
    assert events[1]["rule_hits"] == ["block-sqli"] and events[1]["status"] == 403


def test_monitor_mode_logs_instead_of_blocking_until_switched_to_enforce(tmp_path):
    client, sink = _client(tmp_path, admin_token="s3cret", mode="monitor")
    attack = "/echo/search?q=1 UNION SELECT password FROM users"
    with client:
        client.post("/_apishield/rules", json=RULE, headers=ADMIN)
        assert client.get(attack).status_code == 200
        assert client.put("/_apishield/mode", json={"mode": "enforce"}, headers=ADMIN).json() == {"mode": "enforce"}
        assert client.get(attack).status_code == 403
        events = wait_for_events(sink, 2)
    assert events[0]["action"] == "log" and events[0]["rule_hits"] == ["block-sqli"]
    assert events[1]["action"] == "block"


def test_a_crashing_stage_fails_open_or_closed(tmp_path):
    for fail_open, status in ((True, 200), (False, 500)):
        app, sink = make_gateway(tmp_path, upstream, fail_open=fail_open)
        with TestClient(app) as client:
            async def explode(ctx):
                raise RuntimeError("bug in a check")
            app.state.gateway.stages[3].on_request = explode
            r = client.get("/echo/x")
            event = wait_for_events(sink)[0]
        assert r.status_code == status
        assert "gateway.stage_error.validation" in event["rule_hits"]
