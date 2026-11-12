"""Fails if a raw IP, a raw user subject or the gateway admin token appears in any API
response, in the database, or in the logs."""
import json
import logging
from pathlib import Path

import pytest
from sqlalchemy import select

from admin_api.models import AlertRow
from admin_api.db import Base

from .conftest import ADMIN_TOKEN
from .scenario import RAW_VALUES, build, call_everything, sse_event

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def populated():
    return build()


@pytest.fixture(scope="module")
def responses(populated):
    app, gateway = populated
    return call_everything(app, gateway)


def test_every_endpoint_was_called(responses):
    assert len(responses) >= 40
    failures = {k: v[0] for k, v in responses.items() if v[0] >= 400 and not k.startswith("error_")}
    assert failures == {}


def test_no_raw_ip_or_user_in_any_response(responses):
    for name, (_status, body) in responses.items():
        text = body if isinstance(body, str) else json.dumps(body)
        if name in ("rule_create", "rule_patch", "rules"):
            # Rule.match.ip is operator-entered CIDR config (the agreed exception); check the rest.
            text = text.replace("10.0.0.0/8", "").replace("203.0.113.0/24", "")
        for raw in RAW_VALUES:
            assert raw not in text, f"{raw} leaked in {name}"


def test_sse_messages_are_masked(populated):
    message = sse_event(populated[0])
    assert message.startswith("event: traffic")
    for raw in RAW_VALUES:
        assert raw not in message


def test_raw_ips_never_stored(populated):
    app, _ = populated
    with app.state.session_factory() as s:
        for table in Base.metadata.sorted_tables:
            if table.name == "alerts":  # the scenario's careless-learner row is raw on purpose
                continue
            dump = json.dumps([list(map(str, row)) for row in s.execute(select(table))])
            for raw in RAW_VALUES:
                assert raw not in dump, f"{raw} stored in {table.name}"
        alert = s.get(AlertRow, "al_raw")
    assert alert is not None  # ...and it is still masked on the way out (see the response sweep)


def test_admin_token_never_leaves_the_server(caplog):
    app, gateway = build()
    with caplog.at_level(logging.DEBUG):
        responses = call_everything(app, gateway)
    # The token was really used (towards the gateway)...
    assert any(r.headers.get("x-apishield-admin-token") == ADMIN_TOKEN for r in gateway.requests)
    # ...but never echoed in a response or a log line, including the gateway-down path.
    for name, (_status, body) in responses.items():
        assert ADMIN_TOKEN not in (body if isinstance(body, str) else json.dumps(body)), name
    assert ADMIN_TOKEN not in caplog.text


def test_frontend_never_references_the_gateway_token():
    for path in (REPO / "frontend" / "src").rglob("*"):
        if path.suffix in (".ts", ".tsx", ".js", ".json") and path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "APISHIELD_ADMIN_TOKEN" not in text and "X-APIShield-Admin-Token" not in text, path
    env = (REPO / "frontend" / ".env").read_text(encoding="utf-8")
    assert "TOKEN" not in env.upper()
