import asyncio
import json
import time

import httpx

from gateway.apishield_gateway.config import Settings
from gateway.apishield_gateway.context import RequestContext
from gateway.apishield_gateway.events import MemorySink
from gateway.apishield_gateway.main import create_app
from gateway.apishield_gateway.normalize import NormalizeStage


def run(coro):
    return asyncio.run(coro)


def make_ctx(method="GET", path="/", query="", headers=None, body=b"", ip="10.0.0.1",
             json_body=None, spec=None):
    """Build a request context that has already been through the normalize stage."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    if json_body is not None:
        body = json.dumps(json_body).encode()
        headers.setdefault("content-type", "application/json")
    ctx = RequestContext(method=method, raw_path=path, query_string=query, headers=headers,
                         ip=ip, body=body)
    decision = run(NormalizeStage(lambda: spec).on_request(ctx))
    ctx.caller = f"ip_{ip}"
    return ctx if decision is None else decision


def make_gateway(tmp_path, upstream_app, settings=None, **overrides):
    """Gateway app wired to an in-process upstream, in-memory limits and an event list."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    settings = settings or Settings(inspector_detectors={})
    settings.redis_url = None
    settings.rules_reload_seconds = 0
    if "rules_dir" not in overrides:
        settings.rules_dir = str(rules_dir)
    for key, value in overrides.items():
        setattr(settings, key, value)
    sink = MemorySink()
    app = create_app(settings, upstream_transport=httpx.ASGITransport(app=upstream_app),
                     event_sink=sink)
    return app, sink


def wait_for_events(sink, count=1, timeout=2.0):
    deadline = time.time() + timeout
    while len(sink.events) < count and time.time() < deadline:
        time.sleep(0.01)
    return list(sink.events)
