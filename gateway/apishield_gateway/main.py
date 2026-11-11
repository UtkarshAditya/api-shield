"""APIShield gateway: an async reverse proxy with a protection pipeline.

    request pipeline:   normalize > auth > rate limit > validate > rules
    response pipeline:  secret-leak + error-leak inspection
    every request:      one traffic event to Redis Streams (non-blocking)
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .auth import AuthStage
from .config import Settings, load_settings
from .context import Decision, RequestContext
from .events import EventEmitter, MemorySink, RedisStreamSink, build_event
from .inspector import ResponseInspector
from .normalize import NormalizeStage
from .ratelimit import MemoryBucketStore, RateLimitStage, RedisBucketStore
from .rules import RuleSet, RulesStage
from .spec import ApiSpec, load_spec_file
from .validation import ValidationStage

log = logging.getLogger("apishield.gateway")

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
INTERNAL_PREFIX = "/_apishield"
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
              "trailers", "transfer-encoding", "upgrade"}
# Request headers the gateway sets itself instead of copying from the client.
REPLACED = {"host", "content-length", "accept-encoding", "x-request-id", "x-forwarded-for",
            "x-forwarded-host", "x-forwarded-proto"}


class Gateway:
    def __init__(self, settings: Settings, upstream_transport=None, redis_client=None,
                 event_sink=None, bucket_store=None):
        self.settings = settings
        self.mode = settings.mode
        self._transport = upstream_transport
        self._redis = redis_client
        self._sink = event_sink
        self._store = bucket_store
        self.spec: ApiSpec | None = None
        self.redis_ok = False
        self.ruleset = RuleSet(settings.rules_dir)
        self.inspector = ResponseInspector(settings)
        self._watcher: asyncio.Task | None = None

    # ---- lifecycle ----

    async def start(self) -> None:
        s = self.settings
        self.http = httpx.AsyncClient(
            transport=self._transport, timeout=s.upstream_timeout, follow_redirects=False,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
        if self._redis is None and s.redis_url and (self._store is None or self._sink is None):
            import redis.asyncio as aioredis

            client = aioredis.from_url(s.redis_url, decode_responses=True,
                                       socket_connect_timeout=1, socket_timeout=1)
            try:
                await client.ping()
                self._redis = client
            except Exception as exc:
                log.warning("Redis not reachable (%s). Falling back to in-memory rate limits "
                            "and events: fine for one local instance, not for production.", exc)
                await client.aclose()
        self.redis_ok = self._redis is not None
        if self._store is None:
            self._store = RedisBucketStore(self._redis) if self._redis else MemoryBucketStore()
        if self._sink is None:
            self._sink = (RedisStreamSink(self._redis, s.event_stream, s.event_stream_maxlen)
                          if self._redis else MemorySink())
        self.emitter = EventEmitter(self._sink, queue_size=s.event_queue_size)
        await self.emitter.start()

        await self._load_spec()
        self.ruleset.maybe_reload()
        if s.rules_reload_seconds > 0:
            self._watcher = asyncio.create_task(self.ruleset.watch(s.rules_reload_seconds))

        self.stages = [
            NormalizeStage(lambda: self.spec),
            AuthStage(s),
            RateLimitStage(s, self._store),
            ValidationStage(s),
            RulesStage(self.ruleset, self._store),
        ]
        log.info("gateway ready: upstream=%s mode=%s redis=%s rules=%d spec_operations=%d",
                 s.upstream_url, self.mode, self.redis_ok, len(self.ruleset.rules),
                 len(self.spec) if self.spec else 0)

    async def _load_spec(self) -> None:
        s = self.settings
        try:
            if s.openapi_spec:
                self.spec = ApiSpec(load_spec_file(s.openapi_spec))
            else:  # FastAPI-style upstreams publish their own spec
                resp = await self.http.get(s.upstream_url + "/openapi.json", timeout=3)
                if resp.status_code == 200:
                    self.spec = ApiSpec(resp.json())
        except Exception as exc:
            log.warning("no OpenAPI spec loaded (%s): validation and per-route auth are off", exc)

    async def stop(self) -> None:
        if self._watcher:
            self._watcher.cancel()
        await self.emitter.stop()
        await self.http.aclose()
        if self._redis is not None:
            await self._redis.aclose()

    # ---- request handling ----

    def _client_ip(self, request: Request) -> str:
        if self.settings.trust_forwarded_for:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "0.0.0.0"

    async def _read_body(self, request: Request) -> bytes | None:
        limit = self.settings.max_body_bytes
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            return None
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    async def _run_stages(self, ctx: RequestContext) -> Decision | None:
        for stage in self.stages:
            try:
                decision = await stage.on_request(ctx)
            except Exception:
                log.exception("stage %s failed", stage.name)
                if self.settings.fail_open:
                    ctx.hit(f"gateway.stage_error.{stage.name}")
                    continue
                ctx.hit(f"gateway.stage_error.{stage.name}", "block")
                return Decision(500, "gateway_error", "Gateway check failed",
                                hit=f"gateway.stage_error.{stage.name}")
            if decision is None:
                continue
            if self.mode == "monitor" and not decision.hard:
                ctx.hit(decision.hit, "log")  # monitor mode: record what would have happened
                continue
            ctx.hit(decision.hit, decision.action)
            return decision
        return None

    def _finish(self, ctx: RequestContext, status: int, resp_size: int) -> None:
        latency_ms = (time.perf_counter() - ctx.started) * 1000
        self.emitter.emit(build_event(ctx, status, resp_size, latency_ms))

    def _gateway_headers(self, ctx: RequestContext) -> list:
        total = (time.perf_counter() - ctx.started) * 1000
        timing = f"apishield;dur={max(total - ctx.upstream_ms, 0):.2f}, upstream;dur={ctx.upstream_ms:.2f}"
        return [("x-request-id", ctx.req_id), ("server-timing", timing)]

    def _reject(self, ctx: RequestContext, decision: Decision) -> Response:
        body = {"error": {"code": decision.code, "message": decision.message}, "request_id": ctx.req_id}
        response = JSONResponse(body, status_code=decision.status,
                                headers={**decision.headers, **dict(self._gateway_headers(ctx))})
        self._finish(ctx, decision.status, len(response.body))
        return response

    async def handle(self, request: Request) -> Response:
        headers: dict = {}
        for key, value in request.headers.items():
            key = key.lower()
            headers[key] = f"{headers[key]}, {value}" if key in headers else value
        raw_path = request.scope.get("raw_path") or request.url.path.encode()
        ctx = RequestContext(
            method=request.method, raw_path=raw_path.decode("latin-1").split("?", 1)[0],
            query_string=request.url.query, headers=headers, ip=self._client_ip(request),
        )
        body = await self._read_body(request)
        if body is None:
            ctx.caller = f"ip_{ctx.ip}"
            decision = Decision(413, "payload_too_large",
                                f"Request body exceeds {self.settings.max_body_bytes} bytes",
                                hit="validation.body_too_large", hard=True)
            ctx.hit(decision.hit, decision.action)
            return self._reject(ctx, decision)
        ctx.body = body

        decision = await self._run_stages(ctx)
        if decision is not None:
            return self._reject(ctx, decision)
        return await self._forward(ctx, request)

    async def _forward(self, ctx: RequestContext, request: Request) -> Response:
        s = self.settings
        dropped = HOP_BY_HOP | REPLACED | {
            h.strip().lower() for h in ctx.header("connection").split(",") if h.strip()
        }
        out_headers = [(k, v) for k, v in request.headers.items() if k.lower() not in dropped]
        out_headers += [
            ("x-request-id", ctx.req_id),
            ("x-forwarded-for", ctx.ip),
            ("x-forwarded-host", ctx.header("host")),
            ("x-forwarded-proto", request.url.scheme),
        ]
        if s.inspector_mode != "off":
            out_headers.append(("accept-encoding", "identity"))  # so responses can be inspected
        elif ctx.header("accept-encoding"):
            out_headers.append(("accept-encoding", ctx.header("accept-encoding")))
        url = s.upstream_url + ctx.raw_path + (f"?{ctx.query_string}" if ctx.query_string else "")

        sent = time.perf_counter()
        try:
            upstream = await self.http.send(
                self.http.build_request(ctx.method, url, headers=out_headers, content=ctx.body),
                stream=True,
            )
        except httpx.TimeoutException:
            ctx.hit("gateway.upstream_timeout")
            return self._reject(ctx, Decision(504, "upstream_timeout", "Upstream API timed out",
                                              hit="gateway.upstream_timeout", action="log"))
        except httpx.HTTPError:
            ctx.hit("gateway.upstream_unreachable")
            return self._reject(ctx, Decision(502, "upstream_unreachable", "Upstream API is not reachable",
                                              hit="gateway.upstream_unreachable", action="log"))
        ctx.upstream_ms = (time.perf_counter() - sent) * 1000

        up = upstream.headers
        resp_headers = [(k.lower(), v) for k, v in up.multi_items()
                        if k.lower() not in HOP_BY_HOP and k.lower() not in ("content-length", "x-request-id")]
        ctype = up.get("content-type", "")
        buffered: bytes | None = None
        chunks: list = []
        stream = upstream.aiter_raw()

        if ctx.method != "HEAD" and self.inspector.wants(ctype, up.get("content-encoding", ""),
                                                         up.get("content-length")):
            size, overflow = 0, False
            async for chunk in stream:
                chunks.append(chunk)
                size += len(chunk)
                if size > s.inspector_max_bytes:
                    overflow = True  # too big to hold in memory: pass through uninspected
                    break
            if not overflow:
                ctx.upstream_ms = (time.perf_counter() - sent) * 1000
                await upstream.aclose()
                buffered = self.inspector.inspect(ctx, b"".join(chunks), ctype,
                                                  may_mask=self.mode == "enforce")

        if buffered is not None:
            response = Response(content=buffered, status_code=upstream.status_code)
            resp_headers += [("content-length", str(len(buffered)))] + self._gateway_headers(ctx)
            response.raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in resp_headers]
            self._finish(ctx, upstream.status_code, len(buffered))
            return response

        async def passthrough():
            sent_bytes = 0
            try:
                for chunk in chunks:
                    sent_bytes += len(chunk)
                    yield chunk
                async for chunk in stream:
                    sent_bytes += len(chunk)
                    yield chunk
            finally:
                await upstream.aclose()
                self._finish(ctx, upstream.status_code, sent_bytes)

        if up.get("content-length"):
            resp_headers.append(("content-length", up["content-length"]))
        resp_headers += self._gateway_headers(ctx)
        response = StreamingResponse(passthrough(), status_code=upstream.status_code)
        response.raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in resp_headers]
        return response


def create_app(settings: Settings | None = None, *, upstream_transport=None, redis_client=None,
               event_sink=None, bucket_store=None) -> FastAPI:
    """Build the gateway app. The keyword arguments let tests swap in a fake upstream,
    Redis client, event sink or bucket store."""
    settings = settings or load_settings()
    gw = Gateway(settings, upstream_transport, redis_client, event_sink, bucket_store)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await gw.start()
        yield
        await gw.stop()

    app = FastAPI(title="APIShield Gateway", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.gateway = gw

    def require_admin(request: Request) -> None:
        token = settings.admin_token
        if not token:  # control endpoints stay hidden until a token is configured
            raise HTTPException(404, "Not found")
        if not hmac.compare_digest(request.headers.get("x-apishield-admin-token", ""), token):
            raise HTTPException(401, "Invalid admin token")

    # ---- control endpoints (for the Admin API / scanner, not for API clients) ----

    @app.get(INTERNAL_PREFIX + "/health")
    async def health():
        return {
            "status": "ok", "mode": gw.mode, "upstream": settings.upstream_url,
            "redis": gw.redis_ok, "rules": len(gw.ruleset.rules),
            "rule_errors": gw.ruleset.errors, "spec_operations": len(gw.spec) if gw.spec else 0,
            "events_dropped": gw.emitter.dropped + gw.emitter.failed,
        }

    @app.get(INTERNAL_PREFIX + "/rules")
    async def list_rules(request: Request):
        require_admin(request)
        return {"rules": [{**r.to_dict(), "hits": r.hits} for r in gw.ruleset.rules],
                "errors": gw.ruleset.errors}

    @app.post(INTERNAL_PREFIX + "/rules")
    async def upsert_rules(request: Request):
        require_admin(request)
        payload = await request.json()
        entries = payload.get("rules", [payload]) if isinstance(payload, dict) else payload
        try:
            saved = gw.ruleset.upsert(list(entries))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"saved": saved}

    @app.delete(INTERNAL_PREFIX + "/rules/{rule_id}")
    async def delete_rule(rule_id: str, request: Request):
        require_admin(request)
        if not gw.ruleset.remove(rule_id):
            raise HTTPException(404, "No runtime rule with that id (file-based rules are edited on disk)")
        return {"removed": rule_id}

    @app.post(INTERNAL_PREFIX + "/reload")
    async def reload_rules(request: Request):
        require_admin(request)
        return {"reloaded": gw.ruleset.maybe_reload(), "rules": len(gw.ruleset.rules),
                "errors": gw.ruleset.errors}

    @app.put(INTERNAL_PREFIX + "/mode")
    async def set_mode(request: Request):
        require_admin(request)
        mode = (await request.json()).get("mode")
        if mode not in ("monitor", "enforce"):
            raise HTTPException(400, "mode must be 'monitor' or 'enforce'")
        gw.mode = mode
        return {"mode": gw.mode}

    # ---- everything else is proxied ----

    @app.api_route("/{full_path:path}", methods=METHODS)
    async def proxy(request: Request):
        if request.url.path.startswith(INTERNAL_PREFIX):
            raise HTTPException(404, "Not found")
        return await gw.handle(request)

    return app
