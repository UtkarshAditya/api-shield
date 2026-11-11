"""Stage 3: rate limiting with a token bucket per key / IP / endpoint."""
from __future__ import annotations

import logging
import math
import re
import time

from .config import LimitRule, Settings
from .context import Decision, RequestContext

log = logging.getLogger("apishield.ratelimit")

# Atomic refill-and-take. Returns {allowed (1/0), seconds until a token is free}.
TOKEN_BUCKET_LUA = """
local rate, burst, now = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens, ts = tonumber(state[1]), tonumber(state[2])
if tokens == nil then tokens = burst; ts = now end
tokens = math.min(burst, tokens + math.max(0, now - ts) * rate)
local allowed, retry = 0, 0
if tokens >= 1 then tokens = tokens - 1; allowed = 1 else retry = (1 - tokens) / rate end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', KEYS[1], math.ceil(burst / rate) + 1)
return {allowed, tostring(retry)}
"""


class MemoryBucketStore:
    """Same algorithm as the Lua script, for one process. Fallback when Redis is down."""

    def __init__(self):
        self._buckets: dict = {}

    async def take_many(self, checks: list, now: float | None = None) -> list:
        now = time.time() if now is None else now
        results = []
        for key, rate, burst in checks:
            tokens, ts = self._buckets.get(key, (burst, now))
            tokens = min(burst, tokens + max(0.0, now - ts) * rate)
            if tokens >= 1:
                results.append((True, 0.0))
                tokens -= 1
            else:
                results.append((False, (1 - tokens) / rate))
            self._buckets[key] = (tokens, now)
        if len(self._buckets) > 50_000:  # drop buckets that have refilled completely
            self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < 300}
        return results


class RedisBucketStore:
    """Token buckets in Redis, so limits hold across several gateway instances."""

    def __init__(self, client, prefix: str = "apishield:rl:"):
        self._client, self._prefix = client, prefix

    async def take_many(self, checks: list, now: float | None = None) -> list:
        now = time.time() if now is None else now
        pipe = self._client.pipeline(transaction=False)
        for key, rate, burst in checks:
            pipe.eval(TOKEN_BUCKET_LUA, 1, self._prefix + key, rate, burst, now)
        return [(int(allowed) == 1, float(retry)) for allowed, retry in await pipe.execute()]


def path_pattern(pattern: str) -> re.Pattern:
    """'/users/{id}' and '/admin/*' style patterns -> regex."""
    out = re.escape(pattern)
    out = re.sub(r"\\\{[^/]+?\\\}", "[^/]+", out)
    return re.compile("^" + out.replace(r"\*", ".*") + "/?$")


class RateLimitStage:
    name = "ratelimit"

    def __init__(self, settings: Settings, store):
        self.s = settings
        self.store = store
        self._limits = [(rule, path_pattern(rule.path) if rule.path else None)
                        for rule in settings.rate_limits]

    def _key(self, rule: LimitRule, ctx: RequestContext) -> str:
        if rule.scope == "ip":
            return f"{rule.id}:{ctx.ip}"
        if rule.scope == "endpoint":
            return f"{rule.id}:{ctx.caller}:{ctx.method} {ctx.path_template}"
        return f"{rule.id}:{ctx.caller}"

    async def on_request(self, ctx: RequestContext):
        checks, rules = [], []
        for rule, pattern in self._limits:
            if rule.method and rule.method.upper() not in ("*", ctx.method):
                continue
            if pattern and not (pattern.match(ctx.path) or rule.path == ctx.path_template):
                continue
            checks.append((self._key(rule, ctx), rule.rate, rule.capacity))
            rules.append(rule)
        if not checks:
            return None
        try:
            results = await self.store.take_many(checks)
        except Exception as exc:
            log.warning("rate limit backend error: %s", exc)
            if self.s.fail_open:
                ctx.hit("ratelimit.backend_error")
                return None
            return Decision(503, "rate_limiter_unavailable", "Rate limiter is unavailable",
                            hit="ratelimit.backend_error")
        for rule, (allowed, retry_after) in zip(rules, results):
            if not allowed:
                return too_many_requests(f"ratelimit.{rule.id}", retry_after)
        return None


def too_many_requests(hit: str, retry_after: float) -> Decision:
    seconds = max(1, math.ceil(retry_after))
    return Decision(429, "rate_limited", f"Too many requests. Retry in {seconds}s.",
                    hit=hit, headers={"Retry-After": str(seconds)})
