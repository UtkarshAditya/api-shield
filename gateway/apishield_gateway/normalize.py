"""Stage 1: canonicalise the request so later stages cannot be dodged by encoding tricks."""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from urllib.parse import parse_qsl, unquote, unquote_plus

from .context import Decision, RequestContext
from .spec import fallback_template

MAX_SCAN_CHARS = 262_144
_SLASHES = re.compile(r"/{2,}")


def decode_repeated(value: str, rounds: int = 3) -> str:
    """Percent-decode until stable, so %2527 (double encoding) still shows the quote."""
    for _ in range(rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def shape_of(value, depth: int = 0):
    """Field names and types only, never values."""
    if depth > 8:
        return "..."
    if isinstance(value, dict):
        return {str(k): shape_of(v, depth + 1) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, list):
        return sorted({json.dumps(shape_of(v, depth + 1), sort_keys=True) for v in value})
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return "null"


def shape_hash(query: dict, body) -> str:
    canonical = json.dumps({"q": sorted(query), "b": shape_of(body)}, sort_keys=True)
    return hashlib.sha1(canonical.encode()).hexdigest()[:16]


def _strings(value, out: list, budget: list) -> None:
    """Collect JSON keys and string values (decoded, so \\u003c becomes '<')."""
    if budget[0] <= 0:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            out.append(str(k))
            budget[0] -= len(str(k))
            _strings(v, out, budget)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out, budget)
    elif isinstance(value, str):
        out.append(value)
        budget[0] -= len(value)


class NormalizeStage:
    name = "normalize"

    def __init__(self, get_spec):
        self._get_spec = get_spec  # callable, so the spec can be swapped at runtime

    async def on_request(self, ctx: RequestContext):
        ctx.method = ctx.method.upper()
        decoded = decode_repeated(ctx.raw_path)
        if "\x00" in decoded:
            return Decision(400, "bad_request", "Malformed request path",
                            hit="normalize.null_byte", hard=True)
        ctx.decoded_path = decoded
        path = _SLASHES.sub("/", decoded.replace("\\", "/"))
        path = posixpath.normpath(path) if path else "/"
        ctx.path = path if path.startswith("/") else "/" + path

        query: dict = {}
        for key, value in parse_qsl(ctx.query_string, keep_blank_values=True):
            query.setdefault(key, []).append(value)
        ctx.query = query

        spec = self._get_spec()
        operation, template, params = spec.match(ctx.method, ctx.path) if spec else (None, None, {})
        ctx.operation = operation
        ctx.path_params = params
        ctx.path_template = template or fallback_template(ctx.path)

        ctype = ctx.header("content-type").split(";")[0].strip().lower()
        parts = [decoded]
        for key, values in query.items():
            parts.append(decode_repeated(key))
            parts.extend(decode_repeated(v) for v in values)
        if ctx.body:
            if ctype == "application/json" or ctype.endswith("+json"):
                try:
                    ctx.json = json.loads(ctx.body)
                except (ValueError, UnicodeDecodeError):
                    ctx.json_error = True
            if ctx.json is not None:
                _strings(ctx.json, parts, [MAX_SCAN_CHARS])
            else:
                text = ctx.body[:MAX_SCAN_CHARS].decode("utf-8", errors="replace")
                if ctype == "application/x-www-form-urlencoded":
                    text = decode_repeated(unquote_plus(text))
                parts.append(text)
        ctx.payload_text = "\n".join(parts)[:MAX_SCAN_CHARS]
        ctx.shape_hash = shape_hash(query, ctx.json)
        return None
