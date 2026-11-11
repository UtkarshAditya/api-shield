"""Response pipeline: detect leaked secrets and error details, then mask or alert."""
from __future__ import annotations

import json
import re

from .config import Settings
from .context import RequestContext
from .ratelimit import path_pattern

# Secrets are cut out of the surrounding text.
SECRET_PATTERNS = [
    ("secret.api_key", re.compile(
        r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}"          # Stripe-style
        r"|\bAKIA[0-9A-Z]{16}\b"                                   # AWS access key ID
        r"|\bAIza[0-9A-Za-z_\-]{35}\b"                             # Google API key
        r"|\bgh[pousr]_[0-9A-Za-z]{36,}\b"                         # GitHub token
        r"|\bxox[baprs]-[0-9A-Za-z-]{10,}")),                      # Slack token
    ("secret.jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
]
# These poison the whole value they appear in, so the whole value is replaced.
WHOLE_VALUE_PATTERNS = [
    ("secret.private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("error.stack_trace", re.compile(
        r"Traceback \(most recent call last\)"
        r"|File \"[^\"\n]+\", line \d+"
        r"|\bat [\w$.<>]+\([\w$]+\.(?:java|kt|scala|groovy):\d+\)"
        r"|Exception in thread \""
        r"|\bat [^\n()]{0,120}\(?(?:/|[A-Za-z]:\\|file://|node:)[^\s()]+:\d+:\d+\)?"
        r"|\bat [\w.<>]+\([^)\n]*\) in [^\n]+:line \d+"
        r"|goroutine \d+ \[running\]"
        r"|PHP (?:Fatal|Parse) error|Stack trace:\s*#0")),
    ("error.sql", re.compile(
        r"sqlite3\.\w*Error|near \"[^\"\n]*\": syntax error|unrecognized token"
        r"|no such (?:table|column)|You have an error in your SQL syntax|ORA-\d{5}"
        r"|psycopg2\.\w+|syntax error at or near|SQLSTATE\[|Unclosed quotation mark",
        re.IGNORECASE)),
]
ALL_DETECTORS = [name for name, _ in SECRET_PATTERNS + WHOLE_VALUE_PATTERNS]
_TEXTUAL = ("json", "text/", "xml", "javascript", "x-www-form-urlencoded")


def placeholder(detector: str) -> str:
    return f"[REDACTED:{detector.split('.', 1)[1]}]"


class ResponseInspector:
    def __init__(self, settings: Settings):
        self.s = settings
        self._allow = []
        for entry in settings.inspector_allow:
            self._allow.append((
                path_pattern(str(entry["path"])) if entry.get("path") else None,
                str(entry["method"]).upper() if entry.get("method") else None,
                set(entry.get("detectors") or ALL_DETECTORS),
            ))

    def wants(self, content_type: str, content_encoding: str, content_length: str | None) -> bool:
        if self.s.inspector_mode == "off":
            return False
        if content_encoding and content_encoding.lower() != "identity":
            return False
        if content_length and content_length.isdigit() and int(content_length) > self.s.inspector_max_bytes:
            return False
        return any(marker in content_type.lower() for marker in _TEXTUAL)

    def _plan(self, ctx: RequestContext, may_mask: bool) -> dict:
        """detector -> 'mask' | 'alert' for this request (allow-listed detectors are absent)."""
        skipped = set()
        for pattern, method, detectors in self._allow:
            if (method is None or method == ctx.method) and (pattern is None or pattern.match(ctx.path)):
                skipped |= detectors
        plan = {}
        for name in ALL_DETECTORS:
            mode = self.s.inspector_detectors.get(name, "mask")
            if name in skipped or mode == "off":
                continue
            plan[name] = "mask" if (mode == "mask" and may_mask and self.s.inspector_mode == "mask") else "alert"
        return plan

    def _scan(self, text: str, plan: dict, found: set) -> str:
        for name, pattern in WHOLE_VALUE_PATTERNS:
            if name in plan and pattern.search(text):
                found.add(name)
                if plan[name] == "mask":
                    return placeholder(name)
        for name, pattern in SECRET_PATTERNS:
            if name in plan and pattern.search(text):
                found.add(name)
                if plan[name] == "mask":
                    text = pattern.sub(placeholder(name), text)
        return text

    def _walk(self, value, plan: dict, found: set):
        if isinstance(value, str):
            return self._scan(value, plan, found)
        if isinstance(value, dict):
            return {k: self._walk(v, plan, found) for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(v, plan, found) for v in value]
        return value

    def inspect(self, ctx: RequestContext, body: bytes, content_type: str, may_mask: bool = True) -> bytes:
        """Return the body to send to the client. Records a `resp.<detector>` hit per finding."""
        if not body:
            return body
        plan = self._plan(ctx, may_mask)
        if not plan:
            return body
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body
        patterns = [p for name, p in SECRET_PATTERNS + WHOLE_VALUE_PATTERNS if name in plan]
        found: set = set()
        out = None
        if "json" in content_type.lower():
            try:  # scan decoded string values, so escapes like \n or \u003c cannot hide anything
                out = json.dumps(self._walk(json.loads(text), plan, found), ensure_ascii=False)
            except ValueError:
                out = None
        if out is None:
            if not any(p.search(text) for p in patterns):  # fast path: nothing to report
                return body
            out = self._scan(text, plan, found)
            if out in {placeholder(n) for n, _ in WHOLE_VALUE_PATTERNS}:
                out += " Response removed by APIShield because it exposed internal details."
        for name in sorted(found):
            ctx.hit(f"resp.{name}", "log")
        if not any(plan[name] == "mask" for name in found):
            return body
        return out.encode("utf-8")
