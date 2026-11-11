"""Stage 5: rule engine. Signature and condition based rules loaded from YAML/JSON,
with hot reload. Rule shape: {id, match{...}, action, source, expires_at}."""
from __future__ import annotations

import ast
import asyncio
import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import yaml

from .context import Decision, RequestContext
from .ratelimit import path_pattern, too_many_requests

log = logging.getLogger("apishield.rules")

ACTIONS = ("allow", "log", "block", "throttle", "challenge")
# Friendlier names other components may send; mapped onto the five real actions.
ACTION_ALIASES = {"require_auth": "challenge", "deny": "block", "rate_limit": "throttle"}
SOURCES = ("builtin", "scanner", "analyst", "learner")
DYNAMIC_FILE = "dynamic.json"
_I = re.IGNORECASE | re.MULTILINE

SIGNATURES: dict = {
    "sqli": [
        r"(?:'|\"|\b\d+)\s*(?:or|and)\s*(?:'[^'\n]*'|\"[^\"\n]*\"|\d+)\s*(?:=|like)\s*(?:'|\"|\d)",
        r"\bunion\b(?:\s+all)?\s+select\b",
        r";\s*(?:drop|delete|insert|update|alter|create|truncate)\s",
        r"['\"]\s*(?:--(?:\s|$)|/\*)|'\s*#\s*$",
        r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d",
        r"\bwaitfor\s+delay\b",
        r"\b(?:information_schema|sqlite_master|pg_catalog)\b",
    ],
    "nosqli": [
        r"\$(?:where|ne|gt|gte|lt|lte|in|nin|regex|exists|or|and|not|nor|expr|function)\b",
    ],
    "xss": [
        r"<\s*script\b",
        r"javascript\s*:",
        r"<[^>\n]{0,200}\bon(?:error|load|click|mouseover|focus|toggle|start|begin|animation\w*)\s*=",
        r"<\s*(?:iframe|object|embed|svg|math)\b",
        r"\bdocument\s*\.\s*(?:cookie|location|write)\b",
    ],
    "path_traversal": [
        r"(?:^|[\\/])\.\.(?:[\\/]|$)",
        r"/etc/(?:passwd|shadow|hosts)\b",
        r"[\\/]proc[\\/]self[\\/]",
        r"\b(?:boot|win)\.ini\b",
    ],
    "bad_user_agent": [
        r"sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|zgrab|havij|"
        r"hydra|metasploit|nuclei|ffuf|wfuzz|burpsuite|openvas",
    ],
}
_COMPILED = {name: [re.compile(p, _I) for p in pats] for name, pats in SIGNATURES.items()}


# ---- Conditions: a small, safe expression language (no eval) ---------------------

@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


_FUNCS = {
    "len": lambda v: len(v) if v is not None else 0,
    "contains": lambda a, b: b is not None and a is not None and b in a,
    "matches": lambda s, pattern: s is not None and _regex(pattern).search(str(s)) is not None,
    "startswith": lambda s, p: isinstance(s, str) and s.startswith(p),
    "endswith": lambda s, p: isinstance(s, str) and s.endswith(p),
    "lower": lambda s: s.lower() if isinstance(s, str) else s,
}
_NAMES = ("method", "path", "path_template", "ip", "caller", "authenticated", "req_size",
          "content_type", "user_agent", "query", "header", "body", "claims", "payload")
_LITERALS = {"true": True, "false": False, "null": None}
_ALLOWED = (ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub, ast.Compare, ast.Eq,
            ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Name, ast.Load,
            ast.Constant, ast.Subscript, ast.Attribute, ast.Call, ast.List, ast.Tuple)
_COMPARE = {
    ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b, ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
    ast.In: lambda a, b: b is not None and a in b,
    ast.NotIn: lambda a, b: b is None or a not in b,
}


class Condition:
    """Examples:  req_size > 10000
                  method == 'POST' and not authenticated
                  matches(query['q'], 'admin') or header['x-debug'] == '1'"""

    def __init__(self, source: str):
        self.source = source
        try:
            self._tree = ast.parse(source.strip(), mode="eval").body
        except SyntaxError as exc:
            raise ValueError(f"bad condition: {exc.msg}") from None
        for node in ast.walk(self._tree):
            if not isinstance(node, _ALLOWED):
                raise ValueError(f"bad condition: '{type(node).__name__}' is not allowed")
            if isinstance(node, ast.Name) and node.id not in _NAMES + tuple(_FUNCS) + tuple(_LITERALS):
                raise ValueError(f"bad condition: unknown name '{node.id}'")
            if isinstance(node, ast.Call) and not (
                isinstance(node.func, ast.Name) and node.func.id in _FUNCS and not node.keywords
            ):
                raise ValueError("bad condition: only len, contains, matches, startswith, "
                                 "endswith and lower can be called")

    def evaluate(self, ctx: RequestContext) -> bool:
        env = {
            "method": ctx.method, "path": ctx.path, "path_template": ctx.path_template,
            "ip": ctx.ip, "caller": ctx.caller, "authenticated": ctx.authenticated,
            "req_size": len(ctx.body), "content_type": ctx.header("content-type"),
            "user_agent": ctx.header("user-agent"), "header": ctx.headers,
            "query": {k: v[-1] for k, v in ctx.query.items()},
            "body": ctx.json, "claims": ctx.claims, "payload": ctx.payload_text,
        }
        try:
            return bool(self._eval(self._tree, env))
        except Exception:  # a type mismatch (e.g. None > 5) just means "no match"
            return False

    def _eval(self, node, env):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return _LITERALS[node.id] if node.id in _LITERALS else env[node.id]
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self._eval(e, env) for e in node.elts]
        if isinstance(node, ast.BoolOp):
            values = (self._eval(v, env) for v in node.values)
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp):
            value = self._eval(node.operand, env)
            return (not value) if isinstance(node.op, ast.Not) else -value
        if isinstance(node, ast.Compare):
            left = self._eval(node.left, env)
            for op, right_node in zip(node.ops, node.comparators):
                right = self._eval(right_node, env)
                if not _COMPARE[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            container = self._eval(node.value, env)
            key = node.attr if isinstance(node, ast.Attribute) else self._eval(node.slice, env)
            if isinstance(container, dict):
                return container.get(key)
            if isinstance(container, (list, str)) and isinstance(key, int) and -len(container) <= key < len(container):
                return container[key]
            return None
        if isinstance(node, ast.Call):
            return _FUNCS[node.func.id](*(self._eval(a, env) for a in node.args))
        raise ValueError("unsupported expression")


# ---- Rules --------------------------------------------------------------------

def _parse_time(value) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _as_list(value) -> list:
    return list(value) if isinstance(value, (list, tuple)) else [value]


@dataclass
class Rule:
    id: str
    action: str
    match: dict
    name: str = ""
    enabled: bool = True
    source: str = "analyst"
    expires_at: str | None = None
    priority: int = 100
    throttle: dict = field(default_factory=dict)
    hits: int = 0

    def __post_init__(self):
        m = self.match
        self._expires = _parse_time(self.expires_at)
        self._path = path_pattern(str(m["path"])) if m.get("path") else None
        self._methods = {str(x).upper() for x in _as_list(m["method"])} if m.get("method") else None
        if self._methods and "*" in self._methods:
            self._methods = None
        self._nets = [ipaddress.ip_network(str(x), strict=False) for x in _as_list(m["ip"])] if m.get("ip") else None
        self._headers = {str(k).lower(): re.compile(str(v), re.IGNORECASE)
                         for k, v in (m.get("header") or {}).items()}
        self._sig_name = m.get("signature")
        self._sig = None
        if self._sig_name:
            if str(self._sig_name).startswith("regex:"):
                self._sig = [re.compile(self._sig_name[6:], _I)]
            elif self._sig_name in _COMPILED:
                self._sig = _COMPILED[self._sig_name]
            else:
                raise ValueError(f"unknown signature '{self._sig_name}' "
                                 f"(use one of {', '.join(SIGNATURES)} or 'regex:<pattern>')")
        self._condition = Condition(str(m["condition"])) if m.get("condition") else None

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        if not isinstance(data, dict) or not data.get("id"):
            raise ValueError("rule needs an 'id'")
        action = ACTION_ALIASES.get(str(data.get("action")), str(data.get("action")))
        if action not in ACTIONS:
            raise ValueError(f"rule {data['id']}: action must be one of {', '.join(ACTIONS)}")
        match = data.get("match")
        known = ("path", "method", "ip", "header", "signature", "condition")
        if not isinstance(match, dict) or not any(match.get(k) for k in known):
            raise ValueError(f"rule {data['id']}: 'match' needs at least one of {', '.join(known)}")
        try:
            return cls(
                id=str(data["id"]), action=action, match={k: match[k] for k in known if match.get(k)},
                name=str(data.get("name") or data["id"]), enabled=bool(data.get("enabled", True)),
                source=str(data.get("source", "analyst")),
                expires_at=str(data["expires_at"]) if data.get("expires_at") else None,
                priority=int(data.get("priority", 100)), throttle=dict(data.get("throttle") or {}),
            )
        except (re.error, TypeError) as exc:
            raise ValueError(f"rule {data['id']}: {exc}") from None
        except ValueError as exc:
            raise ValueError(f"rule {data['id']}: {exc}") from None

    def to_dict(self) -> dict:
        out = {"id": self.id, "name": self.name, "enabled": self.enabled, "match": self.match,
               "action": self.action, "source": self.source, "priority": self.priority}
        if self.expires_at:
            out["expires_at"] = self.expires_at
        if self.throttle:
            out["throttle"] = self.throttle
        return out

    def expired(self, now: datetime) -> bool:
        return self._expires is not None and now >= self._expires

    def matches(self, ctx: RequestContext) -> bool:
        """Every field present in `match` must hold (AND)."""
        if self._methods and ctx.method not in self._methods:
            return False
        if self._path and not (self._path.match(ctx.path) or self.match["path"] == ctx.path_template):
            return False
        if self._nets:
            try:
                address = ipaddress.ip_address(ctx.ip)
            except ValueError:
                return False
            if not any(address in net for net in self._nets):
                return False
        for name, pattern in self._headers.items():
            if not pattern.search(ctx.headers.get(name, "")):
                return False
        if self._sig:
            target = ctx.header("user-agent") if self._sig_name == "bad_user_agent" else ctx.payload_text
            if not any(p.search(target) for p in self._sig):
                return False
        if self._condition and not self._condition.evaluate(ctx):
            return False
        return True


class RuleSet:
    """Loads every .yaml/.yml/.json file in a directory and reloads when one changes.
    A file that fails to parse keeps its last good rules; a bad rule is skipped."""

    def __init__(self, rules_dir: str | os.PathLike):
        self.dir = Path(rules_dir)
        self.rules: list = []
        self.errors: list = []
        self._files: dict = {}  # path -> (fingerprint, [Rule])
        self._fingerprint = None

    def _scan(self) -> dict:
        found = {}
        if self.dir.is_dir():
            for p in sorted(self.dir.iterdir()):
                if p.suffix.lower() in (".yaml", ".yml", ".json") and p.is_file():
                    st = p.stat()
                    found[p] = (st.st_mtime_ns, st.st_size)
        return found

    def maybe_reload(self) -> bool:
        """Reload if any rule file was added, removed or modified. Returns True if so."""
        found = self._scan()
        if found == self._fingerprint:
            return False
        self._fingerprint = found
        errors, files = [], {}
        for path, fp in found.items():
            cached = self._files.get(path)
            if cached and cached[0] == fp:
                files[path] = cached
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f) if path.suffix.lower() == ".json" else yaml.safe_load(f)
            except Exception as exc:
                errors.append(f"{path.name}: {exc}")
                files[path] = (fp, cached[1] if cached else [])  # keep the last good version
                continue
            entries = data.get("rules", []) if isinstance(data, dict) else (data or [])
            loaded = []
            for entry in entries:
                try:
                    loaded.append(Rule.from_dict(entry))
                except ValueError as exc:
                    errors.append(f"{path.name}: {exc}")
            files[path] = (fp, loaded)
        self._files = files
        by_id: dict = {}
        old_hits = {r.id: r.hits for r in self.rules}
        for path in found:  # later files override earlier ones with the same id
            for rule in files[path][1]:
                rule.hits = old_hits.get(rule.id, rule.hits)
                by_id[rule.id] = rule
        self.rules = sorted(by_id.values(), key=lambda r: r.priority)  # atomic swap
        self.errors = errors
        for error in errors:
            log.warning("rule load error: %s", error)
        log.info("loaded %d rules from %s", len(self.rules), self.dir)
        return True

    async def watch(self, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                self.maybe_reload()
            except Exception:
                log.exception("rule reload failed; keeping current rules")

    # -- rules pushed at runtime (scanner suggestions, dashboard edits) --

    def _read_dynamic(self) -> list:
        path = self.dir / DYNAMIC_FILE
        if not path.exists():
            return []
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("rules", []) if isinstance(data, dict) else data

    def _write_dynamic(self, rules: list) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / (DYNAMIC_FILE + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"rules": rules}, f, indent=2)
        os.replace(tmp, self.dir / DYNAMIC_FILE)
        self.maybe_reload()

    def upsert(self, entries: list) -> list:
        """Validate, then add or replace rules by id. Raises ValueError on a bad rule."""
        validated = [Rule.from_dict(e).to_dict() for e in entries]
        current = {r["id"]: r for r in self._read_dynamic()}
        for rule in validated:
            current[rule["id"]] = rule
        self._write_dynamic(list(current.values()))
        return validated

    def remove(self, rule_id: str) -> bool:
        current = self._read_dynamic()
        kept = [r for r in current if r.get("id") != rule_id]
        if len(kept) == len(current):
            return False
        self._write_dynamic(kept)
        return True


class RulesStage:
    name = "rules"

    def __init__(self, ruleset: RuleSet, store):
        self.ruleset = ruleset
        self.store = store

    async def on_request(self, ctx: RequestContext):
        now = datetime.now(timezone.utc)
        for rule in self.ruleset.rules:
            if not rule.enabled or rule.expired(now) or not rule.matches(ctx):
                continue
            if rule.action == "allow":  # allow-list entry: skip the remaining rules
                rule.hits += 1
                ctx.hit(rule.id, "allow")
                return None
            if rule.action == "log":
                rule.hits += 1
                ctx.hit(rule.id, "log")
                continue
            if rule.action == "block":
                rule.hits += 1
                return Decision(403, "blocked_by_rule", "Request blocked by a security rule", hit=rule.id)
            if rule.action == "challenge":  # prove who you are: valid credentials pass
                if ctx.authenticated or ctx.auth_method == "jwt_unverified":
                    continue
                rule.hits += 1
                return Decision(401, "auth_required", "This endpoint requires authentication",
                                hit=rule.id, action="challenge", headers={"WWW-Authenticate": "Bearer"})
            if rule.action == "throttle":
                limit = float(rule.throttle.get("limit", 5))
                per = float(rule.throttle.get("per", 60))
                burst = float(rule.throttle.get("burst", limit))
                key = f"rule:{rule.id}:{ctx.caller}"
                (allowed, retry_after), = await self.store.take_many([(key, limit / per, burst)])
                if not allowed:
                    rule.hits += 1
                    decision = too_many_requests(rule.id, retry_after)
                    decision.action = "throttle"
                    return decision
        return None
