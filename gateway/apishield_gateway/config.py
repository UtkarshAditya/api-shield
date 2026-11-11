"""Gateway settings: a YAML file for structure, environment variables on top."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

GATEWAY_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = GATEWAY_DIR / "gateway.yaml"


@dataclass
class LimitRule:
    """One token bucket. `limit` requests per `per` seconds, bursts up to `burst`."""

    id: str
    scope: str = "caller"  # caller | ip | endpoint
    limit: float = 60
    per: float = 60
    burst: float | None = None
    method: str | None = None
    path: str | None = None

    @property
    def rate(self) -> float:
        return self.limit / self.per

    @property
    def capacity(self) -> float:
        return float(self.burst if self.burst is not None else self.limit)


@dataclass
class Settings:
    upstream_url: str = "http://127.0.0.1:8001"
    redis_url: str | None = "redis://127.0.0.1:6379/0"
    mode: str = "enforce"  # monitor (log only) | enforce (block)
    fail_open: bool = True
    upstream_timeout: float = 10.0
    max_body_bytes: int = 1_048_576
    trust_forwarded_for: bool = False
    admin_token: str | None = None

    openapi_spec: str | None = None
    rules_dir: str = str(GATEWAY_DIR / "rules")
    rules_reload_seconds: float = 2.0

    event_stream: str = "apishield:traffic"
    event_stream_maxlen: int = 100_000
    event_queue_size: int = 10_000

    # Auth
    api_key_header: str = "x-api-key"
    api_keys: dict = field(default_factory=dict)  # sha256(key) -> name
    jwt_secret: str | None = None
    jwt_algorithms: list = field(default_factory=lambda: ["HS256"])
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    enforce_spec_auth: bool = True

    rate_limits: list = field(default_factory=list)

    # Validation
    block_unknown_endpoints: bool = False

    # Response inspector
    inspector_mode: str = "mask"  # mask | alert | off
    inspector_max_bytes: int = 1_048_576
    inspector_detectors: dict = field(default_factory=lambda: {"secret.jwt": "alert"})
    inspector_allow: list = field(default_factory=list)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _bool(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _resolve(base: Path, value: str | None) -> str | None:
    if not value:
        return None
    p = Path(value).expanduser()
    return str(p if p.is_absolute() else (base / p).resolve())


def load_settings(path: str | os.PathLike | None = None, env: dict | None = None) -> Settings:
    """Read gateway.yaml (if it exists), then apply APISHIELD_* overrides."""
    env = os.environ if env is None else env
    path = Path(path or env.get("APISHIELD_CONFIG") or DEFAULT_CONFIG)
    raw: dict = {}
    if path.exists():
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    base = path.parent
    s = Settings()

    for name in (
        "upstream_url", "redis_url", "mode", "fail_open", "upstream_timeout", "max_body_bytes",
        "trust_forwarded_for", "admin_token", "rules_reload_seconds", "event_stream",
        "event_stream_maxlen", "event_queue_size", "block_unknown_endpoints",
    ):
        if name in raw:
            setattr(s, name, raw[name])
    if "openapi_spec" in raw:
        s.openapi_spec = _resolve(base, raw["openapi_spec"])
    if "rules_dir" in raw:
        s.rules_dir = _resolve(base, raw["rules_dir"])

    auth = raw.get("auth") or {}
    s.api_key_header = str(auth.get("api_key_header", s.api_key_header)).lower()
    for entry in auth.get("api_keys") or []:
        digest = entry.get("sha256") or hash_key(str(entry["key"]))
        s.api_keys[digest] = entry.get("name", "key")
    jwt_cfg = auth.get("jwt") or {}
    s.jwt_secret = jwt_cfg.get("secret", s.jwt_secret)
    s.jwt_algorithms = list(jwt_cfg.get("algorithms", s.jwt_algorithms))
    s.jwt_issuer = jwt_cfg.get("issuer", s.jwt_issuer)
    s.jwt_audience = jwt_cfg.get("audience", s.jwt_audience)
    s.enforce_spec_auth = bool(auth.get("enforce_spec_auth", s.enforce_spec_auth))

    for entry in raw.get("rate_limits") or []:
        match = entry.get("match") or {}
        s.rate_limits.append(
            LimitRule(
                id=str(entry["id"]),
                scope=entry.get("scope", "caller"),
                limit=float(entry.get("limit", 60)),
                per=float(entry.get("per", 60)),
                burst=float(entry["burst"]) if entry.get("burst") is not None else None,
                method=(match.get("method") or None),
                path=(match.get("path") or None),
            )
        )

    insp = raw.get("inspector") or {}
    s.inspector_mode = insp.get("mode", s.inspector_mode)
    s.inspector_max_bytes = int(insp.get("max_bytes", s.inspector_max_bytes))
    s.inspector_detectors = {**s.inspector_detectors, **(insp.get("detectors") or {})}
    s.inspector_allow = list(insp.get("allow") or [])

    # Environment overrides ("config via env")
    text = {
        "APISHIELD_UPSTREAM_URL": "upstream_url", "APISHIELD_REDIS_URL": "redis_url",
        "APISHIELD_MODE": "mode", "APISHIELD_ADMIN_TOKEN": "admin_token",
        "APISHIELD_JWT_SECRET": "jwt_secret", "APISHIELD_JWT_ISSUER": "jwt_issuer",
        "APISHIELD_JWT_AUDIENCE": "jwt_audience", "APISHIELD_EVENT_STREAM": "event_stream",
    }
    for var, name in text.items():
        if env.get(var) is not None:
            setattr(s, name, env[var] or None)
    if env.get("APISHIELD_OPENAPI_SPEC"):
        s.openapi_spec = _resolve(Path.cwd(), env["APISHIELD_OPENAPI_SPEC"])
    if env.get("APISHIELD_RULES_DIR"):
        s.rules_dir = _resolve(Path.cwd(), env["APISHIELD_RULES_DIR"])
    for var, name in (("APISHIELD_FAIL_OPEN", "fail_open"), ("APISHIELD_TRUST_FORWARDED_FOR", "trust_forwarded_for")):
        if env.get(var) is not None:
            setattr(s, name, _bool(env[var]))
    for pair in filter(None, (env.get("APISHIELD_API_KEYS") or "").split(",")):
        name, _, key = pair.partition(":")
        s.api_keys[hash_key(key.strip())] = name.strip()

    if s.mode not in ("monitor", "enforce"):
        raise ValueError(f"mode must be 'monitor' or 'enforce', got {s.mode!r}")
    s.upstream_url = s.upstream_url.rstrip("/")
    return s
