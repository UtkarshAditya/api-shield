"""Settings from environment variables. See README.md for the full list."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("apishield.admin")

REPO_ROOT = Path(__file__).resolve().parent.parent
_DEV_SALT = "dev-only-pseudo-salt"
_DEV_JWT_SECRET = "dev-only-admin-jwt-secret-change-me"


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass
class Config:
    database_url: str = "sqlite:///./admin_api.db"
    redis_url: str = ""                         # empty = no Redis, ingestion stays idle
    gateway_url: str = "http://localhost:8080"
    admin_token: str = ""                       # gateway control token, never leaves this process
    pseudo_salt: str = _DEV_SALT
    jwt_secret: str = _DEV_JWT_SECRET
    token_ttl_hours: int = 8
    demo_seed: bool = False
    auto_migrate: bool = True

    # The gateway protects one upstream; its events carry no upstream id, so they all go here.
    upstream_id: str = "up_shop"
    upstream_name: str = "Demo Shop API"
    upstream_url: str = "http://localhost:8001"  # scanned directly, never through the gateway
    openapi_spec: str = str(REPO_ROOT / "demo_api" / "openapi.json")

    event_stream: str = "apishield:traffic"
    consumer_group: str = "admin-api"
    consumer_name: str = "admin-api-1"
    recent_events: int = 2000

    scan_allowed_hosts: list = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    scan_username: str = "alice"
    scan_password: str = "alice123"

    cors_origins: list = field(default_factory=list)
    static_dir: str = ""                        # built dashboard (frontend/dist) to serve at /

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ.get
        cfg = cls(
            database_url=e("ADMIN_DATABASE_URL", cls.database_url),
            redis_url=e("APISHIELD_REDIS_URL", ""),
            gateway_url=e("APISHIELD_GATEWAY_URL", cls.gateway_url),
            admin_token=e("APISHIELD_ADMIN_TOKEN", ""),
            pseudo_salt=e("APISHIELD_PSEUDO_SALT", _DEV_SALT),
            jwt_secret=e("ADMIN_JWT_SECRET", _DEV_JWT_SECRET),
            token_ttl_hours=int(e("ADMIN_TOKEN_TTL_HOURS", "8")),
            demo_seed=_bool("DEMO_SEED", False),
            auto_migrate=_bool("ADMIN_AUTO_MIGRATE", True),
            upstream_id=e("APISHIELD_UPSTREAM_ID", cls.upstream_id),
            upstream_name=e("APISHIELD_UPSTREAM_NAME", cls.upstream_name),
            upstream_url=e("APISHIELD_UPSTREAM_URL", cls.upstream_url),
            openapi_spec=e("APISHIELD_OPENAPI_SPEC", cls.openapi_spec),
            event_stream=e("APISHIELD_EVENT_STREAM", cls.event_stream),
            consumer_name=e("ADMIN_CONSUMER_NAME", cls.consumer_name),
            scan_allowed_hosts=_list("APISHIELD_SCAN_ALLOWED_HOSTS", "localhost,127.0.0.1"),
            scan_username=e("APISHIELD_SCAN_USERNAME", cls.scan_username),
            scan_password=e("APISHIELD_SCAN_PASSWORD", cls.scan_password),
            cors_origins=_list("ADMIN_CORS_ORIGINS", ""),
            static_dir=e("ADMIN_STATIC_DIR", ""),
        )
        cfg.warn_insecure_defaults()
        return cfg

    def warn_insecure_defaults(self) -> None:
        if self.pseudo_salt == _DEV_SALT:
            log.warning("APISHIELD_PSEUDO_SALT is not set; using a dev-only salt. "
                        "Set the same value for the Admin API and the learner.")
        if self.jwt_secret == _DEV_JWT_SECRET:
            log.warning("ADMIN_JWT_SECRET is not set; using a dev-only secret.")
        if not self.admin_token:
            log.warning("APISHIELD_ADMIN_TOKEN is not set; rule and mode changes will fail.")
