"""Environment-backed settings for the M3 learning engine."""

from __future__ import annotations

import hashlib
import logging
import os
import socket
from dataclasses import dataclass, field
from typing import Mapping

_DEV_PSEUDO_SALT = "dev-only-pseudo-salt"
log = logging.getLogger("apishield.learning.config")


class ConfigurationError(ValueError):
    """Raised when an M3 setting is malformed or required configuration is absent."""


@dataclass(frozen=True)
class LearningConfig:
    """Redis and privacy settings for one M3 consumer process."""

    redis_url: str = "redis://127.0.0.1:6379/0"
    event_stream: str = "apishield:traffic"
    consumer_group: str = "learner"
    consumer_name: str = field(
        default_factory=lambda: f"{socket.gethostname()}-{os.getpid()}"
    )
    pseudo_salt: str = _DEV_PSEUDO_SALT
    batch_size: int = 100
    block_ms: int = 1000
    dead_letter_stream: str = "apishield:m3:dead-letter"
    dead_letter_maxlen: int = 10_000
    max_delivery_attempts: int = 5
    min_idle_ms: int = 30_000

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LearningConfig:
        """Load settings, allowing a mapping to be supplied for deterministic tests."""
        values = os.environ if env is None else env
        if "APISHIELD_PSEUDO_SALT" not in values:
            log.warning(
                "APISHIELD_PSEUDO_SALT is not set; using the shared development-only salt"
            )

        def positive_int(name: str, default: int, *, allow_zero: bool = False) -> int:
            raw = values.get(name)
            if raw is None:
                return default
            try:
                parsed = int(raw)
            except ValueError as exc:
                raise ConfigurationError(f"{name} must be an integer") from exc
            lower_bound = 0 if allow_zero else 1
            if parsed < lower_bound:
                qualifier = "non-negative" if allow_zero else "positive"
                raise ConfigurationError(f"{name} must be {qualifier}")
            return parsed

        config = cls(
            redis_url=values.get(
                "APISHIELD_REDIS_URL", "redis://127.0.0.1:6379/0"
            ),
            event_stream=values.get("APISHIELD_EVENT_STREAM", "apishield:traffic"),
            consumer_group=values.get(
                "APISHIELD_LEARNING_CONSUMER_GROUP", "learner"
            ),
            consumer_name=values.get(
                "APISHIELD_LEARNING_CONSUMER_NAME",
                f"{socket.gethostname()}-{os.getpid()}",
            ),
            pseudo_salt=values.get("APISHIELD_PSEUDO_SALT", _DEV_PSEUDO_SALT),
            batch_size=positive_int("APISHIELD_LEARNING_BATCH_SIZE", 100),
            block_ms=positive_int("APISHIELD_LEARNING_BLOCK_MS", 1000, allow_zero=True),
            dead_letter_stream=values.get(
                "APISHIELD_LEARNING_DEAD_LETTER_STREAM",
                "apishield:m3:dead-letter",
            ),
            dead_letter_maxlen=positive_int(
                "APISHIELD_LEARNING_DEAD_LETTER_MAXLEN", 10_000
            ),
            max_delivery_attempts=positive_int(
                "APISHIELD_LEARNING_MAX_DELIVERY_ATTEMPTS", 5
            ),
            min_idle_ms=positive_int(
                "APISHIELD_LEARNING_MIN_IDLE_MS", 30_000, allow_zero=True
            ),
        )
        for name in (
            "redis_url",
            "event_stream",
            "consumer_group",
            "consumer_name",
            "dead_letter_stream",
        ):
            if not getattr(config, name).strip():
                raise ConfigurationError(f"{name} must not be empty")
        if config.event_stream == config.dead_letter_stream:
            raise ConfigurationError("dead_letter_stream must differ from event_stream")
        return config

    def require_pseudo_salt(self) -> str:
        """Return the shared Admin API salt, failing closed if explicitly empty."""
        if not self.pseudo_salt:
            raise ConfigurationError(
                "APISHIELD_PSEUDO_SALT must not be empty"
            )
        return self.pseudo_salt

    def internal_pseudonymization_key(self) -> bytes:
        """Derive a domain-separated key for M3's non-alert baseline IDs."""
        salt = self.require_pseudo_salt().encode("utf-8")
        return hashlib.sha256(b"apishield:m3:internal-identifiers:" + salt).digest()
