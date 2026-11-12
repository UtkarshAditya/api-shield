"""Caller pseudonymization, shared by the Admin API and the learner (M3).

    pseudonymize("ip_203.0.113.7", salt)  -> "ip_3fa9c2d1"
    pseudonymize("203.0.113.7", salt)     -> "ip_3fa9c2d1"   (the event's bare `ip` field)
    pseudonymize("user_alice", salt)      -> "user_9b1e0c4a"
    pseudonymize("key_1a2b3c4d", salt)    -> "key_1a2b3c4d"  (already a hash of the API key)

The output is "<prefix>" + the first 8 hex chars of HMAC-SHA256(value, salt), where value
is the part after the prefix. Every service that pseudonymizes must use the same
APISHIELD_PSEUDO_SALT so that the same caller gets the same id everywhere.
Call it once, on raw values: it is not idempotent ("ip_3fa9c2d1" would be hashed again).
"""
from __future__ import annotations

import hashlib
import hmac

HASHED_PREFIXES = ("ip_", "user_")
PASSTHROUGH_PREFIXES = ("key_",)


def _digest(value: str, salt: str) -> str:
    return hmac.new(salt.encode(), value.encode(), hashlib.sha256).hexdigest()[:8]


def pseudonymize(value: str, salt: str) -> str:
    if not value or value.startswith(PASSTHROUGH_PREFIXES):
        return value
    for prefix in HASHED_PREFIXES:
        if value.startswith(prefix):
            return prefix + _digest(value[len(prefix):], salt)
    return "ip_" + _digest(value, salt)  # a bare address
