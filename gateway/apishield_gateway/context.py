"""Per-request state shared by every pipeline stage."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Higher number wins when several stages or rules touch the same request.
ACTION_ORDER = {"allow": 0, "log": 1, "throttle": 2, "challenge": 3, "block": 4}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Decision:
    """A stage's verdict: stop the request and answer it at the gateway."""

    status: int
    code: str
    message: str
    hit: str
    action: str = "block"
    headers: dict = field(default_factory=dict)
    # Hard decisions protect the gateway itself and apply even in monitor mode.
    hard: bool = False


@dataclass
class RequestContext:
    method: str
    raw_path: str
    query_string: str
    headers: dict
    ip: str
    body: bytes = b""
    req_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started: float = field(default_factory=time.perf_counter)
    ts: str = field(default_factory=now_iso)

    # Filled in by the normalize stage
    path: str = ""
    decoded_path: str = ""
    path_template: str = ""
    path_params: dict = field(default_factory=dict)
    query: dict = field(default_factory=dict)
    json: Any = None
    json_error: bool = False
    payload_text: str = ""
    shape_hash: str = ""
    operation: Any = None

    # Filled in by the auth stage
    caller: str = ""
    authenticated: bool = False
    credential_presented: bool = False
    auth_method: str = "none"
    claims: dict = field(default_factory=dict)

    # Outcome
    rule_hits: list = field(default_factory=list)
    action: str = "allow"
    upstream_ms: float = 0.0

    def hit(self, name: str, action: str = "log") -> None:
        """Record that a rule or check fired, and raise the request's action."""
        if name not in self.rule_hits:
            self.rule_hits.append(name)
        if ACTION_ORDER.get(action, 0) > ACTION_ORDER.get(self.action, 0):
            self.action = action

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)
