"""Startup rows. The upstream and the settings row always exist; demo users, alerts and
learning progress are added only when DEMO_SEED=true (they mirror frontend/src/mocks/seed.ts).

The top seeded alerts belong to key_929bf132, the gateway's id for the simulator's attacker key
(key-mallory, scripts/simulate_traffic.py), so they tell the same story as the alerts the
demo replay (demo_alerts.py) computes from live traffic."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import hash_password
from .config import Config
from .db import utcnow
from .models import AlertRow, LearningState, SettingsRow, Upstream, User

DEMO_USERS = [
    ("u_admin", "admin@demo.local", "Ada Admin", "admin"),
    ("u_analyst", "analyst@demo.local", "Sam Analyst", "analyst"),
    ("u_viewer", "viewer@demo.local", "Vic Viewer", "viewer"),
]
DEMO_PASSWORD = "demo"
DEFAULT_REDACTION = ["authorization", "password", "card_number", "email", "ssn"]


def ensure_base_rows(session: Session, cfg: Config) -> None:
    upstream = session.get(Upstream, cfg.upstream_id)
    if upstream is None:
        session.add(Upstream(id=cfg.upstream_id, name=cfg.upstream_name, url=cfg.upstream_url,
                             spec_path=cfg.openapi_spec))
    else:  # env is the source of truth for the single configured upstream
        upstream.name, upstream.url, upstream.spec_path = cfg.upstream_name, cfg.upstream_url, cfg.openapi_spec
    if session.get(SettingsRow, 1) is None:
        session.add(SettingsRow(id=1, mode="monitor", fail_open=True, retention_days=14,
                                redaction_patterns=list(DEFAULT_REDACTION)))
    if session.get(LearningState, cfg.upstream_id) is None:
        session.add(LearningState(upstream_id=cfg.upstream_id, mode="warmup", progress=0.0,
                                  started_at=utcnow(), ends_at=utcnow() + timedelta(days=1)))
    session.commit()


def seed_demo(session: Session, cfg: Config) -> None:
    if session.scalar(select(User).limit(1)) is None:
        hashed = hash_password(DEMO_PASSWORD)
        session.add_all(User(id=i, email=e, name=n, role=r, password_hash=hashed) for i, e, n, r in DEMO_USERS)

    up = cfg.upstream_id
    if not cfg.seed_alerts:  # the learner (M3) writes real alerts and learning progress
        session.commit()
        return
    learning = session.get(LearningState, up)
    if learning is not None and learning.endpoints_learned == 0 and learning.progress == 0:
        now = utcnow()
        learning.mode, learning.progress = "active", 1.0
        learning.started_at, learning.ends_at = now - timedelta(days=3), now - timedelta(days=2)
        learning.endpoints_learned, learning.shapes_learned = 7, 23

    if session.scalar(select(AlertRow).where(AlertRow.upstream_id == up).limit(1)) is None:
        session.add_all(_demo_alerts(up))
    session.commit()


def _demo_alerts(up: str) -> list:
    now = utcnow()

    def ago(minutes: int):
        return now - timedelta(minutes=minutes)

    burst = [{"ts": (ago(12 - i)).isoformat(timespec="seconds").replace("+00:00", "Z"),
              "count": 25 + (i % 3) if i < 8 else 380 + i * 8} for i in range(12)]
    return [
        AlertRow(id="al_1001", upstream_id=up, ts=ago(2), caller="key_929bf132", endpoint="GET /search",
                 score=0.97, rank=1, severity="critical", status="new", group_id="grp_929b", timeline=burst,
                 reasons=[{"feature": "Request rate", "observed": "412 req/min", "baseline": "28 req/min", "z": 14.2},
                          {"feature": "New payload shape", "observed": "query.q: string(len 180+)",
                           "baseline": "string(len ≤ 40)", "z": 9.1},
                          {"feature": "Error ratio", "observed": "38% 5xx", "baseline": "0.4% 5xx", "z": 7.7}],
                 explanation="This caller is hitting /search 14× faster than usual with a query shape we've never "
                             "seen, and a third of the responses are server errors. That pattern usually means "
                             "automated injection probing."),
        AlertRow(id="al_1002", upstream_id=up, ts=ago(4), caller="ip_5be03a71", endpoint="POST /login",
                 score=0.91, rank=2, severity="high", status="new", group_id="grp_5be0",
                 reasons=[{"feature": "Failed logins", "observed": "96 in 5 min", "baseline": "2 in 5 min", "z": 11.3},
                          {"feature": "Distinct usernames", "observed": "88", "baseline": "1", "z": 10.4}],
                 explanation="One IP tried 88 different usernames on /login in five minutes, almost all failing. "
                             "This looks like credential stuffing."),
        AlertRow(id="al_1003", upstream_id=up, ts=ago(9), caller="key_a07b93d4", endpoint="GET /users/{user_id}",
                 score=0.78, rank=3, severity="high", status="acknowledged", group_id="grp_a07b",
                 reasons=[{"feature": "Distinct IDs requested", "observed": "640 / 10 min",
                           "baseline": "6 / 10 min", "z": 8.8},
                          {"feature": "Sequential ID access", "observed": "yes", "baseline": "no"}],
                 explanation="This key is walking user IDs in sequence, far more than any normal client would. "
                             "It may be scraping other people's profiles (broken object-level authorization)."),
        AlertRow(id="al_1004", upstream_id=up, ts=ago(22), caller="key_d2e85f01", endpoint="POST /comments",
                 score=0.52, rank=4, severity="medium", status="new", group_id="grp_d2e8",
                 reasons=[{"feature": "Payload size", "observed": "48 KB", "baseline": "0.6 KB", "z": 5.2}],
                 explanation="Comment requests from this key are about 80× larger than normal. It could be a client "
                             "bug or an attempt to overload the endpoint."),
        AlertRow(id="al_1005", upstream_id=up, ts=ago(75), caller="key_77c0e6aa", endpoint="GET /search",
                 score=0.21, rank=5, severity="low", status="false_positive", group_id="grp_77c0",
                 reasons=[{"feature": "New user agent family", "observed": "python-requests", "baseline": "browser"}],
                 explanation="A key that normally comes from browsers is now using a script client. Often harmless "
                             "(for example, a new integration)."),
    ]
