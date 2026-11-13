"""Shared helpers for the live-learner tests: a temporary Admin DB and M1-shaped events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from admin_api import models  # noqa: F401  (registers the tables)
from admin_api.db import Base, make_session_factory

from apishield_learning.baselines import BaselineConfig
from apishield_learning.config import LearningConfig
from apishield_learning.events import IdentifierPseudonymizer, TrafficEvent
from apishield_learning.features import extract_features
from apishield_learning.live import LiveLearner, LiveSettings
from apishield_learning.sql_storage import SqlLearningStorage, make_learner_engine

SALT = "live-test-salt"
CONFIG = LearningConfig(pseudo_salt=SALT)
PSEUDONYMIZER = IdentifierPseudonymizer(CONFIG.internal_pseudonymization_key())
UPSTREAM = "up_shop"
START = datetime(2026, 11, 13, 18, 0, tzinfo=timezone.utc)
RAW_IP = "203.0.113.77"
RAW_USER = "user_alice-sub-1234"


def db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'admin.db').as_posix()}"


def make_storage(tmp_path, **kwargs) -> SqlLearningStorage:
    url = db_url(tmp_path)
    engine = make_learner_engine(url)
    Base.metadata.create_all(engine)
    return SqlLearningStorage(make_session_factory(engine), UPSTREAM, **kwargs)


def make_learner(storage: SqlLearningStorage, *, now=None, isolation_forest=False, **settings) -> LiveLearner:
    return LiveLearner(
        storage,
        LiveSettings(upstream_id=UPSTREAM, isolation_forest=isolation_forest, detector_min_samples=3,
                     max_event_age_seconds=10**9, **settings),
        baseline_config=BaselineConfig(min_observations=5, warmup_period_seconds=20),
        now=now or (lambda: START + timedelta(hours=1)),
    )


def event(offset: float, *, caller="key_aaaaaaaa", ip="198.51.100.10", method="GET", path="/search",
          status=200, req_size=0, resp_size=120, shape="shape-search", rule_hits=(), action="allow",
          latency=12.0) -> TrafficEvent:
    return TrafficEvent(
        ts=(START + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"),
        req_id=f"req-{offset}",
        caller=caller,
        ip=ip,
        method=method,
        path_template=path,
        status=status,
        latency_ms=latency,
        req_size=req_size,
        resp_size=resp_size,
        shape_hash=shape,
        rule_hits=tuple(rule_hits),
        action=action,
    )


def features(ev: TrafficEvent):
    return extract_features(ev, PSEUDONYMIZER, config=CONFIG)


def warm_up(learner: LiveLearner, seconds: int = 40) -> float:
    """Normal traffic from two callers on /search and /login, one request per second."""
    for i in range(seconds):
        caller = "key_aaaaaaaa" if i % 2 else "key_bbbbbbbb"
        if i % 4 == 3:
            learner.process(features(event(i, caller=caller, method="POST", path="/login",
                                           req_size=40, resp_size=80, shape="shape-login")))
        else:
            learner.process(features(event(i, caller=caller)))
    return float(seconds)


def attack(learner: LiveLearner, start: float, *, caller="key_929bf132", ip=RAW_IP, count=6):
    """Failed logins with rule hits, then a SQLi-like search with a new shape."""
    alerts = []
    for i in range(count):
        alerts += learner.process(features(event(start + i * 0.5, caller=caller, ip=ip, method="POST",
                                                 path="/login", status=401, req_size=40, resp_size=30,
                                                 shape="shape-login", rule_hits=("login-rate",))))
    alerts += learner.process(features(event(start + 5, caller=caller, ip=ip, status=500, resp_size=900,
                                             shape="shape-search-sqli", rule_hits=("sqli",))))
    return alerts
