"""Database tables. `alerts`, `learning_state` and `alert_feedback` are shared with the
learner (M3): it writes alerts and learning progress, and consumes feedback rows.
Callers are always stored pseudonymized (see privacy.py); raw IPs are never stored."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, UTCDateTime, utcnow


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # admin | analyst | viewer
    password_hash: Mapped[str] = mapped_column(String(255))


class Upstream(Base):
    __tablename__ = "upstreams"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(512))
    spec_path: Mapped[str] = mapped_column(String(1024), default="")


class SettingsRow(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    mode: Mapped[str] = mapped_column(String(16), default="monitor")
    fail_open: Mapped[bool] = mapped_column(Boolean, default=True)
    retention_days: Mapped[int] = mapped_column(Integer, default=14)
    redaction_patterns: Mapped[list] = mapped_column(JSON, default=list)


# ---- Traffic aggregates (written only by the ingestor) ---------------------------

class TrafficMinute(Base):
    __tablename__ = "traffic_minute"
    upstream_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    minute: Mapped[datetime] = mapped_column(UTCDateTime, primary_key=True)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[int] = mapped_column(Integer, default=0)
    # Sparse latency histogram {bucket index: count}; see metrics.LATENCY_BOUNDS.
    latency_hist: Mapped[dict] = mapped_column(JSON, default=dict)


class TrafficMinuteEndpoint(Base):
    __tablename__ = "traffic_minute_endpoint"
    upstream_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    minute: Mapped[datetime] = mapped_column(UTCDateTime, primary_key=True)
    method: Mapped[str] = mapped_column(String(16), primary_key=True)
    path_template: Mapped[str] = mapped_column(String(512), primary_key=True)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[int] = mapped_column(Integer, default=0)


class TrafficMinuteCaller(Base):
    __tablename__ = "traffic_minute_caller"
    upstream_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    minute: Mapped[datetime] = mapped_column(UTCDateTime, primary_key=True)
    caller: Mapped[str] = mapped_column(String(64), primary_key=True)  # pseudonymized
    requests: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[int] = mapped_column(Integer, default=0)


class TrafficMinuteRule(Base):
    __tablename__ = "traffic_minute_rule"
    upstream_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    minute: Mapped[datetime] = mapped_column(UTCDateTime, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)


# ---- Rules ------------------------------------------------------------------------

class RuleRow(Base):
    __tablename__ = "rules"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)  # gateway rule ids are global
    upstream_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    match: Mapped[dict] = mapped_column(JSON)
    action: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(16), default="analyst")
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    throttle: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


# ---- Shared with the learner (M3) ---------------------------------------------------

class AlertRow(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    upstream_id: Mapped[str] = mapped_column(String(64), index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime)
    caller: Mapped[str] = mapped_column(String(64))           # pseudonymized
    endpoint: Mapped[str] = mapped_column(String(600))        # "GET /search"
    score: Mapped[float] = mapped_column(Float)
    rank: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    reasons: Mapped[list] = mapped_column(JSON, default=list)  # [{feature, observed, baseline, z?}]
    explanation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="new")
    group_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timeline: Mapped[list | None] = mapped_column(JSON, nullable=True)  # [{ts, count}]


class LearningState(Base):
    __tablename__ = "learning_state"
    upstream_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    mode: Mapped[str] = mapped_column(String(16), default="warmup")  # warmup | active | disabled
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    ends_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    endpoints_learned: Mapped[int] = mapped_column(Integer, default=0)
    shapes_learned: Mapped[int] = mapped_column(Integer, default=0)
    sensitivity: Mapped[float] = mapped_column(Float, default=0.5)
    reset_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class LearnerBaseline(Base):
    """Written only by the learner (M3): its baseline snapshot (pseudonymous keys, counts and
    statistics, never payloads) plus its threshold tuning, so a restart does not redo warm-up."""
    __tablename__ = "learner_baselines"
    upstream_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    tuning: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AlertFeedback(Base):
    __tablename__ = "alert_feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    verdict: Mapped[str] = mapped_column(String(32))
    feature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    threshold_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)  # set by M3


# ---- Scans ---------------------------------------------------------------------------

class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    upstream_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    safe_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    api_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    endpoint_risk: Mapped[dict] = mapped_column(JSON, default=dict)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # masked scanner report
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    upstream_id: Mapped[str] = mapped_column(String(64), index=True)
    scanner_id: Mapped[str] = mapped_column(String(255))
    endpoint: Mapped[str] = mapped_column(String(512))
    method: Mapped[str] = mapped_column(String(16))
    owasp_cat: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[float] = mapped_column(Float)
    evidence: Mapped[dict] = mapped_column(JSON)           # masked {request, response}
    fix: Mapped[str] = mapped_column(Text, default="")
    suggested_rule: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # gateway-format rule
    status: Mapped[str] = mapped_column(String(16), default="open")


# ---- Audit -----------------------------------------------------------------------------

class AuditRow(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

