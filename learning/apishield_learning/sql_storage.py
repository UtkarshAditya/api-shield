"""LearningStorage adapter on the Admin API's database (Postgres in Compose, SQLite locally).

* Alerts: the learner's full alert records stay in this process (the learner's own
  bookkeeping: grouping keys, per-detector evidence); the mapped row is upserted into the
  shared ``alerts`` table (see alert_mapping.py) and the upstream is re-ranked. The Admin
  API owns ``status``: it is set to "new" on insert and never written again. When reading,
  Admin ``true_positive``/``false_positive`` count as learner ``resolved`` (a new incident
  can open), and a row the Admin API deleted (demo reset) ends the incident.
* Baselines: ``BaselineLearner`` saves a snapshot on every update, so writes are buffered
  and flushed to ``learner_baselines`` at most every ``flush_interval`` seconds (and on
  ``flush_baselines(force=True)``, called at shutdown).
* Feedback records produced by FeedbackService stay in memory; the source of truth for
  analyst feedback is the Admin API's ``alert_feedback`` table (see live.py).

Only pseudonymous ids, path templates, counts and numbers are written.
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import event, select

from admin_api.db import make_engine, make_session_factory, utcnow
from admin_api.models import AlertFeedback, AlertRow, LearnerBaseline, LearningState, ScanRow

from .alert_mapping import parse_ts, timeline_add, timeline_view, to_alert_row

log = logging.getLogger("apishield.learning.sql")

ACTIVE_ADMIN = ("new", "acknowledged")
RESOLVED_ADMIN = ("true_positive", "false_positive")


def make_learner_engine(url: str):
    """Engine for the shared DB. On SQLite: WAL and a busy timeout, so the Admin API and
    the learner can both write the same file."""
    engine = make_engine(url)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - trivial
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA busy_timeout=10000")
            if url not in ("sqlite://", "sqlite:///:memory:"):
                cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()
    return engine


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, allow_nan=False))


def rerank(session, upstream_id: str) -> None:
    """Same order as the Admin API's demo replay: active alerts first, then by score."""
    rows = list(session.scalars(select(AlertRow).where(AlertRow.upstream_id == upstream_id)))
    rows.sort(key=lambda r: (r.status not in ACTIVE_ADMIN, -r.score, r.id))
    for i, row in enumerate(rows, 1):
        row.rank = i


class SqlLearningStorage:
    """LearningStorage for one upstream, backed by the shared Admin database."""

    def __init__(
        self,
        session_factory,
        upstream_id: str,
        *,
        flush_interval: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.session_factory = session_factory
        self.upstream_id = upstream_id
        self.flush_interval = flush_interval
        self._clock = clock
        self._alerts: dict[str, dict[str, Any]] = {}
        self._timelines: dict[str, dict[int, int]] = {}
        self._feedback: list[dict[str, Any]] = []
        self._pending_baselines: dict[str, dict[str, Any]] = {}
        self._last_flush = clock()
        self.stats: Counter[str] = Counter()

    @classmethod
    def from_url(cls, url: str, upstream_id: str, **kwargs: Any) -> "SqlLearningStorage":
        return cls(make_session_factory(make_learner_engine(url)), upstream_id, **kwargs)

    # ---- baselines -------------------------------------------------------------------

    def save_baseline(self, upstream_id: str, baseline: Mapping[str, object]) -> None:
        self._pending_baselines[upstream_id] = dict(baseline)
        self.flush_baselines()

    def load_baseline(self, upstream_id: str) -> Mapping[str, object] | None:
        if upstream_id in self._pending_baselines:
            return _copy(self._pending_baselines[upstream_id])
        with self.session_factory() as session:
            row = session.get(LearnerBaseline, upstream_id)
            return _copy(row.snapshot) if row is not None and row.snapshot else None

    def flush_baselines(self, *, force: bool = False) -> int:
        """Write buffered snapshots if the interval passed (or force). Returns rows written."""
        if not self._pending_baselines:
            return 0
        if not force and self._clock() - self._last_flush < self.flush_interval:
            return 0
        pending, self._pending_baselines = self._pending_baselines, {}
        with self.session_factory() as session:
            for upstream_id, snapshot in pending.items():
                row = session.get(LearnerBaseline, upstream_id)
                if row is None:
                    session.add(LearnerBaseline(upstream_id=upstream_id, snapshot=snapshot, tuning={},
                                                updated_at=utcnow()))
                else:
                    row.snapshot, row.updated_at = snapshot, utcnow()
            session.commit()
        self._last_flush = self._clock()
        self.stats["baseline_flushes"] += 1
        return len(pending)

    def clear_baseline(self, upstream_id: str) -> None:
        """Forget the learned baseline and tuning (learning reset)."""
        self._pending_baselines.pop(upstream_id, None)
        with self.session_factory() as session:
            row = session.get(LearnerBaseline, upstream_id)
            if row is not None:
                session.delete(row)
            session.commit()

    def load_tuning(self, upstream_id: str) -> dict[str, Any]:
        with self.session_factory() as session:
            row = session.get(LearnerBaseline, upstream_id)
            return _copy(row.tuning) if row is not None and row.tuning else {}

    def save_tuning(self, upstream_id: str, tuning: Mapping[str, Any]) -> None:
        self.flush_baselines(force=True)
        with self.session_factory() as session:
            row = session.get(LearnerBaseline, upstream_id)
            if row is None:
                session.add(LearnerBaseline(upstream_id=upstream_id, snapshot={}, tuning=dict(tuning),
                                            updated_at=utcnow()))
            else:
                row.tuning, row.updated_at = dict(tuning), utcnow()
            session.commit()

    # ---- alerts ------------------------------------------------------------------------

    def save_alert(self, alert: Mapping[str, object]) -> None:
        alert_id = alert.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            raise ValueError("alert must include a non-empty alert_id")
        self._store(_copy(alert))

    def update_alert(self, alert: Mapping[str, object]) -> None:
        alert_id = alert.get("alert_id")
        if not isinstance(alert_id, str) or alert_id not in self._alerts:
            raise KeyError(f"alert not found: {alert_id}")
        self._store(_copy(alert))

    def get_alert(self, alert_id: str) -> Mapping[str, Any] | None:
        alert = self._alerts.get(alert_id)
        return _copy(alert) if alert is not None else None

    def list_alerts(self) -> list[Mapping[str, Any]]:
        return [_copy(a) for a in self._alerts.values()]

    def find_recent_alert(self, grouping_key: str, since_timestamp: str) -> Mapping[str, Any] | None:
        since = parse_ts(since_timestamp)
        candidates = [
            a for a in self._alerts.values()
            if a.get("grouping_key") == grouping_key
            and a.get("status") in ACTIVE_ADMIN
            and isinstance(a.get("last_seen"), str)
            and parse_ts(a["last_seen"]) >= since
        ]
        if not candidates:
            return None
        statuses = self._admin_statuses([a["alert_id"] for a in candidates])
        eligible = []
        for alert in candidates:
            status = statuses.get(alert["alert_id"])
            if status is None:
                if alert.get("severity") in ("critical", "high", "medium", "low"):
                    # it was written once, so the Admin API deleted it (demo reset): incident over
                    self._alerts.pop(alert["alert_id"], None)
                    self._timelines.pop(alert["alert_id"], None)
                    continue
                eligible.append(alert)  # info-level, never written
            elif status in RESOLVED_ADMIN:
                alert["status"] = "resolved"
            else:
                alert["status"] = status
                eligible.append(alert)
        if not eligible:
            return None
        newest = max(eligible, key=lambda a: parse_ts(a["last_seen"]))
        return _copy(newest)

    def forget_alerts(self) -> None:
        self._alerts.clear()
        self._timelines.clear()

    def _admin_statuses(self, alert_ids: list[str]) -> dict[str, str]:
        with self.session_factory() as session:
            rows = session.execute(select(AlertRow.id, AlertRow.status).where(AlertRow.id.in_(alert_ids)))
            return {row.id: row.status for row in rows}

    def _store(self, data: dict[str, Any]) -> None:
        alert_id = data["alert_id"]
        previous = self._alerts.get(alert_id)
        if previous is None or previous.get("last_observation_key") != data.get("last_observation_key"):
            timeline_add(self._timelines.setdefault(alert_id, {}), str(data.get("last_seen") or data["timestamp"]))
        self._alerts[alert_id] = data
        values = to_alert_row(data, self.upstream_id,
                              timeline_view(self._timelines.get(alert_id, {}), str(data.get("last_seen") or data["timestamp"])))
        if values is None:
            self.stats["alerts_skipped_info"] += 1
            return
        with self.session_factory() as session:
            row = session.get(AlertRow, alert_id)
            if row is None:
                session.add(AlertRow(rank=0, status="new", **values))
                self.stats["alerts_created"] += 1
            else:  # keep the analyst's status
                for key, value in values.items():
                    if key != "id":
                        setattr(row, key, value)
                self.stats["alerts_updated"] += 1
            session.flush()
            rerank(session, self.upstream_id)
            session.commit()

    # ---- feedback (learner-side records) --------------------------------------------------

    def save_feedback(self, feedback: Mapping[str, object]) -> None:
        self._feedback.append(_copy(feedback))

    def list_feedback(self) -> list[Mapping[str, Any]]:
        return [_copy(f) for f in self._feedback]

    # ---- shared tables the live runner reads and writes -------------------------------------

    def tables_ready(self) -> bool:
        try:
            with self.session_factory() as session:
                session.execute(select(AlertRow.id).limit(1))
                session.execute(select(LearnerBaseline.upstream_id).limit(1))
            return True
        except Exception:
            return False

    def read_learning_control(self) -> dict[str, Any]:
        """mode / sensitivity / reset_requested_at as set by the Admin API (None if no row)."""
        with self.session_factory() as session:
            row = session.get(LearningState, self.upstream_id)
            if row is None:
                return {"mode": None, "sensitivity": 0.5, "reset_requested_at": None}
            return {"mode": row.mode, "sensitivity": row.sensitivity,
                    "reset_requested_at": row.reset_requested_at}

    def write_learning_state(self, *, mode: str, progress: float, started_at: datetime | None,
                             ends_at: datetime | None, endpoints_learned: int, shapes_learned: int) -> None:
        """Writes progress. Never touches sensitivity or reset_requested_at, and never
        overrides an Admin-set ``disabled`` mode."""
        with self.session_factory() as session:
            row = session.get(LearningState, self.upstream_id)
            if row is None:
                row = LearningState(upstream_id=self.upstream_id, mode=mode, sensitivity=0.5,
                                    started_at=started_at or utcnow())
                session.add(row)
            if row.mode != "disabled":
                row.mode = mode
            row.progress = max(0.0, min(1.0, float(progress)))
            row.started_at = started_at or row.started_at or utcnow()
            row.ends_at = ends_at
            row.endpoints_learned, row.shapes_learned = int(endpoints_learned), int(shapes_learned)
            session.commit()

    def pending_feedback(self) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(AlertFeedback)
                .join(AlertRow, AlertRow.id == AlertFeedback.alert_id)
                .where(AlertFeedback.consumed_at.is_(None), AlertRow.upstream_id == self.upstream_id)
                .order_by(AlertFeedback.id)
            )
            return [{"id": r.id, "alert_id": r.alert_id, "verdict": r.verdict, "feature": r.feature,
                     "threshold_delta": r.threshold_delta} for r in rows]

    def mark_feedback(self, feedback_id: int, *, feature: str | None, threshold_delta: float | None) -> None:
        """Consumes a feedback row and records what the learner actually applied."""
        with self.session_factory() as session:
            row = session.get(AlertFeedback, feedback_id)
            if row is None:
                return
            row.consumed_at = datetime.now(timezone.utc)
            row.feature, row.threshold_delta = feature, threshold_delta
            session.commit()

    def _latest_scan(self, session):
        return session.scalars(
            select(ScanRow)
            .where(ScanRow.upstream_id == self.upstream_id, ScanRow.status == "done")
            .order_by(ScanRow.finished_at.desc().nulls_last(), ScanRow.started_at.desc())
            .limit(1)
        ).first()

    def latest_endpoint_risk(self) -> dict[str, float]:
        with self.session_factory() as session:
            scan = self._latest_scan(session)
            return dict(scan.endpoint_risk or {}) if scan is not None else {}

    def latest_scan_id(self) -> str | None:
        with self.session_factory() as session:
            scan = self._latest_scan(session)
            return scan.id if scan is not None else None
