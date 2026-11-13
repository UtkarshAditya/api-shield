"""SqlLearningStorage on SQLite: alert upsert, status ownership, ranking, baselines."""

from admin_api.models import AlertFeedback, AlertRow, LearnerBaseline, LearningState
from sqlalchemy import select

from live_helpers import UPSTREAM, make_storage
from test_live_mapping import learner_alert


def rows(storage):
    with storage.session_factory() as session:
        return list(session.scalars(select(AlertRow).order_by(AlertRow.rank)))


def set_status(storage, alert_id, status):
    with storage.session_factory() as session:
        session.get(AlertRow, alert_id).status = status
        session.commit()


def test_upsert_creates_then_updates_without_touching_status(tmp_path):
    storage = make_storage(tmp_path)
    alert = learner_alert()
    storage.save_alert(alert)
    [row] = rows(storage)
    assert (row.status, row.rank, row.score) == ("new", 1, 0.75)

    set_status(storage, alert["alert_id"], "acknowledged")
    storage.update_alert({**alert, "priority_score": 0.9, "severity": "critical", "repeat_count": 7,
                          "last_seen": "2026-11-13T18:00:20Z", "last_observation_key": "2026-11-13T18:00:20Z"})
    [row] = rows(storage)
    assert row.status == "acknowledged"  # Admin-owned, never overwritten
    assert (row.score, row.severity) == (0.9, "critical")
    assert sum(b["count"] for b in row.timeline) == 2


def test_duplicate_observation_does_not_grow_timeline(tmp_path):
    storage = make_storage(tmp_path)
    alert = learner_alert()
    storage.save_alert(alert)
    storage.update_alert({**alert, "feedback_status": "true_positive"})  # same observation key
    [row] = rows(storage)
    assert sum(b["count"] for b in row.timeline) == 1


def test_info_alerts_are_kept_in_memory_only(tmp_path):
    storage = make_storage(tmp_path)
    storage.save_alert(learner_alert(severity="info", priority_score=0.1))
    assert rows(storage) == []
    assert storage.get_alert(learner_alert()["alert_id"]) is not None
    assert storage.stats["alerts_skipped_info"] == 1


def test_rank_follows_score_with_resolved_last(tmp_path):
    storage = make_storage(tmp_path)
    for i, score in enumerate((0.3, 0.9, 0.6)):
        storage.save_alert(learner_alert(alert_id=f"a{i}", priority_score=score, severity="medium",
                                         grouping_key=f"g{i}"))
    assert [r.id for r in rows(storage)] == ["a1", "a2", "a0"]
    set_status(storage, "a1", "false_positive")
    storage.save_alert(learner_alert(alert_id="a3", priority_score=0.1, severity="low", grouping_key="g3"))
    assert [(r.id, r.rank) for r in rows(storage)] == [("a2", 1), ("a0", 2), ("a3", 3), ("a1", 4)]


def test_find_recent_alert_respects_window_and_admin_status(tmp_path):
    storage = make_storage(tmp_path)
    alert = learner_alert()
    storage.save_alert(alert)
    key = alert["grouping_key"]
    assert storage.find_recent_alert(key, "2026-11-13T17:59:00Z")["alert_id"] == alert["alert_id"]
    assert storage.find_recent_alert(key, "2026-11-13T18:05:00Z") is None  # outside the window
    assert storage.find_recent_alert("other", "2026-11-13T17:59:00Z") is None

    set_status(storage, alert["alert_id"], "acknowledged")
    assert storage.find_recent_alert(key, "2026-11-13T17:59:00Z")["status"] == "acknowledged"
    set_status(storage, alert["alert_id"], "true_positive")
    assert storage.find_recent_alert(key, "2026-11-13T17:59:00Z") is None  # resolved: a new incident opens


def test_alert_deleted_by_admin_ends_the_incident(tmp_path):
    storage = make_storage(tmp_path)
    alert = learner_alert()
    storage.save_alert(alert)
    with storage.session_factory() as session:
        session.delete(session.get(AlertRow, alert["alert_id"]))
        session.commit()
    assert storage.find_recent_alert(alert["grouping_key"], "2026-11-13T17:59:00Z") is None
    assert storage.get_alert(alert["alert_id"]) is None


def test_baseline_round_trip_and_buffered_writes(tmp_path):
    now = [0.0]
    storage = make_storage(tmp_path, flush_interval=5.0, clock=lambda: now[0])
    storage.save_baseline(UPSTREAM, {"version": 1, "n": 1})
    storage.save_baseline(UPSTREAM, {"version": 1, "n": 2})
    with storage.session_factory() as session:
        assert session.get(LearnerBaseline, UPSTREAM) is None  # buffered, not written yet
    assert storage.load_baseline(UPSTREAM) == {"version": 1, "n": 2}  # served from the buffer

    now[0] = 6.0
    storage.save_baseline(UPSTREAM, {"version": 1, "n": 3})  # interval passed: flushed
    assert storage.stats["baseline_flushes"] == 1
    storage.save_baseline(UPSTREAM, {"version": 1, "n": 4})
    assert storage.flush_baselines(force=True) == 1

    fresh = make_storage(tmp_path)  # another process on the same file
    assert fresh.load_baseline(UPSTREAM) == {"version": 1, "n": 4}
    fresh.save_tuning(UPSTREAM, {"multipliers": {"latency": 1.1}})
    assert fresh.load_tuning(UPSTREAM) == {"multipliers": {"latency": 1.1}}
    assert fresh.load_baseline(UPSTREAM) == {"version": 1, "n": 4}
    fresh.clear_baseline(UPSTREAM)
    assert fresh.load_baseline(UPSTREAM) is None


def test_learning_state_keeps_sensitivity_and_disabled(tmp_path):
    storage = make_storage(tmp_path)
    storage.write_learning_state(mode="warmup", progress=0.4, started_at=None, ends_at=None,
                                 endpoints_learned=1, shapes_learned=2)
    with storage.session_factory() as session:
        row = session.get(LearningState, UPSTREAM)
        row.sensitivity, row.mode = 0.8, "disabled"
        session.commit()
    storage.write_learning_state(mode="active", progress=1.0, started_at=None, ends_at=None,
                                 endpoints_learned=3, shapes_learned=5)
    with storage.session_factory() as session:
        row = session.get(LearningState, UPSTREAM)
        assert (row.mode, row.sensitivity, row.progress, row.endpoints_learned) == ("disabled", 0.8, 1.0, 3)


def test_feedback_rows_are_consumed_once(tmp_path):
    storage = make_storage(tmp_path)
    storage.save_alert(learner_alert())
    with storage.session_factory() as session:
        session.add(AlertFeedback(alert_id=learner_alert()["alert_id"], verdict="false_positive",
                                  feature="Request rate", threshold_delta=0.1, created_by="a@demo.local"))
        session.commit()
    [pending] = storage.pending_feedback()
    storage.mark_feedback(pending["id"], feature="Request rate", threshold_delta=0.1)
    assert storage.pending_feedback() == []


def test_sqlite_uses_wal_and_busy_timeout(tmp_path):
    storage = make_storage(tmp_path)
    with storage.session_factory() as session:
        conn = session.connection().connection
        cur = conn.cursor()
        assert cur.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert cur.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000
