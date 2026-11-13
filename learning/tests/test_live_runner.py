"""LiveLearner: the replay flow on live records plus the Admin integration around it."""

from datetime import datetime, timedelta, timezone

from admin_api.models import AlertFeedback, AlertRow, LearningState, ScanRow
from sqlalchemy import select

from apishield_learning.live import LiveSettings, SqlEndpointRiskProvider
from live_helpers import START, UPSTREAM, attack, event, features, make_learner, make_storage, warm_up


def alert_rows(storage):
    with storage.session_factory() as session:
        return list(session.scalars(select(AlertRow).order_by(AlertRow.rank)))


def set_learning(storage, **values):
    with storage.session_factory() as session:
        row = session.get(LearningState, UPSTREAM) or LearningState(upstream_id=UPSTREAM, started_at=START)
        for key, value in values.items():
            setattr(row, key, value)
        session.merge(row)
        session.commit()


def test_attack_after_warmup_creates_ranked_learner_alerts(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage)
    warm_up(learner)
    status = learner.write_state()
    assert status["mode"] == "active" and status["endpoints_learned"] == 2
    attack(learner, 41)
    attacker = [r for r in alert_rows(storage) if r.caller == "key_929bf132"]
    assert {r.endpoint for r in attacker} == {"POST /login", "GET /search"}
    top = alert_rows(storage)[0]
    assert top.rank == 1 and top.caller == "key_929bf132"
    assert "(Learner:" in top.explanation and not top.id.startswith("al_demo_")
    with storage.session_factory() as session:
        row = session.get(LearningState, UPSTREAM)
        assert (row.mode, row.progress) == ("active", 1.0)
        assert row.ends_at - row.started_at == timedelta(seconds=20)


def test_alerts_can_wait_for_the_end_of_warmup(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage, alert_during_warmup=False)
    warm_up(learner)
    assert alert_rows(storage) == []  # the first /login during warm-up raised nothing
    assert learner.stats["suppressed_warmup"] >= 1
    attack(learner, 41)
    assert any(r.caller == "key_929bf132" for r in alert_rows(storage))


def test_disabled_mode_learns_but_creates_no_alerts(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage)
    warm_up(learner)
    set_learning(storage, mode="disabled")
    learner.housekeeping()
    before = len(alert_rows(storage))
    attack(learner, 41)
    assert len(alert_rows(storage)) == before
    assert learner.stats["processed"] == 47


def test_old_stream_history_trains_but_does_not_alert(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage, now=lambda: START + timedelta(days=2))
    learner.settings = LiveSettings(upstream_id=UPSTREAM, isolation_forest=False, detector_min_samples=3,
                                    max_event_age_seconds=300)
    warm_up(learner)
    attack(learner, 41)
    assert alert_rows(storage) == []
    assert learner.stats["suppressed_old"] > 0
    assert learner.learning_status()["mode"] == "active"


def test_false_positive_raises_the_named_detector_threshold(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage)
    warm_up(learner)
    attack(learner, 41)
    top = alert_rows(storage)[0]
    with storage.session_factory() as session:
        session.add(AlertFeedback(alert_id=top.id, verdict="false_positive", feature="Response size",
                                  threshold_delta=0.1, created_by="analyst@demo.local"))
        session.commit()
    before = learner.detection.thresholds("response_size")["z_score"]
    learner.housekeeping()
    after = learner.detection.thresholds("response_size")["z_score"]
    assert round(after / before, 6) == 1.1  # FeedbackAnalysisConfig.suggested_threshold_increase
    assert learner.detection.thresholds("latency")["z_score"] == before  # other detectors unchanged
    with storage.session_factory() as session:
        fb = session.scalars(select(AlertFeedback)).one()
        assert fb.consumed_at is not None and fb.threshold_delta == 0.1 and fb.feature == "Response size"
    assert storage.get_alert(top.id)["feedback_status"] == "false_positive"
    # persisted: a restarted learner keeps the adjustment
    assert make_learner(storage).detection.multipliers == {"response_size": 1.1}


def test_false_positive_on_a_signal_reports_zero_delta(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage)
    warm_up(learner)
    attack(learner, 41)
    top = alert_rows(storage)[0]
    with storage.session_factory() as session:
        session.add(AlertFeedback(alert_id=top.id, verdict="false_positive", feature="Rule hits / blocked",
                                  threshold_delta=0.1, created_by="analyst@demo.local"))
        session.commit()
    learner.housekeeping()
    with storage.session_factory() as session:
        assert session.scalars(select(AlertFeedback)).one().threshold_delta == 0.0
    assert learner.detection.multipliers == {}


def test_raised_threshold_is_applied_by_the_detector(tmp_path):
    learner = make_learner(make_storage(tmp_path))
    baseline = {"state": "active", "observation_count": 30, "learned_shape_hashes": ["shape-search"],
                "metrics": {"response_size": {"mean": 120.0, "standard_deviation": 10.0, "ewma": 120.0,
                                              "count": 30}}}
    probe = features(event(70, resp_size=160))  # z = 4.0 against the default 3.0
    detected = lambda: {r.detector: r.detected for r in learner.detection.detect(probe, baseline)}
    assert detected()["response_size"]
    deltas = [learner.detection.raise_threshold("response_size", 0.1) for _ in range(4)]  # 3.0 -> 4.39
    assert deltas == [0.1] * 4
    assert not detected()["response_size"]
    assert learner.detection.raise_threshold("rule_hit_or_blocked_action", 0.1) == 0.0


def test_sensitivity_scales_thresholds(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage)
    assert learner.detection.thresholds("latency") == {"z_score": 3.0, "ratio": 3.0}
    set_learning(storage, sensitivity=1.0)
    learner.housekeeping()
    assert learner.detection.thresholds("latency") == {"z_score": 1.5, "ratio": 1.5}
    set_learning(storage, sensitivity=0.0)
    learner.housekeeping()
    assert learner.detection.thresholds("latency") == {"z_score": 4.5, "ratio": 4.5}


def test_reset_request_drops_baselines_once(tmp_path):
    storage = make_storage(tmp_path, flush_interval=0)
    learner = make_learner(storage)
    warm_up(learner)
    learner.housekeeping()
    assert storage.load_baseline(UPSTREAM) is not None
    set_learning(storage, reset_requested_at=datetime.now(timezone.utc))
    learner.housekeeping()
    assert learner.baseline.get_all_baselines() == {}
    assert learner.learning_status()["mode"] == "warmup"
    warm_up(learner, 10)
    learner.housekeeping()  # same request: not handled twice
    assert learner.baseline.get_all_baselines() != {}
    assert make_learner(storage)._reset_handled_at is not None  # remembered across restarts


def test_restart_restores_the_learned_baseline(tmp_path):
    storage = make_storage(tmp_path, flush_interval=0)
    learner = make_learner(storage)
    warm_up(learner)
    learner.close()
    again = make_learner(make_storage(tmp_path))
    assert again.learning_status()["mode"] == "active"


def test_endpoint_risk_from_latest_scan_raises_priority(tmp_path):
    storage = make_storage(tmp_path)
    clock = [0.0]
    provider = SqlEndpointRiskProvider(storage, ttl=30, clock=lambda: clock[0])
    assert provider.get_risk_score("/login", "POST") is None
    with storage.session_factory() as session:
        session.add(ScanRow(id="scan_old", upstream_id=UPSTREAM, status="done", started_at=START,
                            finished_at=START, endpoint_risk={"/login": 2.0}))
        session.add(ScanRow(id="scan_new", upstream_id=UPSTREAM, status="done", started_at=START,
                            finished_at=START + timedelta(minutes=5), endpoint_risk={"/login": 9.0}))
        session.add(ScanRow(id="scan_run", upstream_id=UPSTREAM, status="running", started_at=START,
                            endpoint_risk={"/login": 1.0}))
        session.commit()
    assert provider.get_risk_score("/login", "POST") is None  # cached for 30 s
    assert provider.refresh_if_new_scan()  # ...unless housekeeping sees a new finished scan
    assert provider.get_risk_score("/login", "POST") == 0.9
    assert not provider.refresh_if_new_scan()
    clock[0] = 31
    assert provider.get_risk_score("/login", "POST") == 0.9
    assert provider.get_risk_score("/search", "GET") is None

    other = tmp_path / "no_scan"
    other.mkdir()
    without = make_learner(make_storage(other))
    warm_up(without)
    low = max(a.priority_score for a in attack(without, 41) if a.endpoint == "/login")
    learner = make_learner(storage)
    warm_up(learner)
    high = max(a.priority_score for a in attack(learner, 41) if a.endpoint == "/login")
    assert high > low


def test_warmup_stays_done_when_new_endpoints_appear(tmp_path):
    storage = make_storage(tmp_path)
    learner = make_learner(storage, alert_during_warmup=False)
    warm_up(learner)
    assert learner.learning_status()["mode"] == "active"
    learner.housekeeping()
    # a new endpoint with clean traffic is learned, but warm-up does not restart
    learner.process(features(event(41, path="/debug", status=500, shape="shape-debug")))
    status = learner.learning_status()
    assert (status["mode"], status["endpoints_seen"], status["endpoints_learned"]) == ("active", 3, 2)
    attack(learner, 42)  # alerts are not muted
    assert any(r.caller == "key_929bf132" and r.endpoint == "POST /login" for r in alert_rows(storage))
    assert make_learner(storage).learning_status()["mode"] == "active"  # persisted
    learner.reset("2099-01-01T00:00:00+00:00")
    assert learner.learning_status()["mode"] == "warmup"


def test_threshold_profile_from_env_stacks_with_feedback(tmp_path):
    settings = LiveSettings.from_env({"APISHIELD_LEARNING_THRESHOLD_MULTIPLIERS": "latency=3, request_size=2"})
    assert settings.threshold_profile == (("latency", 3.0), ("request_size", 2.0))
    storage = make_storage(tmp_path)
    learner = make_learner(storage, threshold_profile=settings.threshold_profile)
    assert learner.detection.thresholds("latency")["z_score"] == 9.0
    assert learner.detection.thresholds("response_size")["z_score"] == 3.0
    learner.detection.raise_threshold("latency", 0.1)
    assert round(learner.detection.thresholds("latency")["z_score"], 6) == 9.9
    assert learner.detection.multipliers == {"latency": 1.1}  # only feedback is persisted as tuning
    import pytest
    with pytest.raises(ValueError):
        LiveSettings.from_env({"APISHIELD_LEARNING_THRESHOLD_MULTIPLIERS": "rule_hit_or_blocked_action=2"})
