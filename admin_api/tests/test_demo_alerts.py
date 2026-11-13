"""Demo-replay alerts (admin_api/demo_alerts.py): the stand-in for M3 until the learner writes alerts."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from admin_api import demo_alerts
from admin_api.db import iso
from admin_api.models import AlertRow
from admin_api.privacy import pseudonymize

from .conftest import SALT, event, login

ALICE, BOB, MALLORY = "key_a11ce000", "key_b0b00000", "key_3a11e7e5"
RAW_IP = "198.51.100.66"
Q = "?upstream_id=up_shop"


def _traffic(now: datetime) -> list:
    """Two normal API keys for two minutes, then one attacker key and one anonymous probe."""
    events = []
    for i in range(120):
        ts = iso(now - timedelta(seconds=150 - i))
        caller = ALICE if i % 2 else BOB
        events.append(event(ts, caller=caller, ip="10.0.0.5", path="/search"))
        if i % 40 == 0:
            events.append(event(ts, caller=caller, ip="10.0.0.5", method="POST", path="/login"))
    for i in range(30):  # password guessing
        events.append(event(iso(now - timedelta(seconds=20 - i * 0.5)), caller=MALLORY, ip=RAW_IP, method="POST",
                            path="/login", status=401))
    for i in range(10):  # SQL injection probes
        events.append(event(iso(now - timedelta(seconds=10 - i)), caller=MALLORY, ip=RAW_IP, path="/search",
                            status=403, action="block", rule_hits=["builtin-sqli"]))
    for i in range(5):  # no API key at all: the caller is the (pseudonymized) IP
        events.append(event(iso(now - timedelta(seconds=5 - i)), caller=None, ip=RAW_IP, path="/admin/stats", status=401))
    return events


def _populate(app, now=None):
    now = now or datetime.now(timezone.utc)
    app.state.ingestor.process(_traffic(now))
    return now


def _demo_rows(app):
    with app.state.session_factory() as s:
        return list(s.scalars(select(AlertRow).where(AlertRow.id.like(demo_alerts.ID_PREFIX + "%"))))


def test_burst_creates_ranked_explained_alert_for_the_attacker(app, client, as_admin):
    _populate(app)
    resp = client.post(f"/api/demo/alerts/replay{Q}", headers=as_admin)
    assert resp.status_code == 200 and resp.json()["created"] >= 2

    alerts = client.get(f"/api/alerts{Q}&status=active&sort=rank", headers=as_admin).json()["items"]
    top = alerts[0]
    assert top["caller"] == MALLORY and top["id"].startswith(demo_alerts.ID_PREFIX)
    assert top["endpoint"] in ("POST /login", "GET /search") and top["severity"] in ("critical", "high")
    login_alert = next(a for a in alerts if a["caller"] == MALLORY and a["endpoint"] == "POST /login")
    features = {r["feature"]: r for r in login_alert["reasons"]}
    assert "Failed logins" in features and features["Failed logins"]["z"] >= 3
    assert features["Failed logins"]["observed"].startswith("100% of 30")
    assert "Request rate" in features
    assert demo_alerts.MARKER in login_alert["explanation"] and "password guessing" in login_alert["explanation"]
    sqli = next(a for a in alerts if a["caller"] == MALLORY and a["endpoint"] == "GET /search")
    assert any(r["feature"] == "Gateway rule hits" for r in sqli["reasons"])
    assert login_alert["timeline"] and all({"ts", "count"} == set(p) for p in login_alert["timeline"])

    # Normal callers are never flagged.
    assert not [a for a in alerts if a["caller"] in (ALICE, BOB) and a["id"].startswith(demo_alerts.ID_PREFIX)]


def test_alert_caller_matches_traffic_and_never_stores_raw_values(app, client, as_admin):
    _populate(app)
    client.post(f"/api/demo/alerts/replay{Q}", headers=as_admin)
    anon = pseudonymize(RAW_IP, SALT)
    rows = _demo_rows(app)
    assert any(r.caller == anon and r.endpoint == "GET /admin/stats" for r in rows)
    traffic_callers = {e["caller"] for e in client.get(f"/api/traffic/recent{Q}&limit=500", headers=as_admin).json()["items"]}
    assert {r.caller for r in rows} <= traffic_callers
    for r in rows:
        stored = repr((r.caller, r.endpoint, r.reasons, r.explanation, r.timeline, r.group_id))
        assert RAW_IP not in stored and "10.0.0.5" not in stored


def test_running_twice_does_not_duplicate_and_keeps_feedback(app, client, as_admin, as_analyst):
    _populate(app)
    first = client.post(f"/api/demo/alerts/replay{Q}", headers=as_admin).json()
    rows = _demo_rows(app)
    login_id = next(r.id for r in rows if r.caller == MALLORY and r.endpoint == "POST /login")
    client.patch(f"/api/alerts/{login_id}", json={"status": "false_positive"}, headers=as_analyst)

    second = client.post(f"/api/demo/alerts/replay{Q}", headers=as_admin).json()
    assert second["created"] == 0 and second["updated"] == first["created"]
    again = _demo_rows(app)
    assert sorted(r.id for r in again) == sorted(r.id for r in rows)
    assert next(r for r in again if r.id == login_id).status == "false_positive"


def test_detect_is_pure_and_quiet_on_normal_traffic():
    now = datetime.now(timezone.utc)
    normal = [e for e in _traffic(now) if e["caller"] in (ALICE, BOB)]
    from admin_api.ingest import mask_event
    masked = [mask_event(e, SALT) for e in normal]
    assert demo_alerts.detect(masked, "up_shop", now) == []
    old = [mask_event(e, SALT) for e in _traffic(now - timedelta(hours=1))]
    assert demo_alerts.detect(old, "up_shop", now) == []  # outside the 15-minute window


def test_only_admins_can_trigger_replay(client, as_analyst, as_viewer):
    assert client.post(f"/api/demo/alerts/replay{Q}", headers=as_analyst).status_code == 403
    assert client.post(f"/api/demo/alerts/replay{Q}", headers=as_viewer).status_code == 403


def test_demo_reset_restores_the_starting_state(app, client, as_admin, as_analyst):
    _populate(app)
    client.post(f"/api/demo/alerts/replay{Q}", headers=as_admin)
    client.patch("/api/alerts/al_1001", json={"status": "false_positive"}, headers=as_analyst)
    from admin_api.models import AlertFeedback, ScanRow
    with app.state.session_factory() as s:
        s.add(ScanRow(id="sc_old", upstream_id="up_shop", status="done", progress=1.0, counts={}, endpoint_risk={}))
        s.commit()

    resp = client.post(f"/api/demo/reset{Q}", headers=as_admin)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scans"] == 1 and body["feedback"] == 1 and body["buffered_events"] > 0
    assert _demo_rows(app) == []
    seeded = client.get("/api/alerts/al_1001", headers=as_admin).json()
    assert seeded["status"] == "new" and seeded["caller"] == "key_929bf132"
    with app.state.session_factory() as s:
        assert s.query(AlertFeedback).count() == 0 and s.query(ScanRow).count() == 0
    # The buffer is empty, so the replay does not bring the last burst back.
    assert client.post(f"/api/demo/alerts/replay{Q}", headers=as_admin).json()["created"] == 0
    assert client.get("/api/me", headers=as_admin).status_code == 200  # users kept


def test_demo_reset_is_admin_only_and_demo_only(gateway, client, as_analyst):
    assert client.post(f"/api/demo/reset{Q}", headers=as_analyst).status_code == 403
    import httpx
    from fastapi.testclient import TestClient
    from admin_api.main import create_app
    from .conftest import make_config
    real = create_app(make_config(demo_seed=False), gateway_transport=httpx.MockTransport(gateway.handler),
                      run_background=False)
    with TestClient(real) as c:
        with real.state.session_factory() as s:  # no demo users without DEMO_SEED: add an admin
            from admin_api.auth import hash_password
            from admin_api.models import User
            s.add(User(id="u1", email="root@example.com", name="Root", role="admin", password_hash=hash_password("pw")))
            s.commit()
        tok = c.post("/api/auth/login", json={"email": "root@example.com", "password": "pw"}).json()["token"]
        resp = c.post(f"/api/demo/reset{Q}", headers={"Authorization": f"Bearer {tok}"})
    assert resp.status_code == 409 and resp.json()["error"]["code"] == "demo_only"


def test_learner_mode_seeds_nothing_and_reset_keeps_the_baseline(gateway):
    """ADMIN_SEED_ALERTS=false (learner on): no canned alerts or fake learning progress; the
    reset clears learner alerts and their feedback but keeps learner_baselines and learning_state."""
    import httpx
    from datetime import datetime, timezone
    from fastapi.testclient import TestClient
    from admin_api.main import create_app
    from admin_api.models import AlertFeedback, AlertRow, LearnerBaseline, LearningState
    from .conftest import login, make_config
    app = create_app(make_config(seed_alerts=False), gateway_transport=httpx.MockTransport(gateway.handler),
                     run_background=False)
    with TestClient(app) as c:
        admin = login(c, "admin")
        assert c.get(f"/api/alerts{Q}", headers=admin).json()["total"] == 0
        assert c.get(f"/api/learning/status{Q}", headers=admin).json()["endpoints_learned"] == 0
        now = datetime.now(timezone.utc)
        with app.state.session_factory() as s:
            s.add(AlertRow(id="3f1c-learner-uuid", upstream_id="up_shop", ts=now, caller="key_929bf132",
                           endpoint="POST /login", score=0.8, rank=1, severity="high", status="new",
                           reasons=[], explanation="... (Learner: priority 0.80 ...)"))
            s.add(AlertFeedback(alert_id="3f1c-learner-uuid", verdict="false_positive", created_by="a@x"))
            s.add(LearnerBaseline(upstream_id="up_shop", snapshot={"version": 1}, tuning={}, updated_at=now))
            row = s.get(LearningState, "up_shop")
            row.mode, row.progress, row.endpoints_learned = "active", 1.0, 3
            s.commit()
        body = c.post(f"/api/demo/reset{Q}", headers=admin).json()
        assert (body["alerts_removed"], body["feedback"], body["alerts_seeded"]) == (1, 1, 0)
        assert c.get(f"/api/alerts{Q}", headers=admin).json()["total"] == 0
        status = c.get(f"/api/learning/status{Q}", headers=admin).json()
        assert (status["mode"], status["endpoints_learned"]) == ("active", 3)
        with app.state.session_factory() as s:
            assert s.get(LearnerBaseline, "up_shop").snapshot == {"version": 1}
