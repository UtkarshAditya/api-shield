from datetime import datetime, timezone

from admin_api.db import iso
from admin_api.models import AlertFeedback, AuditRow, LearningState

from .conftest import event

Q = "?upstream_id=up_shop"


def test_alerts_ranked_and_filtered(client, as_viewer):
    body = client.get(f"/api/alerts{Q}&sort=rank", headers=as_viewer).json()
    assert [a["rank"] for a in body["items"]] == sorted(a["rank"] for a in body["items"])
    assert body["total"] == 5
    active = client.get(f"/api/alerts{Q}&status=active", headers=as_viewer).json()
    assert {a["status"] for a in active["items"]} == {"new", "acknowledged"} and active["total"] == 4
    crit = client.get(f"/api/alerts{Q}&severity=critical", headers=as_viewer).json()
    assert [a["id"] for a in crit["items"]] == ["al_1001"]
    assert client.get(f"/api/alerts{Q}&limit=2&offset=1", headers=as_viewer).json()["items"][0]["rank"] == 2


def test_alert_detail_has_timeline(client, as_viewer):
    alert = client.get("/api/alerts/al_1001", headers=as_viewer).json()
    assert len(alert["timeline"]) == 12 and alert["group_id"] == "grp_929b"
    assert client.get("/api/alerts/al_nope", headers=as_viewer).status_code == 404


def test_false_positive_returns_adjustment_and_records_feedback(client, as_analyst, app):
    resp = client.patch("/api/alerts/al_1001", json={"status": "false_positive"}, headers=as_analyst)
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert"]["status"] == "false_positive"
    assert body["adjustment"] == {"feature": "Request rate", "threshold_delta": 0.1}  # highest z
    with app.state.session_factory() as s:
        fb = s.query(AlertFeedback).one()
        entry = s.query(AuditRow).filter_by(action="alert.feedback").one()
    assert (fb.verdict, fb.feature, fb.consumed_at) == ("false_positive", "Request rate", None)
    assert entry.details == {"from": "new", "to": "false_positive"}


def test_acknowledge_has_no_adjustment(client, as_analyst):
    body = client.patch("/api/alerts/al_1002", json={"status": "acknowledged"}, headers=as_analyst).json()
    assert body["adjustment"] is None


def test_viewer_cannot_triage(client, as_viewer):
    assert client.patch("/api/alerts/al_1001", json={"status": "acknowledged"}, headers=as_viewer).status_code == 403


def test_promote_key_caller_targets_caller(client, as_analyst, gateway):
    resp = client.post(f"/api/alerts/al_1001/promote-to-rule{Q}", json={"action": "block"}, headers=as_analyst)
    assert resp.status_code == 201, resp.text
    rule = resp.json()
    assert rule["match"] == {"path": "/search", "method": "GET", "condition": "caller == 'key_929bf132'"}
    assert gateway.rules["alert-al_1001"]["action"] == "block"


def test_promote_ip_caller_is_endpoint_scoped(client, as_analyst):
    rule = client.post(f"/api/alerts/al_1002/promote-to-rule{Q}", headers=as_analyst).json()
    assert rule["match"] == {"path": "/login", "method": "POST"}
    assert rule["action"] == "throttle" and rule["throttle"] == {"limit": 10, "per": 60}


def test_learning_status_patch_and_reset(client, as_viewer, as_admin, as_analyst, app):
    status = client.get(f"/api/learning/status{Q}", headers=as_viewer).json()
    assert status["mode"] == "active" and status["progress"] == 1 and status["shapes_learned"] == 23
    assert client.patch(f"/api/learning{Q}", json={"sensitivity": 0.8}, headers=as_analyst).status_code == 403
    assert client.patch(f"/api/learning{Q}", json={"sensitivity": 1.5}, headers=as_admin).status_code == 422
    assert client.patch(f"/api/learning{Q}", json={"sensitivity": 0.8}, headers=as_admin).json()["sensitivity"] == 0.8
    reset = client.post(f"/api/learning/reset{Q}", headers=as_admin).json()
    assert reset["mode"] == "warmup" and reset["progress"] == 0 and reset["endpoints_learned"] == 0
    with app.state.session_factory() as s:
        assert s.get(LearningState, "up_shop").reset_requested_at is not None


def test_audit_log_admin_only_and_newest_first(client, as_admin, as_analyst):
    client.patch("/api/alerts/al_1002", json={"status": "acknowledged"}, headers=as_analyst)
    client.patch("/api/settings", json={"mode": "enforce"}, headers=as_admin)
    assert client.get("/api/audit-log", headers=as_analyst).status_code == 403
    log = client.get("/api/audit-log", headers=as_admin).json()
    assert [e["action"] for e in log["items"]] == ["mode.change", "alert.feedback"]
    assert log["total"] == 2
    assert client.get("/api/audit-log?action=mode.change", headers=as_admin).json()["total"] == 1


def test_purge_deletes_traffic_and_is_audited(client, as_admin, as_analyst, app):
    app.state.ingestor.process([event(iso(datetime.now(timezone.utc)))] * 2)
    assert client.post(f"/api/privacy/purge{Q}", headers=as_analyst).status_code == 403
    body = client.post(f"/api/privacy/purge{Q}", headers=as_admin).json()
    assert body["recent_events"] == 2 and body["aggregate_rows"] == 3
    summary = client.get(f"/api/metrics/summary{Q}&range=1h", headers=as_admin).json()
    assert summary["requests"] == 0
    assert client.get("/api/audit-log?action=data.purge", headers=as_admin).json()["total"] == 1
