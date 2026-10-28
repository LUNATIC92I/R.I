"""Lost/stolen device response and offline synchronisation."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.models import Device
from tests.conftest import login


def _device_id(db, actor):
    return db.scalar(select(Device.id).where(Device.install_id == actor.install_id))


def test_user_reports_device_lost_and_all_its_sessions_die(client, engine, db):
    a = login(client, engine, "analyste.nord", "phone-lost-0001")
    other = login(client, engine, "analyste.nord", "tablet-ok-0001")
    did = _device_id(db, a)
    r = other.post(f"/api/v1/me/devices/{did}/report-lost", json={"status": "lost", "reason": "Perte déclarée", "wipe": True})
    assert r.status_code == 200 and r.json()["wipe_requested"] is True
    assert a.get("/api/v1/me").status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": a.refresh}).status_code == 401
    assert other.get("/api/v1/me").status_code == 200
    # The revoked device cannot log in again.
    r = client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": __import__("tests.conftest").conftest.TEST_PASSWORD,
                                                "device": {"install_id": "phone-lost-0001", "platform": "test", "label": "x"}})
    assert r.status_code == 401


def test_admin_revokes_stolen_device(client, engine, db):
    victim = login(client, engine, "analyste.nord", "phone-stolen-01")
    admin = login(client, engine, "admin.tech")
    r = admin.post(f"/api/v1/admin/devices/{_device_id(db, victim)}/revoke",
                   json={"status": "stolen", "reason": "Vol déclaré au service", "wipe": True})
    assert r.status_code == 200
    assert victim.get("/api/v1/me").status_code == 401


def test_cannot_report_someone_elses_device(client, engine, db):
    a = login(client, engine, "analyste.nord")
    b = login(client, engine, "analyste.sud")
    r = b.post(f"/api/v1/me/devices/{_device_id(db, a)}/report-lost", json={"status": "lost", "reason": "malveillant"})
    assert r.status_code == 404


def _offline_case(actors):
    sup = actors("superviseur.nord")
    from tests.conftest import case_payload

    case = sup.post("/api/v1/cases", json=case_payload(classification_rank=1)).json()
    return sup, case


def test_offline_package_requires_explicit_policy(actors):
    sup, case = _offline_case(actors)
    assert sup.post(f"/api/v1/sync/offline-package/{case['id']}").json()["code"] == "offline_not_authorised"
    sup.post(f"/api/v1/cases/{case['id']}/offline", params={"allowed": True})
    pkg = sup.post(f"/api/v1/sync/offline-package/{case['id']}").json()
    assert pkg["documents_included"] is False and pkg["expires_at"]
    assert [g["grant_id"] for g in sup.get("/api/v1/sync/grants").json()] == [pkg["grant_id"]]


def test_offline_refused_above_policy_classification(actors):
    sup = actors("superviseur.nord")
    from tests.conftest import case_payload

    case = sup.post("/api/v1/cases", json=case_payload(classification_rank=2)).json()
    sup.post(f"/api/v1/cases/{case['id']}/offline", params={"allowed": True})
    assert sup.post(f"/api/v1/sync/offline-package/{case['id']}").json()["code"] == "classification_not_allowed_offline"


def test_sync_push_applies_is_idempotent_and_detects_conflicts(actors):
    sup, case = _offline_case(actors)
    sup.post(f"/api/v1/cases/{case['id']}/offline", params={"allowed": True})
    sup.post(f"/api/v1/sync/offline-package/{case['id']}")
    now = datetime.now(UTC).isoformat()
    ops = [
        {"client_op_id": "op-0000001", "op_type": "add_statement", "case_id": case["id"], "queued_at": now,
         "payload": {"kind": "claim", "text": "Déclaration saisie hors ligne"}},
        {"client_op_id": "op-0000002", "op_type": "update_case_summary", "case_id": case["id"], "queued_at": now,
         "base_version": 999, "payload": {"executive_summary": "x"}},
    ]
    res = sup.post("/api/v1/sync/push", json={"operations": ops}).json()["results"]
    assert [r["result"] for r in res] == ["applied", "conflict"]
    again = sup.post("/api/v1/sync/push", json={"operations": ops[:1]}).json()["results"][0]
    assert again["replayed"] is True
    texts = [s["text"] for s in sup.get(f"/api/v1/cases/{case['id']}/statements").json()]
    assert texts.count("Déclaration saisie hors ligne") == 1


def test_sync_push_rejected_without_grant_or_authorisation(actors):
    sup, case = _offline_case(actors)
    now = datetime.now(UTC).isoformat()
    op = {"client_op_id": "op-0000010", "op_type": "add_statement", "case_id": case["id"], "queued_at": now,
          "payload": {"kind": "claim", "text": "x"}}
    assert sup.post("/api/v1/sync/push", json={"operations": [op]}).json()["results"][0]["detail"] == "no_valid_offline_grant"
    outsider = actors("analyste.sud")
    op2 = dict(op, client_op_id="op-0000011", case_id=str(uuid.uuid4()))
    assert outsider.post("/api/v1/sync/push", json={"operations": [op2]}).json()["results"][0]["detail"] == "not_authorised"


def test_device_revocation_revokes_offline_grants(client, engine, db, actors):
    sup = login(client, engine, "superviseur.nord", "phone-offline-1")
    from tests.conftest import case_payload

    case = sup.post("/api/v1/cases", json=case_payload()).json()
    sup.post(f"/api/v1/cases/{case['id']}/offline", params={"allowed": True})
    sup.post(f"/api/v1/sync/offline-package/{case['id']}")
    other = login(client, engine, "superviseur.nord", "phone-offline-2")
    other.post(f"/api/v1/me/devices/{_device_id(db, sup)}/report-lost", json={"status": "stolen", "reason": "Vol fictif"})
    from app.models import OfflineGrant

    assert all(g.revoked_at is not None for g in db.scalars(select(OfflineGrant)).all())
