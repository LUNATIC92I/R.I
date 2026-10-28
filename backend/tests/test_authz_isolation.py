"""Case isolation, need-to-know and anti-IDOR guarantees, enforced server side."""

import uuid

import pytest

from tests.conftest import case_payload, user_id


def _populate(actor, case_id):
    src = actor.post(f"/api/v1/cases/{case_id}/sources", json={
        "kind": "official_report", "title": "Rapport fictif", "reliability": "B", "legal_basis": "Base fictive"}).json()
    st = actor.post(f"/api/v1/cases/{case_id}/statements", json={
        "kind": "unverified_information", "text": "Information fictive", "source_id": src["id"]}).json()
    ev = actor.post(f"/api/v1/cases/{case_id}/events", json={"title": "Événement fictif"}).json()
    return src, st, ev


CHILD_ROUTES = [
    "/api/v1/cases/{id}",
    "/api/v1/cases/{id}/statements",
    "/api/v1/cases/{id}/sources",
    "/api/v1/cases/{id}/events",
    "/api/v1/cases/{id}/documents",
    "/api/v1/cases/{id}/reports",
    "/api/v1/cases/{id}/assessments",
    "/api/v1/cases/{id}/osint",
    "/api/v1/cases/{id}/indicators",
    "/api/v1/cases/{id}/graph",
    "/api/v1/cases/{id}/gaps",
    "/api/v1/cases/{id}/members",
    "/api/v1/cases/{id}/history",
]


def test_other_service_cannot_access_case_by_changing_identifier(actors, nord_case):
    outsider = actors("analyste.sud")
    for route in CHILD_ROUTES:
        r = outsider.get(route.format(id=nord_case["id"]))
        assert r.status_code == 404, (route, r.status_code)
    # Same response for an identifier that does not exist: no enumeration oracle.
    assert outsider.get(f"/api/v1/cases/{uuid.uuid4()}").json() == outsider.get(f"/api/v1/cases/{nord_case['id']}").json()


def test_other_service_cannot_write_into_case(actors, nord_case):
    outsider = actors("analyste.sud")
    cid = nord_case["id"]
    assert outsider.post(f"/api/v1/cases/{cid}/statements", json={"kind": "claim", "text": "x"}).status_code == 404
    assert outsider.patch(f"/api/v1/cases/{cid}", json={"version": 1, "title": "pirate"}).status_code == 404
    assert outsider.post(f"/api/v1/cases/{cid}/reports", json={"report_type": "intelligence_note", "title": "x"}).status_code == 404


def test_case_absent_from_outsider_lists_search_and_aggregates(actors, nord_case):
    outsider = actors("analyste.sud")
    assert all(c["id"] != nord_case["id"] for c in outsider.get("/api/v1/cases").json())
    assert outsider.get("/api/v1/search", params={"q": "Dossier fictif"}).json()["count"] == 0
    assert outsider.get("/api/v1/dashboard").json()["active_cases"] == 0
    assert outsider.get("/api/v1/analysis/timeline", params={"case_ids": [nord_case["id"]]}).status_code == 404
    assert outsider.get("/api/v1/analysis/correlations", params={"case_ids": [nord_case["id"]]}).status_code == 404
    feats = outsider.get("/api/v1/analysis/map").json()["features"]
    assert all(f["properties"].get("case_id") != nord_case["id"] for f in feats)


def test_child_object_of_another_case_cannot_be_referenced(actors, nord_case):
    """IDOR on nested objects: using my own case id with someone else's statement id."""
    nord = actors("analyste.nord")
    sud = actors("analyste.sud")
    _, st, _ = _populate(nord, nord_case["id"])
    own = sud.post("/api/v1/cases", json=case_payload(title="Dossier sud")).json()
    r = sud.post(f"/api/v1/cases/{own['id']}/statements/{st['id']}/verify",
                 json={"version": 1, "source_id": str(uuid.uuid4()), "credibility": 2})
    assert r.status_code == 404
    r = sud.post(f"/api/v1/cases/{own['id']}/statements", json={"kind": "claim", "text": "x", "contradicts_id": st["id"]})
    assert r.status_code == 400


def test_supervisor_of_same_service_sees_case_via_service_scope(actors, nord_case):
    assert actors("superviseur.nord").get(f"/api/v1/cases/{nord_case['id']}").status_code == 200


def test_director_of_parent_service_sees_case(actors, nord_case):
    assert actors("directeur").get(f"/api/v1/cases/{nord_case['id']}").status_code == 200


def test_technical_admin_cannot_read_operational_cases(actors, nord_case):
    admin = actors("admin.tech")
    assert admin.get(f"/api/v1/cases/{nord_case['id']}").status_code == 403  # lacks case:read entirely
    assert admin.get("/api/v1/cases").status_code == 403


def test_auditor_cannot_read_cases_but_reads_audit(actors, nord_case):
    auditor = actors("auditeur")
    assert auditor.get(f"/api/v1/cases/{nord_case['id']}").status_code == 403
    assert auditor.get("/api/v1/audit").status_code == 200


def test_member_grant_gives_read_and_respects_clearance(actors, nord_case, db):
    nord = actors("analyste.nord")
    sup = actors("superviseur.nord")
    sud = actors("analyste.sud")
    assert sud.get(f"/api/v1/cases/{nord_case['id']}").status_code == 404
    r = sup.post(f"/api/v1/cases/{nord_case['id']}/members", json={
        "user_id": str(user_id(db, "analyste.sud")), "access": "read", "justification": "Besoin d'en connaître fictif"})
    assert r.status_code == 201, r.text
    assert sud.get(f"/api/v1/cases/{nord_case['id']}").status_code == 200
    # Read-only member cannot write.
    assert sud.post(f"/api/v1/cases/{nord_case['id']}/statements", json={"kind": "claim", "text": "x"}).status_code == 404
    # The analyst (owner, not supervisor) cannot grant access: missing permission.
    assert nord.post(f"/api/v1/cases/{nord_case['id']}/members", json={
        "user_id": str(user_id(db, "consultant")), "justification": "test"}).status_code == 403


def test_member_with_insufficient_clearance_cannot_be_granted(actors, nord_case, db):
    sup = actors("superviseur.nord")
    secret_case = sup.post("/api/v1/cases", json=case_payload(classification_rank=2)).json()
    r = sup.post(f"/api/v1/cases/{secret_case['id']}/members", json={
        "user_id": str(user_id(db, "enqueteur.nord")), "justification": "test"})
    assert r.status_code == 400 and r.json()["code"] == "user_clearance_insufficient"


def test_case_above_clearance_hidden_even_within_service(actors, db):
    sup = actors("superviseur.nord")
    secret_case = sup.post("/api/v1/cases", json=case_payload(classification_rank=2)).json()
    investigator = actors("enqueteur.nord")
    assert investigator.get(f"/api/v1/cases/{secret_case['id']}").status_code == 404


def test_cannot_create_case_above_own_clearance(actors):
    r = actors("analyste.nord").post("/api/v1/cases", json=case_payload(classification_rank=3))
    assert r.status_code == 403


def test_expired_membership_no_longer_grants_access(actors, nord_case, db):
    sup = actors("superviseur.nord")
    sup.post(f"/api/v1/cases/{nord_case['id']}/members", json={
        "user_id": str(user_id(db, "analyste.sud")), "justification": "Mission fictive",
        "expires_at": "2000-01-01T00:00:00Z"})
    assert actors("analyste.sud").get(f"/api/v1/cases/{nord_case['id']}").status_code == 404


def test_denials_are_audited(actors, nord_case, db):
    from sqlalchemy import select

    from app.models import AuditLog

    actors("analyste.sud").get(f"/api/v1/cases/{nord_case['id']}")
    denied = db.scalars(select(AuditLog).where(AuditLog.action == "case.access_denied")).all()
    assert denied and denied[-1].details["reason"] == "no_need_to_know"


@pytest.mark.parametrize("path", ["/api/v1/admin/users", "/api/v1/admin/devices", "/api/v1/audit"])
def test_analyst_cannot_reach_admin_or_audit(actors, path):
    assert actors("analyste.nord").get(path).status_code == 403


def test_privilege_change_requires_step_up_and_revokes_sessions(actors, engine, db):
    admin = actors("admin.tech")
    target = actors("consultant")
    uid = user_id(db, "consultant")
    r = admin.patch(f"/api/v1/admin/users/{uid}", json={"roles": ["analyst"]})
    assert r.status_code == 403 and r.json()["code"] == "step_up_required"
    admin.step_up(engine)
    assert admin.patch(f"/api/v1/admin/users/{uid}", json={"roles": ["analyst"]}).status_code == 200
    assert target.get("/api/v1/me").status_code == 401


def test_admin_cannot_modify_self(actors, engine, db):
    admin = actors("admin.tech")
    admin.step_up(engine)
    r = admin.patch(f"/api/v1/admin/users/{user_id(db, 'admin.tech')}", json={"clearance_rank": 3})
    assert r.status_code == 403
