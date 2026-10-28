"""Reports workflow and exports; audit trail integrity and content hygiene."""

import io

from docx import Document as Docx
from sqlalchemy import select, text

from app.models import AuditLog, ExportRecord
from tests.conftest import TEST_PASSWORD


def _case_with_material(a, cid):
    src = a.post(f"/api/v1/cases/{cid}/sources", json={"kind": "official_report", "title": "Rapport fictif officiel",
                                                       "reliability": "B", "legal_basis": "Base fictive"}).json()
    a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "unverified_information", "text": "Élément fictif à vérifier",
                                                    "source_id": src["id"]})
    a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "working_hypothesis", "text": "Hypothèse fictive"})
    return src


def _submitted_report(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    _case_with_material(a, cid)
    rep = a.post(f"/api/v1/cases/{cid}/reports", json={"report_type": "intelligence_note", "title": "Note fictive",
                                                       "recommendations": "Vérifications complémentaires"}).json()
    assert rep["source_ids"] and rep["statement_ids"] and "Hypothèse de travail" in rep["analysis"]
    assert a.post(f"/api/v1/cases/{cid}/reports/{rep['id']}/submit").json()["status"] == "submitted"
    return rep


def test_report_four_eyes_validation(actors, nord_case):
    rep = _submitted_report(actors, nord_case)
    cid = nord_case["id"]
    a = actors("analyste.nord")
    assert a.post(f"/api/v1/cases/{cid}/reports/{rep['id']}/decision", json={"decision": "approved"}).status_code == 403
    sup = actors("superviseur.nord")
    pending = sup.get("/api/v1/reports/pending-validation").json()
    assert [p["id"] for p in pending] == [rep["id"]]
    r = sup.post(f"/api/v1/cases/{cid}/reports/{rep['id']}/decision", json={"decision": "approved", "comment": "ok"})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    # An approved report is locked against edits.
    assert a.patch(f"/api/v1/cases/{cid}/reports/{rep['id']}", json={"version": r.json()["version"], "title": "x"}).status_code == 409


def test_export_requires_approval_and_step_up_and_keeps_markings(actors, engine, nord_case, db):
    rep = _submitted_report(actors, nord_case)
    cid = nord_case["id"]
    sup = actors("superviseur.nord")
    url = f"/api/v1/cases/{cid}/reports/{rep['id']}/export"
    assert sup.get(url).status_code == 409  # not yet approved
    sup.post(f"/api/v1/cases/{cid}/reports/{rep['id']}/decision", json={"decision": "approved"})
    assert sup.get(url).json()["code"] == "step_up_required"
    sup.step_up(engine)
    pdf = sup.get(url, params={"fmt": "pdf"})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    docx = sup.get(url, params={"fmt": "docx"})
    assert docx.status_code == 200
    d = Docx(io.BytesIO(docx.content))
    header = d.sections[0].header.paragraphs[0].text
    footer = d.sections[0].footer.paragraphs[0].text
    body = "\n".join(p.text for p in d.paragraphs)
    assert header == "DIFFUSION RESTREINTE / RESTRICTED"
    assert "EXP-" in footer and "SUP-0101" in footer
    assert "Rapport fictif officiel" in body and "ne constitue pas une preuve" in body
    assert len(db.scalars(select(ExportRecord)).all()) == 2


def test_analyst_without_export_permission_cannot_export(actors, nord_case):
    rep = _submitted_report(actors, nord_case)
    r = actors("enqueteur.nord").get(f"/api/v1/cases/{nord_case['id']}/reports/{rep['id']}/export")
    assert r.status_code == 403


def test_report_requires_sources_before_submission(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    rep = a.post(f"/api/v1/cases/{cid}/reports", json={"report_type": "daily_summary", "title": "Synthèse vide"}).json()
    assert a.post(f"/api/v1/cases/{cid}/reports/{rep['id']}/submit").status_code == 400


def test_audit_chain_valid_then_tampering_detected(actors, nord_case, engine):
    auditor = actors("auditeur")
    actors("analyste.nord").get(f"/api/v1/cases/{nord_case['id']}")
    ok = auditor.get("/api/v1/audit/verify").json()
    assert ok["valid"] is True and ok["checked"] > 5
    with engine.begin() as conn:
        conn.execute(text("UPDATE audit_logs SET outcome = 'denied' WHERE seq = 3"))
    broken = auditor.get("/api/v1/audit/verify").json()
    assert broken["valid"] is False and broken["first_broken_seq"] == 3


def test_audit_deletion_detected(actors, nord_case, engine):
    auditor = actors("auditeur")
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_logs WHERE seq = (SELECT MAX(seq) FROM audit_logs)"))
    assert auditor.get("/api/v1/audit/verify").json()["valid"] is False


def test_audit_reads_are_themselves_audited(actors, db):
    actors("auditeur").get("/api/v1/audit")
    assert db.scalar(select(AuditLog).where(AuditLog.action == "audit.read")) is not None


def test_audit_entries_contain_no_secrets_or_content(actors, nord_case, db):
    a = actors("analyste.nord")
    a.post(f"/api/v1/cases/{nord_case['id']}/statements", json={"kind": "claim", "text": "CONTENU-SENSIBLE-FICTIF"})
    a.get("/api/v1/search", params={"q": "REQUETE-SENSIBLE"})
    rows = db.scalars(select(AuditLog)).all()
    dump = " ".join(f"{r.details} {r.target_id} {r.actor_label}" for r in rows)
    for needle in ("CONTENU-SENSIBLE-FICTIF", "REQUETE-SENSIBLE", TEST_PASSWORD, a.token, a.refresh):
        assert needle not in dump


def test_case_history_lists_consultations(actors, nord_case):
    a = actors("analyste.nord")
    a.get(f"/api/v1/cases/{nord_case['id']}")
    actions = [h["action"] for h in a.get(f"/api/v1/cases/{nord_case['id']}/history").json()]
    assert "case.view" in actions and "case.create" in actions
