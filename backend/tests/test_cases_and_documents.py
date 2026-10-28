"""Case lifecycle, epistemic status of statements, documents encryption and versioning."""

from sqlalchemy import select

from app.models import DocumentBlob
from tests.conftest import case_payload

PDF = b"%PDF-1.4\n% synthetic test document\n"


def _source(actor, cid, **kw):
    data = {"kind": "official_report", "title": "Source fictive", "reliability": "B", "legal_basis": "Base fictive"}
    data.update(kw)
    r = actor.post(f"/api/v1/cases/{cid}/sources", json=data)
    assert r.status_code == 201, r.text
    return r.json()


def test_create_and_read_case_with_all_fields(actors, nord_case):
    case = actors("analyste.nord").get(f"/api/v1/cases/{nord_case['id']}").json()
    for field in ("reference", "category", "country_code", "jurisdiction", "owner_id", "service_id", "executive_summary",
                  "analysis_context", "legal_basis", "review_date", "retention_rule_id", "classification_rank", "version"):
        assert field in case
    assert case["reference"].startswith("XX-")


def test_validation_rejects_bad_input(actors):
    a = actors("analyste.nord")
    assert a.post("/api/v1/cases", json=case_payload(category="suspects")).status_code == 422
    assert a.post("/api/v1/cases", json=case_payload(unknown_field="x")).status_code == 422
    assert a.post("/api/v1/cases", json=case_payload(review_date="2000-01-01")).status_code == 400
    assert a.post("/api/v1/cases", json=case_payload(classification_rank=42)).status_code == 400


def test_optimistic_locking(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    assert a.patch(f"/api/v1/cases/{cid}", json={"version": 1, "title": "Titre 2"}).status_code == 200
    stale = a.patch(f"/api/v1/cases/{cid}", json={"version": 1, "title": "Titre 3"})
    assert stale.status_code == 409


def test_facts_hypotheses_and_four_eyes_verification(actors, nord_case):
    a = actors("analyste.nord")
    sup = actors("superviseur.nord")
    cid = nord_case["id"]
    src = _source(a, cid)
    # A confirmed fact cannot be created directly.
    assert a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "confirmed_fact", "text": "x"}).status_code == 422
    st = a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "unverified_information", "text": "Info fictive"}).json()
    hyp = a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "working_hypothesis", "text": "Hypothèse fictive"}).json()
    assert hyp["kind"] == "working_hypothesis"
    # Author cannot confirm their own statement.
    r = a.post(f"/api/v1/cases/{cid}/statements/{st['id']}/verify", json={"version": 1, "source_id": src["id"], "credibility": 2})
    assert r.status_code == 403
    r = sup.post(f"/api/v1/cases/{cid}/statements/{st['id']}/verify", json={"version": 1, "source_id": src["id"], "credibility": 2})
    assert r.status_code == 200 and r.json()["kind"] == "confirmed_fact" and r.json()["verified_by"]
    kinds = {s["kind"] for s in a.get(f"/api/v1/cases/{cid}/statements").json()}
    assert kinds == {"confirmed_fact", "working_hypothesis"}


def test_human_source_requires_protected_reference(actors, nord_case):
    a = actors("analyste.nord")
    r = a.post(f"/api/v1/cases/{nord_case['id']}/sources", json={
        "kind": "human_protected", "title": "Source humaine", "legal_basis": "Base fictive"})
    assert r.status_code == 400


def test_event_location_precision_rules(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    assert a.post(f"/api/v1/cases/{cid}/events", json={"title": "x", "latitude": 1.0, "longitude": 2.0}).status_code == 400
    assert a.post(f"/api/v1/cases/{cid}/events", json={"title": "x", "location_precision": "exact"}).status_code == 400
    ok = a.post(f"/api/v1/cases/{cid}/events", json={"title": "x", "latitude": 1.0, "longitude": 2.0,
                                                     "location_precision": "approximate", "location_accuracy_m": 2000})
    assert ok.status_code == 201


def test_causal_relation_requires_source(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    e1 = a.post(f"/api/v1/cases/{cid}/entities", json={"kind": "organisation", "label": "Organisation fictive A"}).json()
    e2 = a.post(f"/api/v1/cases/{cid}/entities", json={"kind": "place", "label": "Lieu fictif B"}).json()
    r = a.post(f"/api/v1/cases/{cid}/relations", json={"from_entity_id": e1["id"], "to_entity_id": e2["id"],
                                                       "relation_type": "located_at", "basis": "Proximité",
                                                       "is_causal_claim": True})
    assert r.status_code == 400
    r = a.post(f"/api/v1/cases/{cid}/relations", json={"from_entity_id": e1["id"], "to_entity_id": e2["id"],
                                                       "relation_type": "located_at", "basis": "Rapport fictif p.3"})
    assert r.status_code == 201
    graph = a.get(f"/api/v1/cases/{cid}/graph").json()
    assert graph["edges"][0]["basis"] == "Rapport fictif p.3" and graph["edges"][0]["confidence"] == "low"


def test_lifecycle_close_archive_read_only_and_four_eyes_deletion(actors, engine, nord_case):
    a = actors("analyste.nord")
    sup = actors("superviseur.nord")
    director = actors("directeur")
    cid = nord_case["id"]
    assert a.post(f"/api/v1/cases/{cid}/status", json={"action": "close", "justification": "fin"}).status_code == 403
    assert sup.post(f"/api/v1/cases/{cid}/status", json={"action": "close", "justification": "fin"}).status_code == 200
    # Closed case is read-only.
    assert a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "claim", "text": "x"}).status_code == 409
    assert a.get(f"/api/v1/cases/{cid}").status_code == 200
    assert sup.post(f"/api/v1/cases/{cid}/status", json={"action": "archive", "justification": "fin"}).status_code == 403
    sup.step_up(engine)
    assert sup.post(f"/api/v1/cases/{cid}/status", json={"action": "archive", "justification": "fin"}).status_code == 200
    assert sup.post(f"/api/v1/cases/{cid}/status", json={"action": "request_deletion", "justification": "durée"}).status_code == 200
    director.step_up(engine)
    r = director.post(f"/api/v1/cases/{cid}/status", json={"action": "approve_deletion", "justification": "conforme"})
    assert r.status_code == 200
    assert director.get(f"/api/v1/cases/{cid}").status_code == 404


def test_requester_cannot_approve_own_deletion(actors, engine):
    director = actors("directeur")
    cid = director.post("/api/v1/cases", json=case_payload()).json()["id"]
    director.step_up(engine)
    for action in ("close", "request_deletion"):
        assert director.post(f"/api/v1/cases/{cid}/status", json={"action": action, "justification": "x" * 5}).status_code == 200
    r = director.post(f"/api/v1/cases/{cid}/status", json={"action": "approve_deletion", "justification": "xxxxx"})
    assert r.status_code == 403 and r.json()["code"] == "four_eyes_required"


def test_document_encrypted_at_rest_versioned_and_hash_checked(actors, engine, nord_case, db):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    r = a.post(f"/api/v1/cases/{cid}/documents", data={"title": "Pièce fictive", "classification_rank": "1"},
               files={"file": ("piece.pdf", PDF, "application/pdf")})
    assert r.status_code == 201, r.text
    doc = r.json()
    blob = db.scalar(select(DocumentBlob).where(DocumentBlob.document_id == __import__("uuid").UUID(doc["id"])))
    assert PDF not in blob.ciphertext and b"synthetic" not in blob.ciphertext
    v2 = PDF + b"version 2\n"
    a.post(f"/api/v1/cases/{cid}/documents", data={"title": "Pièce fictive", "classification_rank": "1",
                                                   "document_id": doc["id"]},
           files={"file": ("piece.pdf", v2, "application/pdf")})
    versions = a.get(f"/api/v1/cases/{cid}/documents/{doc['id']}/versions").json()
    assert [v["version"] for v in versions] == [1, 2]
    # Restricted level requires a fresh re-authentication to download.
    assert a.get(f"/api/v1/cases/{cid}/documents/{doc['id']}/content").status_code == 403
    a.step_up(engine)
    r = a.get(f"/api/v1/cases/{cid}/documents/{doc['id']}/content", params={"version": 1})
    assert r.status_code == 200 and r.content == PDF
    assert r.headers["cache-control"] == "no-store"


def test_document_type_spoofing_rejected(actors, nord_case):
    a = actors("analyste.nord")
    r = a.post(f"/api/v1/cases/{nord_case['id']}/documents", data={"title": "x", "classification_rank": "1"},
               files={"file": ("x.pdf", b"MZ\x90\x00 not a pdf", "application/pdf")})
    assert r.status_code == 400 and r.json()["code"] == "content_type_mismatch"
    r = a.post(f"/api/v1/cases/{nord_case['id']}/documents", data={"title": "x", "classification_rank": "1"},
               files={"file": ("x.exe", b"MZ", "application/x-msdownload")})
    assert r.status_code == 400


def test_tampered_ciphertext_detected(actors, engine, nord_case, db):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    doc = a.post(f"/api/v1/cases/{cid}/documents", data={"title": "x", "classification_rank": "1"},
                 files={"file": ("x.pdf", PDF, "application/pdf")}).json()
    with engine.begin() as conn:
        from sqlalchemy import update

        blob = db.scalar(select(DocumentBlob))
        tampered = bytes([blob.ciphertext[0] ^ 1]) + blob.ciphertext[1:]
        conn.execute(update(DocumentBlob).where(DocumentBlob.id == blob.id).values(ciphertext=tampered))
    a.step_up(engine)
    r = a.get(f"/api/v1/cases/{cid}/documents/{doc['id']}/content")
    assert r.status_code == 500 and "Traceback" not in r.text


def test_assessment_distinguishes_levels_and_requires_confirmation(actors, engine, nord_case):
    a = actors("analyste.nord")
    sup = actors("superviseur.nord")
    cid = nord_case["id"]
    src = _source(a, cid)
    r = a.post(f"/api/v1/cases/{cid}/assessments", json={"threat": "Menace fictive", "category": "critical_infrastructure",
                                                         "level": "confirmed_threat"})
    assert r.status_code == 422  # cannot self-declare a confirmed threat
    r = a.post(f"/api/v1/cases/{cid}/assessments", json={
        "threat": "Menace fictive", "category": "critical_infrastructure", "level": "anomaly",
        "observed_facts": ["Fait fictif"], "source_ids": [src["id"]], "alternative_hypotheses": ["Panne technique"],
        "uncertainty": "high", "recommended_verifications": ["Recouper"]})
    assert r.status_code == 201
    body = r.json()
    assert body["analyst_professional_id"] == "ANA-0102" and "preuve" in body["disclaimer"]
    sup.step_up(engine)
    conf = sup.post(f"/api/v1/cases/{cid}/assessments/{body['id']}/confirm", json={"justification": "Recoupement fictif fait"})
    assert conf.status_code == 200 and conf.json()["level"] == "confirmed_threat"
