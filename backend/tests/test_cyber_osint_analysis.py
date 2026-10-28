"""Cyber intelligence, OSINT, correlation, map and assistant."""

from datetime import UTC, datetime, timedelta

import pytest

from app.services import assistant, cyber, osint
from tests.conftest import login


def now(days=0):
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


@pytest.mark.parametrize("kind,raw,expected", [
    ("ipv4", " 192.0.2.10 ", "192.0.2.10"),
    ("domain", "Example[.]ORG.", "example.org"),
    ("url", "hxxps://example[.]org/a", "https://example.org/a"),
    ("sha256", "A" * 64, "a" * 64),
])
def test_indicator_normalisation(kind, raw, expected):
    assert cyber.normalize(kind, raw) == expected


@pytest.mark.parametrize("kind,raw", [("ipv4", "999.1.1.1"), ("ipv4", "::1"), ("domain", "-bad-.x"), ("md5", "xyz")])
def test_indicator_validation_rejects_garbage(kind, raw):
    with pytest.raises(ValueError):
        cyber.normalize(kind, raw)


def test_ip_context_warns_against_physical_location():
    ctx = cyber.ip_context("ipv4", "192.0.2.1")
    assert "localiser" in ctx["location_note"]


def _indicator(a, cid, **kw):
    data = {"type": "domain", "value": "malveillant-fictif.example", "provenance": "Rapport fictif CERT",
            "first_seen": now(-2)}
    data.update(kw)
    r = a.post(f"/api/v1/cases/{cid}/indicators", json=data)
    assert r.status_code == 201, r.text
    return r.json()


def test_isolated_or_stale_signal_cannot_be_declared_malicious(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    ind = _indicator(a, cid)
    r = a.post(f"/api/v1/cases/{cid}/indicators/{ind['id']}/verdict",
               json={"verdict": "malicious_confirmed", "justification": "Réputation trouvée en ligne"})
    assert r.json()["code"] == "isolated_signal"
    old = _indicator(a, cid, value="ancien-fictif.example", first_seen=now(-400), last_seen=now(-300),
                     independent_source_count=3)
    assert old["freshness"] == "stale"
    r = a.post(f"/api/v1/cases/{cid}/indicators/{old['id']}/verdict",
               json={"verdict": "malicious_confirmed", "justification": "Ancienne réputation"})
    assert r.json()["code"] == "stale_indicator"
    ok = _indicator(a, cid, value="corrobore-fictif.example", independent_source_count=2)
    r = a.post(f"/api/v1/cases/{cid}/indicators/{ok['id']}/verdict",
               json={"verdict": "malicious_confirmed", "justification": "Deux sources indépendantes concordantes"})
    assert r.status_code == 200 and r.json()["verdict"] == "malicious_confirmed"


def test_stix_import(actors, nord_case):
    a = actors("analyste.nord")
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '198.51.100.7']", "pattern_type": "stix",
         "valid_from": "2026-01-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--2", "pattern": "[file:hashes.'SHA-256' = '" + "b" * 64 + "']"},
        {"type": "indicator", "id": "indicator--3", "pattern": "[x:y = 'z'] AND [a:b = 'c']"},
    ]}
    r = a.post(f"/api/v1/cases/{nord_case['id']}/indicators/import-stix", json={"bundle": bundle, "provenance": "Flux fictif"})
    assert r.json()["created"] == 2 and r.json()["skipped"][0]["reason"] == "unsupported_pattern"


def test_siem_ingest_raises_alert_only_visible_with_need_to_know(client, engine, actors, nord_case, db):
    a = actors("analyste.nord")
    _indicator(a, nord_case["id"], type="ipv4", value="203.0.113.5")
    admin = login(client, engine, "admin.tech")
    admin.step_up(engine)
    from sqlalchemy import select

    from app.models import Service

    svc_id = db.scalar(select(Service.id).where(Service.code == "HQ"))
    key = admin.post("/api/v1/admin/service-accounts", json={"name": "siem-fictif", "scopes": ["siem:ingest"],
                                                              "service_id": str(svc_id)}).json()["api_key"]
    event = {"external_id": "evt-1", "observed_at": now(), "sensor": "IDS fictif", "observable_type": "ipv4",
             "observable_value": "203.0.113.5", "severity": "high"}
    assert client.post("/api/v1/integrations/siem/events", json={"events": [event]},
                       headers={"X-API-Key": "bad.key"}).status_code == 401
    r = client.post("/api/v1/integrations/siem/events", json={"events": [event]}, headers={"X-API-Key": key})
    assert r.status_code == 200 and r.json() == {"received": 1, "stored": 1}
    alerts = a.get("/api/v1/alerts").json()
    match = [x for x in alerts if x["kind"] == "ioc_match"]
    assert match and "jamais une preuve" in match[0]["notice"]
    assert not [x for x in actors("analyste.sud").get("/api/v1/alerts").json() if x["kind"] == "ioc_match"]


def test_osint_duplicates_and_versions(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    body = "Un communiqué fictif annonce la fermeture temporaire d'un poste frontière fictif pour travaux de maintenance."
    first = a.post(f"/api/v1/cases/{cid}/osint", json={
        "source_name": "Journal fictif", "url": "https://www.journal-fictif.example/article?utm_source=x",
        "title": "Fermeture fictive", "content": body, "published_at": now(-3), "event_date": now(-5),
        "reliability": "C", "unverified_points": ["Durée des travaux"]}).json()
    assert first["possible_duplicates"] == [] and first["item"]["collected_at"] != first["item"]["published_at"]
    dup = a.post(f"/api/v1/cases/{cid}/osint", json={
        "source_name": "Agrégateur fictif", "url": "https://journal-fictif.example/article/", "title": "Reprise",
        "content": body}).json()
    assert dup["possible_duplicates"][0]["match"] == "same_url"
    v2 = a.post(f"/api/v1/cases/{cid}/osint", json={
        "source_name": "Journal fictif", "title": "Fermeture fictive (mise à jour)", "content": body + " Réouverture prévue.",
        "previous_version_id": first["item"]["id"]}).json()
    cmp = a.get(f"/api/v1/cases/{cid}/osint/{first['item']['id']}/compare/{v2['item']['id']}").json()
    assert cmp["hash_changed"] is True and 0.5 < cmp["similarity"] < 1


def test_normalize_url_strips_tracking():
    assert osint.normalize_url("http://WWW.Site.example/a/?utm_medium=x&b=2") == "https://site.example/a?b=2"


def test_correlation_labels_proximity_as_non_causal(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    for title in ("Coupure fictive A", "Incident fictif B"):
        a.post(f"/api/v1/cases/{cid}/events", json={"title": title, "occurred_at": now(-1), "latitude": 5.0,
                                                    "longitude": 5.0, "location_precision": "exact"})
    a.post(f"/api/v1/cases/{cid}/events", json={"title": "Coupure fictive A", "occurred_at": now(-20)})
    res = a.get("/api/v1/analysis/correlations").json()
    assert res["co_occurrences"] and "pas la preuve" in res["co_occurrences"][0]["notice"]
    assert any(c["type"] == "date_conflict" for c in res["contradictions"])
    tl = a.get("/api/v1/analysis/timeline").json()
    assert len(tl) == 3
    feats = a.get("/api/v1/analysis/map").json()
    assert {f["properties"]["precision"] for f in feats["features"]} == {"exact"}


def test_gaps_detection(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "working_hypothesis", "text": "Hypothèse unique fictive"})
    a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "claim", "text": "Déclaration sans source"})
    types = {g["type"] for g in a.get(f"/api/v1/cases/{cid}/gaps").json()}
    assert {"no_alternative_hypothesis", "unsourced_statement"} <= types


def test_assistant_local_engine_cites_material_and_states_limits(actors, nord_case):
    a = actors("analyste.nord")
    cid = nord_case["id"]
    a.post(f"/api/v1/cases/{cid}/statements", json={"kind": "unverified_information", "text": "Info fictive"})
    text = "Le 12 mars 2026, une réunion fictive s'est tenue. Une seconde réunion est annoncée pour le 2026-04-01."
    r = a.post(f"/api/v1/cases/{cid}/assistant", json={"task": "extract_dates", "text": text}).json()
    assert [d["match"] for d in r["items"]] == ["12 mars 2026", "2026-04-01"]
    assert r["engine"] == "local" and "mesure coercitive" in r["notice"]
    q = a.post(f"/api/v1/cases/{cid}/assistant", json={"task": "verification_questions"}).json()
    assert q["items"] and all("about" in i for i in q["items"])
    draft = a.post(f"/api/v1/cases/{cid}/assistant", json={"task": "draft_report"}).json()["draft"]
    assert draft["status"] == "draft_for_human_review" and draft["missing"]
    empty = a.post(f"/api/v1/cases/{cid}/assistant", json={"task": "summarize"}).json()
    assert empty["items"] == [] and empty["missing"]


def test_summarize_is_extractive():
    text = ("La première phrase fictive décrit une situation calme. La seconde phrase fictive décrit un incident "
            "fictif au port. La troisième phrase fictive conclut sur le port fictif.")
    items = assistant.summarize(text, 2)
    assert all(i["text"] in text for i in items)


def test_llm_refuses_classified_material():
    from app.core.config import Settings
    from app.core.errors import ApiError

    s = Settings(environment="test", database_url="sqlite://", jwt_signing_keys={"k": "x" * 40}, jwt_active_kid="k",
                 master_key_b64="A" * 44, llm_endpoint="https://llm.institution.example", llm_max_classification_rank=0)
    with pytest.raises(ApiError):
        assistant.InstitutionalLlm(s).summarize("texte", classification_rank=2)
