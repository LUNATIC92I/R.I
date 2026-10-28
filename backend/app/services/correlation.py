"""Timelines, co-occurrence candidates, contradictions and information gaps.

All functions take the set of case ids the caller is allowed to read and never
look outside of it. Co-occurrences are *candidates for analysis*, labelled as
such: proximity in time, space or documentation is never presented as a
causal relation.
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import ensure_aware
from app.models import (
    Document,
    DocumentBlob,
    Entity,
    Event,
    Indicator,
    Relation,
    Source,
    Statement,
    ThreatAssessment,
)

CO_OCCURRENCE_NOTICE = (
    "Rapprochement fondé sur une proximité temporelle, géographique ou documentaire. "
    "Ce n'est pas la preuve d'une relation causale. / Proximity-based candidate, not evidence of causation."
)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def timeline(db: Session, case_ids: set[uuid.UUID]) -> list[dict]:
    if not case_ids:
        return []
    events = db.scalars(select(Event).where(Event.case_id.in_(case_ids))).all()
    dated = sorted((e for e in events if e.occurred_at), key=lambda e: ensure_aware(e.occurred_at))
    undated = [e for e in events if not e.occurred_at]
    return [_event_dict(e) for e in dated] + [_event_dict(e) for e in undated]


def _event_dict(e: Event) -> dict:
    return {
        "id": e.id, "case_id": e.case_id, "title": e.title, "category": e.category,
        "occurred_at": e.occurred_at, "occurred_until": e.occurred_until, "date_precision": e.date_precision,
        "location_label": e.location_label, "location_precision": e.location_precision,
        "source_id": e.source_id, "document_id": e.document_id,
    }


def _location_uncertainty_km(e: Event) -> float:
    if e.location_accuracy_m:
        return e.location_accuracy_m / 1000
    return {"exact": 0.1, "approximate": 5.0, "region": 50.0}.get(e.location_precision, math.inf)


def co_occurrences(db: Session, case_ids: set[uuid.UUID], hours: int = 48, km: float = 10.0) -> list[dict]:
    if not case_ids:
        return []
    events = [e for e in db.scalars(select(Event).where(Event.case_id.in_(case_ids))).all()]
    results = []
    window = timedelta(hours=hours)
    for i, a in enumerate(events):
        for b in events[i + 1:]:
            bases = []
            if a.occurred_at and b.occurred_at and abs(ensure_aware(a.occurred_at) - ensure_aware(b.occurred_at)) <= window:
                bases.append("temporal")
            if a.latitude is not None and b.latitude is not None:
                distance = haversine_km(a.latitude, a.longitude, b.latitude, b.longitude)
                uncertainty = _location_uncertainty_km(a) + _location_uncertainty_km(b)
                if distance <= km:
                    bases.append("geographic")
                    if uncertainty > km:
                        bases.append("geographic_uncertain")
            if a.document_id and a.document_id == b.document_id:
                bases.append("shared_document")
            if a.source_id and a.source_id == b.source_id:
                bases.append("shared_source")
            if len([x for x in bases if x != "geographic_uncertain"]) >= 2 or "shared_document" in bases:
                results.append({
                    "event_a": a.id, "event_b": b.id, "basis": bases, "cross_case": a.case_id != b.case_id,
                    "confidence": "low", "notice": CO_OCCURRENCE_NOTICE,
                })
    results.extend(_shared_document_hashes(db, case_ids))
    results.extend(_shared_indicators(db, case_ids))
    return results


def _shared_document_hashes(db: Session, case_ids: set[uuid.UUID]) -> list[dict]:
    rows = db.execute(
        select(DocumentBlob.sha256, Document.case_id, Document.id)
        .join(Document, Document.id == DocumentBlob.document_id).where(Document.case_id.in_(case_ids))
    ).all()
    by_hash: dict[str, set] = defaultdict(set)
    for sha, case_id, doc_id in rows:
        by_hash[sha].add((case_id, doc_id))
    return [
        {"documents": sorted(str(d) for _, d in refs), "basis": ["identical_document_hash"],
         "cross_case": len({c for c, _ in refs}) > 1, "confidence": "moderate", "notice": CO_OCCURRENCE_NOTICE}
        for refs in by_hash.values() if len({d for _, d in refs}) > 1
    ]


def _shared_indicators(db: Session, case_ids: set[uuid.UUID]) -> list[dict]:
    rows = db.execute(select(Indicator.value_hash, Indicator.case_id, Indicator.id)
                      .where(Indicator.case_id.in_(case_ids))).all()
    by_hash: dict[str, list] = defaultdict(list)
    for vh, case_id, ind_id in rows:
        by_hash[vh].append((case_id, ind_id))
    return [
        {"indicators": [str(i) for _, i in refs], "basis": ["shared_technical_indicator"], "cross_case": True,
         "confidence": "low", "notice": CO_OCCURRENCE_NOTICE}
        for refs in by_hash.values() if len({c for c, _ in refs}) > 1
    ]


def contradictions(db: Session, case_ids: set[uuid.UUID]) -> list[dict]:
    """Explicitly linked contradictions plus conflicting dates for identically titled events."""
    if not case_ids:
        return []
    out = []
    statements = db.scalars(select(Statement).where(Statement.case_id.in_(case_ids))).all()
    by_id = {st.id: st for st in statements}
    for st in statements:
        if st.contradicts_id and st.contradicts_id in by_id:
            out.append({"type": "declared_contradiction", "items": [st.id, st.contradicts_id],
                        "detail": "Contradiction déclarée entre deux éléments."})
    events = db.scalars(select(Event).where(Event.case_id.in_(case_ids))).all()
    by_title: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_title[e.title.strip().lower()].append(e)
    for group in by_title.values():
        dates = {ensure_aware(e.occurred_at).date() for e in group if e.occurred_at}
        if len(dates) > 1:
            out.append({"type": "date_conflict", "items": [e.id for e in group],
                        "detail": "Le même événement est daté différemment selon les rapports."})
    return out


def gaps(db: Session, case_id: uuid.UUID) -> list[dict]:
    out = []
    statements = db.scalars(select(Statement).where(Statement.case_id == case_id)).all()
    for st in statements:
        if st.kind in {"unverified_information", "claim"} and st.source_id is None:
            out.append({"type": "unsourced_statement", "item": st.id, "detail": "Élément sans source rattachée."})
    hypotheses = [st for st in statements if st.kind == "working_hypothesis"]
    if hypotheses and not any(st.kind == "alternative_hypothesis" for st in statements):
        out.append({"type": "no_alternative_hypothesis", "item": None,
                    "detail": "Aucune hypothèse alternative n'a été formulée."})
    events = sorted((e for e in db.scalars(select(Event).where(Event.case_id == case_id)) if e.occurred_at),
                    key=lambda e: ensure_aware(e.occurred_at))
    for a, b in zip(events, events[1:], strict=False):
        delta = ensure_aware(b.occurred_at) - ensure_aware(a.occurred_at)
        if delta > timedelta(days=30):
            out.append({"type": "timeline_gap", "item": [a.id, b.id],
                        "detail": f"Période de {delta.days} jours sans événement documenté."})
    undated = [e.id for e in db.scalars(select(Event).where(Event.case_id == case_id, Event.occurred_at.is_(None)))]
    if undated:
        out.append({"type": "undated_events", "item": undated, "detail": "Événements sans date."})
    for a in db.scalars(select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)):
        if not a.alternative_hypotheses:
            out.append({"type": "assessment_without_alternatives", "item": a.id,
                        "detail": "Évaluation sans hypothèse alternative."})
        if not a.source_ids:
            out.append({"type": "assessment_without_sources", "item": a.id, "detail": "Évaluation sans source."})
    sources = db.scalars(select(Source).where(Source.case_id == case_id)).all()
    if sources and all(src.reliability in {"E", "F"} for src in sources):
        out.append({"type": "low_reliability_sources", "item": None,
                    "detail": "Toutes les sources sont de fiabilité faible ou indéterminée."})
    return out


def relation_graph(db: Session, case_id: uuid.UUID) -> dict:
    entities = db.scalars(select(Entity).where(Entity.case_id == case_id)).all()
    relations = db.scalars(select(Relation).where(Relation.case_id == case_id)).all()
    return {
        "nodes": [{"id": e.id, "label": e.label, "kind": e.kind} for e in entities],
        "edges": [{
            "id": r.id, "from": r.from_entity_id, "to": r.to_entity_id, "type": r.relation_type,
            "basis": r.basis, "source_id": r.source_id, "confidence": r.confidence, "causal": r.is_causal_claim,
        } for r in relations],
        "notice": "Seules les relations documentées sont affichées, avec leur origine et leur niveau de confiance.",
    }
