"""OSINT, cyber intelligence, correlation, mapping, graph, assistant and reports."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, load_case, require
from app.authz.policy import READ, WRITE, accessible_case_filter
from app.core.errors import ApiError, not_found
from app.db.session import get_db
from app.models import (
    Case,
    Document,
    Event,
    Indicator,
    OsintItem,
    ReferenceSite,
    Report,
    Source,
    Statement,
    ThreatAssessment,
)
from app.schemas import api as s
from app.services import assistant, audit, correlation, cyber, osint, reports
from app.services.cases import read_document

router = APIRouter(tags=["analysis"])


def _readable_case_ids(db: Session, principal: Principal, case_ids: list[uuid.UUID] | None) -> set[uuid.UUID]:
    allowed = set(db.scalars(select(Case.id).where(accessible_case_filter(db, principal.user))).all())
    if case_ids:
        requested = set(case_ids)
        denied = requested - allowed
        if denied:
            audit.record(db, principal.audit, "correlation.access_denied", "access", "denied",
                         details={"count": len(denied)})
            raise not_found("case")
        return requested
    return allowed


# --- OSINT ------------------------------------------------------------------

@router.get("/cases/{case_id}/osint", response_model=list[s.OsintOut])
def list_osint(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(OsintItem).where(OsintItem.case_id == case.id).order_by(OsintItem.collected_at.desc())).all()


@router.post("/cases/{case_id}/osint", status_code=201)
def add_osint(case_id: uuid.UUID, data: s.OsintIn, principal: Principal = Depends(require("osint:write")),
              db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    item, duplicates = osint.create_item(db, principal, case, data)
    return {"item": s.OsintOut.model_validate(item), "possible_duplicates": duplicates,
            "notice": "Les sources ouvertes peuvent être inexactes ou manipulées : recoupement requis."}


@router.get("/cases/{case_id}/osint/{item_id}/compare/{other_id}")
def compare_osint(case_id: uuid.UUID, item_id: uuid.UUID, other_id: uuid.UUID,
                  principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    a, b = db.get(OsintItem, item_id), db.get(OsintItem, other_id)
    if not a or not b or a.case_id != case.id or b.case_id != case.id:
        raise not_found("osint item")
    return osint.compare_versions(a, b)


@router.get("/cases/{case_id}/osint-clusters")
def osint_clusters(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    items = db.scalars(select(OsintItem).where(OsintItem.case_id == case.id)).all()
    return {"clusters": osint.cluster_publications(list(items))}


# --- Cyber ------------------------------------------------------------------

def _indicator_out(ind: Indicator) -> s.IndicatorOut:
    out = s.IndicatorOut.model_validate(ind)
    out.freshness = cyber.freshness(ind)
    return out


@router.get("/cases/{case_id}/indicators", response_model=list[s.IndicatorOut])
def list_indicators(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return [_indicator_out(i) for i in db.scalars(select(Indicator).where(Indicator.case_id == case.id))]


@router.post("/cases/{case_id}/indicators", response_model=s.IndicatorOut, status_code=201)
def add_indicator(case_id: uuid.UUID, data: s.IndicatorIn, principal: Principal = Depends(require("cyber:write")),
                  db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return _indicator_out(cyber.create_indicator(db, principal, case, data))


def _case_indicator(db: Session, principal: Principal, case_id: uuid.UUID, indicator_id: uuid.UUID) -> Indicator:
    case = load_case(db, principal, case_id, WRITE)
    ind = db.get(Indicator, indicator_id)
    if ind is None or ind.case_id != case.id:
        raise not_found("indicator")
    return ind


@router.post("/cases/{case_id}/indicators/{indicator_id}/verdict", response_model=s.IndicatorOut)
def indicator_verdict(case_id: uuid.UUID, indicator_id: uuid.UUID, data: s.IndicatorVerdictIn,
                      principal: Principal = Depends(require("cyber:verdict")), db: Session = Depends(get_db)):
    ind = _case_indicator(db, principal, case_id, indicator_id)
    return _indicator_out(cyber.set_verdict(db, principal, ind, data.verdict, data.justification))


@router.post("/cases/{case_id}/indicators/{indicator_id}/enrich", response_model=s.IndicatorOut)
def indicator_enrich(case_id: uuid.UUID, indicator_id: uuid.UUID, principal: Principal = Depends(require("cyber:write")),
                     db: Session = Depends(get_db)):
    ind = _case_indicator(db, principal, case_id, indicator_id)
    return _indicator_out(cyber.enrich(db, principal, ind))


@router.post("/cases/{case_id}/indicators/import-stix")
def import_stix(case_id: uuid.UUID, data: s.StixImportIn, principal: Principal = Depends(require("cyber:write")),
                db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return cyber.import_stix(db, principal, case, data.bundle, data.provenance)


@router.get("/cyber/campaigns")
def campaigns(principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    ids = _readable_case_ids(db, principal, None)
    rows = db.scalars(select(Indicator).where(Indicator.case_id.in_(ids), Indicator.campaign.is_not(None))).all() if ids else []
    out: dict[str, dict] = {}
    for ind in rows:
        c = out.setdefault(ind.campaign, {"campaign": ind.campaign, "indicators": 0, "types": set(), "last_seen": None})
        c["indicators"] += 1
        c["types"].add(ind.type)
        c["last_seen"] = max(filter(None, [c["last_seen"], ind.last_seen]))
    return [{**c, "types": sorted(c["types"])} for c in out.values()]


@router.get("/cases/{case_id}/indicator-graph")
def indicator_graph(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    """Links between indicators of a case that share a campaign or a provenance."""
    case = load_case(db, principal, case_id, READ)
    inds = db.scalars(select(Indicator).where(Indicator.case_id == case.id)).all()
    edges = []
    for i, a in enumerate(inds):
        for b in inds[i + 1:]:
            basis = [k for k, ok in (("campaign", a.campaign and a.campaign == b.campaign),
                                     ("provenance", a.provenance == b.provenance)) if ok]
            if basis:
                edges.append({"from": a.id, "to": b.id, "basis": basis})
    return {"nodes": [{"id": i.id, "type": i.type, "value": i.value, "verdict": i.verdict} for i in inds],
            "edges": edges, "notice": correlation.CO_OCCURRENCE_NOTICE}


# --- Correlation, timeline, map, graph --------------------------------------

@router.get("/analysis/timeline")
def timeline(case_ids: list[uuid.UUID] | None = Query(default=None), principal: Principal = Depends(require("case:read")),
             db: Session = Depends(get_db)):
    return correlation.timeline(db, _readable_case_ids(db, principal, case_ids))


@router.get("/analysis/correlations")
def correlations(case_ids: list[uuid.UUID] | None = Query(default=None), hours: int = Query(48, ge=1, le=720),
                 km: float = Query(10.0, gt=0, le=500), principal: Principal = Depends(require("case:read")),
                 db: Session = Depends(get_db)):
    ids = _readable_case_ids(db, principal, case_ids)
    audit.record(db, principal.audit, "correlation.run", "analysis", "success", details={"cases": len(ids)})
    return {"co_occurrences": correlation.co_occurrences(db, ids, hours, km),
            "contradictions": correlation.contradictions(db, ids), "notice": correlation.CO_OCCURRENCE_NOTICE}


@router.get("/cases/{case_id}/gaps")
def case_gaps(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return correlation.gaps(db, case.id)


@router.get("/cases/{case_id}/graph")
def case_graph(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return correlation.relation_graph(db, case.id)


@router.get("/analysis/map")
def geo_map(case_ids: list[uuid.UUID] | None = Query(default=None), category: str | None = None,
            start: datetime | None = None, end: datetime | None = None, include_sites: bool = True,
            principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    """GeoJSON of authorised, geolocated events plus declared reference sites."""
    ids = _readable_case_ids(db, principal, case_ids)
    features = []
    if ids:
        stmt = select(Event).where(Event.case_id.in_(ids), Event.latitude.is_not(None))
        if category:
            stmt = stmt.where(Event.category == category)
        if start:
            stmt = stmt.where(Event.occurred_at >= start)
        if end:
            stmt = stmt.where(Event.occurred_at <= end)
        for e in db.scalars(stmt):
            features.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [e.longitude, e.latitude]},
                             "properties": {"kind": "event", "id": str(e.id), "case_id": str(e.case_id),
                                            "title": e.title, "category": e.category,
                                            "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                                            "precision": e.location_precision, "accuracy_m": e.location_accuracy_m,
                                            "provenance": e.location_provenance}})
    unlocated = db.scalar(select(Event.id).where(Event.case_id.in_(ids), Event.latitude.is_(None)).limit(1)) if ids else None
    if include_sites:
        for site in db.scalars(select(ReferenceSite).where(ReferenceSite.classification_rank <= principal.user.clearance_rank)):
            features.append({"type": "Feature",
                             "geometry": {"type": "Point", "coordinates": [site.longitude, site.latitude]},
                             "properties": {"kind": "reference_site", "id": str(site.id), "title": site.name,
                                            "sector": site.sector, "precision": site.location_precision,
                                            "provenance": site.referential}})
    audit.record(db, principal.audit, "map.view", "consultation", "success", details={"features": len(features)})
    return {"type": "FeatureCollection", "features": features,
            "meta": {"events_without_location": unlocated is not None,
                     "notice": "Précision des coordonnées indiquée pour chaque point. Une localisation approximative "
                               "ou inconnue ne doit pas être interprétée comme exacte."}}


# --- Assistant --------------------------------------------------------------

@router.post("/cases/{case_id}/assistant")
def run_assistant(case_id: uuid.UUID, data: s.AssistantIn, principal: Principal = Depends(require("assistant:use")),
                  db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    text, ref = data.text, "input_text" if data.text else None
    if data.document_id:
        document = db.get(Document, data.document_id)
        if document is None or document.case_id != case.id:
            raise not_found("document")
        if not principal.can("document:download"):
            raise ApiError(403, "missing_permission", "document:download")
        blob, raw = read_document(db, principal, document, None)
        if not blob.mime_type.startswith("text/"):
            raise ApiError(400, "assistant_text_only", "Only plain-text documents can be analysed locally")
        text, ref = raw.decode("utf-8", errors="replace"), f"document:{document.id}:v{blob.version}"
    statements = db.scalars(select(Statement).where(Statement.case_id == case.id)).all()
    sources = db.scalars(select(Source).where(Source.case_id == case.id)).all()
    assessments = db.scalars(select(ThreatAssessment).where(ThreatAssessment.case_id == case.id)).all()
    result = assistant.run(db, case, data.task, statements, sources, assessments, text, ref)
    audit.record(db, principal.audit, "assistant.run", "analysis", "success", "case", case.id,
                 {"task": data.task, "engine": result["engine"]})
    return result


# --- Reports ----------------------------------------------------------------

def _case_report(db: Session, principal: Principal, case_id: uuid.UUID, report_id: uuid.UUID, level: str):
    case = load_case(db, principal, case_id, level)
    report = db.get(Report, report_id)
    if report is None or report.case_id != case.id or report.classification_rank > principal.user.clearance_rank:
        raise not_found("report")
    return case, report


@router.get("/cases/{case_id}/reports", response_model=list[s.ReportOut])
def list_reports(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(Report).where(Report.case_id == case.id,
                                           Report.classification_rank <= principal.user.clearance_rank)).all()


@router.post("/cases/{case_id}/reports", response_model=s.ReportOut, status_code=201)
def create_report(case_id: uuid.UUID, data: s.ReportIn, principal: Principal = Depends(require("report:write")),
                  db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return reports.create_report(db, principal, case, data)


@router.get("/cases/{case_id}/reports/{report_id}", response_model=s.ReportOut)
def get_report(case_id: uuid.UUID, report_id: uuid.UUID, principal: Principal = Depends(require("case:read")),
               db: Session = Depends(get_db)):
    _, report = _case_report(db, principal, case_id, report_id, READ)
    return report


@router.patch("/cases/{case_id}/reports/{report_id}", response_model=s.ReportOut)
def update_report(case_id: uuid.UUID, report_id: uuid.UUID, data: s.ReportUpdateIn,
                  principal: Principal = Depends(require("report:write")), db: Session = Depends(get_db)):
    case, report = _case_report(db, principal, case_id, report_id, WRITE)
    return reports.update_report(db, principal, case, report, data)


@router.post("/cases/{case_id}/reports/{report_id}/submit", response_model=s.ReportOut)
def submit_report(case_id: uuid.UUID, report_id: uuid.UUID, principal: Principal = Depends(require("report:write")),
                  db: Session = Depends(get_db)):
    case, report = _case_report(db, principal, case_id, report_id, WRITE)
    return reports.submit_report(db, principal, case, report)


@router.post("/cases/{case_id}/reports/{report_id}/decision", response_model=s.ReportOut)
def decide_report(case_id: uuid.UUID, report_id: uuid.UUID, data: s.ReportDecisionIn,
                  principal: Principal = Depends(require("report:validate")), db: Session = Depends(get_db)):
    _, report = _case_report(db, principal, case_id, report_id, READ)
    return reports.decide_report(db, principal, report, data.decision, data.comment)


@router.get("/cases/{case_id}/reports/{report_id}/export")
def export_report(case_id: uuid.UUID, report_id: uuid.UUID, fmt: str = Query("pdf", pattern="^(pdf|docx)$"),
                  principal: Principal = Depends(require("report:export")), db: Session = Depends(get_db)):
    case, report = _case_report(db, principal, case_id, report_id, READ)
    data, mime, filename = reports.export_report(db, principal, case, report, fmt)
    return Response(content=data, media_type=mime, headers={
        "Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})


@router.get("/reports/pending-validation", response_model=list[s.ReportOut])
def pending_validation(principal: Principal = Depends(require("report:validate")), db: Session = Depends(get_db)):
    ids = _readable_case_ids(db, principal, None)
    if not ids:
        return []
    return db.scalars(select(Report).where(Report.case_id.in_(ids), Report.status == "submitted",
                                           Report.author_id != principal.id,
                                           Report.classification_rank <= principal.user.clearance_rank)).all()

