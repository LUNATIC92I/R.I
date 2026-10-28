"""Case (dossier) endpoints. Every route resolves the case through ABAC first."""

from __future__ import annotations

import uuid
from datetime import date

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Principal, load_case, require, require_step_up
from app.authz.policy import MANAGE, READ, WRITE, accessible_case_filter
from app.core.errors import ApiError, not_found
from app.db.session import get_db
from app.models import (
    AuditLog,
    Case,
    CaseLink,
    CaseMember,
    Document,
    Entity,
    Event,
    Relation,
    Source,
    Statement,
    ThreatAssessment,
    User,
)
from app.schemas import api as s
from app.services import audit
from app.services import cases as svc

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=list[s.CaseSummaryOut])
def list_cases(
    status: str | None = None,
    category: str | None = None,
    priority: str | None = None,
    owner: uuid.UUID | None = None,
    review_before: date | None = None,
    created_after: date | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require("case:read")),
    db: Session = Depends(get_db),
):
    stmt = select(Case).where(accessible_case_filter(db, principal.user))
    if status:
        stmt = stmt.where(Case.status == status)
    if category:
        stmt = stmt.where(Case.category == category)
    if priority:
        stmt = stmt.where(Case.priority == priority)
    if owner:
        stmt = stmt.where(Case.owner_id == owner)
    if review_before:
        stmt = stmt.where(Case.review_date <= review_before)
    if created_after:
        stmt = stmt.where(func.date(Case.created_at) >= created_after)
    if q:
        stmt = stmt.where(Case.title.ilike(f"%{_escape_like(q)}%", escape="\\") | (Case.reference == q))
    return db.scalars(stmt.order_by(Case.updated_at.desc()).limit(limit).offset(offset)).all()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.post("", response_model=s.CaseOut, status_code=201)
def create_case(data: s.CaseCreateIn, principal: Principal = Depends(require("case:create")), db: Session = Depends(get_db)):
    return svc.create_case(db, principal, data)


@router.get("/{case_id}", response_model=s.CaseOut)
def get_case(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    audit.record(db, principal.audit, "case.view", "consultation", "success", "case", case.id,
                 {"classification_rank": case.classification_rank})
    return case


@router.patch("/{case_id}", response_model=s.CaseOut)
def update_case(case_id: uuid.UUID, data: s.CaseUpdateIn, principal: Principal = Depends(require("case:update")),
                db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return svc.update_case(db, principal, case, data)


@router.post("/{case_id}/status", response_model=s.CaseOut | None)
def change_status(case_id: uuid.UUID, data: s.CaseStatusIn, principal: Principal = Depends(require("case:read")),
                  db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if case is None:
        raise not_found("case")
    svc.lifecycle_access(db, principal, case)
    if data.action in {"request_deletion", "approve_deletion", "archive"}:
        require_step_up(principal, db, f"case.{data.action}")
    return svc.change_status(db, principal, case, data)


@router.post("/{case_id}/offline", response_model=s.CaseOut)
def set_offline(case_id: uuid.UUID, allowed: bool, principal: Principal = Depends(require("case:offline_authorize")),
                db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, MANAGE)
    case.offline_allowed = allowed
    audit.record(db, principal.audit, "case.offline_policy", "case", "success", "case", case.id, {"allowed": allowed})
    return case


@router.get("/{case_id}/history")
def case_history(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    """Consultation and modification history of the case (metadata only)."""
    case = load_case(db, principal, case_id, READ)
    rows = db.scalars(
        select(AuditLog).where(AuditLog.target_id == str(case.id)).order_by(AuditLog.seq.desc()).limit(200)
    ).all()
    return [{"at": r.occurred_at, "actor": r.actor_label, "action": r.action, "outcome": r.outcome} for r in rows]


# --- Members ----------------------------------------------------------------

@router.get("/{case_id}/members", response_model=list[s.MemberOut])
def list_members(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(CaseMember).where(CaseMember.case_id == case.id)).all()


@router.post("/{case_id}/members", response_model=s.MemberOut, status_code=201)
def add_member(case_id: uuid.UUID, data: s.MemberIn, principal: Principal = Depends(require("case:manage_members")),
               db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, MANAGE)
    return svc.add_member(db, principal, case, data)


@router.delete("/{case_id}/members/{user_id}", status_code=204)
def remove_member(case_id: uuid.UUID, user_id: uuid.UUID, principal: Principal = Depends(require("case:manage_members")),
                  db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, MANAGE)
    svc.remove_member(db, principal, case, user_id)


# --- Links between cases ----------------------------------------------------

@router.get("/{case_id}/links")
def list_links(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    links = db.scalars(select(CaseLink).where((CaseLink.from_case_id == case.id) | (CaseLink.to_case_id == case.id))).all()
    visible = set(db.scalars(select(Case.id).where(accessible_case_filter(db, principal.user))).all())
    result = []
    for link in links:
        other = link.to_case_id if link.from_case_id == case.id else link.from_case_id
        # A link to a case outside the user's need to know is shown as masked.
        if other in visible:
            other_case = db.get(Case, other)
            result.append({"case_id": other, "reference": other_case.reference, "title": other_case.title,
                           "rationale": link.rationale, "masked": False})
        else:
            result.append({"case_id": None, "reference": None, "title": None, "rationale": None, "masked": True})
    return result


@router.post("/{case_id}/links", status_code=201)
def add_link(case_id: uuid.UUID, data: s.CaseLinkIn, principal: Principal = Depends(require("case:update")),
             db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    target = load_case(db, principal, data.to_case_id, READ)
    link = svc.link_cases(db, principal, case, target, data.rationale)
    return {"id": link.id}


# --- Sources and statements -------------------------------------------------

@router.get("/{case_id}/sources", response_model=list[s.SourceOut])
def list_sources(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(Source).where(Source.case_id == case.id).order_by(Source.collected_at)).all()


@router.post("/{case_id}/sources", response_model=s.SourceOut, status_code=201)
def add_source(case_id: uuid.UUID, data: s.SourceIn, principal: Principal = Depends(require("statement:write")),
               db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return svc.add_source(db, principal, case, data)


@router.get("/{case_id}/statements", response_model=list[s.StatementOut])
def list_statements(case_id: uuid.UUID, kind: str | None = None, principal: Principal = Depends(require("case:read")),
                    db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    stmt = select(Statement).where(Statement.case_id == case.id)
    if kind:
        stmt = stmt.where(Statement.kind == kind)
    return db.scalars(stmt.order_by(Statement.created_at)).all()


@router.post("/{case_id}/statements", response_model=s.StatementOut, status_code=201)
def add_statement(case_id: uuid.UUID, data: s.StatementIn, principal: Principal = Depends(require("statement:write")),
                  db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return svc.add_statement(db, principal, case, data)


@router.post("/{case_id}/statements/{statement_id}/verify", response_model=s.StatementOut)
def verify_statement(case_id: uuid.UUID, statement_id: uuid.UUID, data: s.StatementVerifyIn,
                     principal: Principal = Depends(require("statement:verify")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    statement = db.get(Statement, statement_id)
    if statement is None or statement.case_id != case.id:
        raise not_found("statement")
    return svc.verify_statement(db, principal, case, statement, data)


# --- Timeline events, entities, relations -----------------------------------

@router.get("/{case_id}/events", response_model=list[s.EventOut])
def list_events(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(Event).where(Event.case_id == case.id).order_by(Event.occurred_at)).all()


@router.post("/{case_id}/events", response_model=s.EventOut, status_code=201)
def add_event(case_id: uuid.UUID, data: s.EventIn, principal: Principal = Depends(require("statement:write")),
              db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return svc.add_event(db, principal, case, data)


@router.get("/{case_id}/entities", response_model=list[s.EntityOut])
def list_entities(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(Entity).where(Entity.case_id == case.id)).all()


@router.post("/{case_id}/entities", response_model=s.EntityOut, status_code=201)
def add_entity(case_id: uuid.UUID, data: s.EntityIn, principal: Principal = Depends(require("statement:write")),
               db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return svc.add_entity(db, principal, case, data)


@router.get("/{case_id}/relations", response_model=list[s.RelationOut])
def list_relations(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(Relation).where(Relation.case_id == case.id)).all()


@router.post("/{case_id}/relations", response_model=s.RelationOut, status_code=201)
def add_relation(case_id: uuid.UUID, data: s.RelationIn, principal: Principal = Depends(require("statement:write")),
                 db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return svc.add_relation(db, principal, case, data)


# --- Documents --------------------------------------------------------------

@router.get("/{case_id}/documents", response_model=list[s.DocumentOut])
def list_documents(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    return db.scalars(select(Document).where(Document.case_id == case.id,
                                             Document.classification_rank <= principal.user.clearance_rank)).all()


@router.post("/{case_id}/documents", response_model=s.DocumentOut, status_code=201)
async def upload_document(
    case_id: uuid.UUID,
    title: str = Form(..., min_length=1, max_length=300),
    classification_rank: int = Form(..., ge=0, le=100),
    document_id: uuid.UUID | None = Form(default=None),
    source_id: uuid.UUID | None = Form(default=None),
    file: UploadFile = File(...),
    principal: Principal = Depends(require("document:upload")),
    db: Session = Depends(get_db),
):
    case = load_case(db, principal, case_id, WRITE)
    content = await file.read(svc.MAX_DOCUMENT_BYTES + 1)
    return svc.upload_document(db, principal, case, title, file.filename or "document",
                               file.content_type or "", content, classification_rank, document_id, source_id)


@router.get("/{case_id}/documents/{document_id}/versions", response_model=list[s.DocumentVersionOut])
def document_versions(case_id: uuid.UUID, document_id: uuid.UUID, principal: Principal = Depends(require("case:read")),
                      db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    document = db.get(Document, document_id)
    if document is None or document.case_id != case.id or document.classification_rank > principal.user.clearance_rank:
        raise not_found("document")
    return document.versions


@router.get("/{case_id}/documents/{document_id}/content")
def download_document(case_id: uuid.UUID, document_id: uuid.UUID, version: int | None = None,
                      principal: Principal = Depends(require("document:download")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    document = db.get(Document, document_id)
    if document is None or document.case_id != case.id:
        raise not_found("document")
    blob, data = svc.read_document(db, principal, document, version)
    return Response(content=data, media_type=blob.mime_type, headers={
        "Content-Disposition": f'attachment; filename="{blob.filename}"',
        "Cache-Control": "no-store",
        "X-Content-SHA256": blob.sha256,
    })


# --- Threat assessments -----------------------------------------------------

def _assessment_out(db: Session, a: ThreatAssessment) -> s.AssessmentOut:
    out = s.AssessmentOut.model_validate(a)
    analyst = db.get(User, a.analyst_id)
    out.analyst_professional_id = analyst.professional_id if analyst else None
    return out


@router.get("/{case_id}/assessments", response_model=list[s.AssessmentOut])
def list_assessments(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, READ)
    rows = db.scalars(select(ThreatAssessment).where(ThreatAssessment.case_id == case.id)
                      .order_by(ThreatAssessment.last_assessed_at.desc())).all()
    return [_assessment_out(db, a) for a in rows]


@router.post("/{case_id}/assessments", response_model=s.AssessmentOut, status_code=201)
def add_assessment(case_id: uuid.UUID, data: s.AssessmentIn, principal: Principal = Depends(require("assessment:write")),
                   db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    return _assessment_out(db, svc.add_assessment(db, principal, case, data))


@router.post("/{case_id}/assessments/{assessment_id}/confirm", response_model=s.AssessmentOut)
def confirm_assessment(case_id: uuid.UUID, assessment_id: uuid.UUID, data: s.AssessmentConfirmIn,
                       principal: Principal = Depends(require("assessment:confirm")), db: Session = Depends(get_db)):
    case = load_case(db, principal, case_id, WRITE)
    assessment = db.get(ThreatAssessment, assessment_id)
    if assessment is None or assessment.case_id != case.id:
        raise not_found("assessment")
    require_step_up(principal, db, "assessment.confirm")
    return _assessment_out(db, svc.confirm_assessment(db, principal, assessment, data.justification))


@router.get("/{case_id}/export-check")
def export_check(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    """Tells the client whether a step-up will be required before an export."""
    case = load_case(db, principal, case_id, READ)
    if not principal.can("report:export"):
        raise ApiError(403, "missing_permission", "report:export")
    return {"case_id": case.id, "step_up_valid": principal.step_up_valid}
