"""Case lifecycle and content management."""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from app.api.deps import Principal
from app.authz.policy import MANAGE, decide_case
from app.core.context import ctx
from app.core.crypto import Sealed, sha256_hex
from app.core.errors import ApiError, bad_request, conflict, not_found
from app.core.security import ensure_aware, utcnow
from app.models import (
    Case,
    CaseLink,
    CaseMember,
    ClassificationLevel,
    Document,
    DocumentBlob,
    Entity,
    Event,
    RetentionRule,
    Source,
    Statement,
    ThreatAssessment,
    User,
)
from app.schemas import api as s
from app.services import audit
from app.services.notifications import notify

MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
ALLOWED_MIME = {
    "application/pdf", "text/plain", "image/png", "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
# Magic numbers checked against the declared type to reject disguised files.
_MAGIC = {
    "application/pdf": [b"%PDF"],
    "image/png": [b"\x89PNG"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [b"PK\x03\x04"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [b"PK\x03\x04"],
}


def _check_classification(db: Session, principal: Principal, rank: int) -> ClassificationLevel:
    level = db.scalar(select(ClassificationLevel).where(ClassificationLevel.rank == rank))
    if level is None:
        raise bad_request("unknown_classification")
    if rank > principal.user.clearance_rank:
        raise ApiError(403, "classification_above_clearance")
    return level


def _new_reference(db: Session, prefix: str) -> str:
    year = utcnow().year
    while True:
        ref = f"{prefix}-{year}-{secrets.token_hex(3).upper()}"
        if db.scalar(select(Case.id).where(Case.reference == ref)) is None:
            return ref


def create_case(db: Session, principal: Principal, data: s.CaseCreateIn) -> Case:
    _check_classification(db, principal, data.classification_rank)
    rule = db.scalar(select(RetentionRule).where(RetentionRule.code == data.retention_rule_code))
    if rule is None:
        raise bad_request("unknown_retention_rule")
    service_id = data.service_id or principal.user.service_id
    if service_id != principal.user.service_id and "service" not in {r.case_scope for r in principal.user.roles}:
        raise ApiError(403, "cannot_create_for_other_service")
    if data.review_date <= utcnow().date():
        raise bad_request("review_date_must_be_future")
    case = Case(
        reference=_new_reference(db, data.country_code),
        title=data.title, category=data.category, country_code=data.country_code,
        jurisdiction=data.jurisdiction, owner_id=principal.id, service_id=service_id,
        classification_rank=data.classification_rank, priority=data.priority,
        executive_summary=data.executive_summary, analysis_context=data.analysis_context,
        legal_basis=data.legal_basis, authorised_follow_up=data.authorised_follow_up,
        review_date=data.review_date, retention_rule_id=rule.id,
    )
    db.add(case)
    db.flush()
    db.add(CaseMember(case_id=case.id, user_id=principal.id, access="write", granted_by=principal.id,
                      justification="Responsable du dossier", granted_at=utcnow()))
    audit.record(db, principal.audit, "case.create", "case", "success", "case", case.id,
                 {"classification_rank": case.classification_rank, "category": case.category}, commit=False)
    db.commit()
    return case


def update_case(db: Session, principal: Principal, case: Case, data: s.CaseUpdateIn) -> Case:
    if data.version != case.version:
        raise conflict("version_conflict", "The case was modified by someone else")
    changes = data.model_dump(exclude_unset=True, exclude={"version"})
    if "classification_rank" in changes:
        _check_classification(db, principal, changes["classification_rank"])
        if changes["classification_rank"] < case.classification_rank and not principal.can("case:close"):
            raise ApiError(403, "declassification_requires_supervisor")
    for key, value in changes.items():
        setattr(case, key, value)
    try:
        audit.record(db, principal.audit, "case.update", "case", "success", "case", case.id,
                     {"fields": sorted(changes)}, commit=False)
        db.commit()
    except StaleDataError:
        db.rollback()
        raise conflict("version_conflict") from None
    _notify_members(db, case, principal.id)
    db.commit()
    return case


def _notify_members(db: Session, case: Case, actor: uuid.UUID) -> None:
    ids = [m.user_id for m in db.scalars(select(CaseMember).where(CaseMember.case_id == case.id)) if m.user_id != actor]
    notify(db, ids, "case_activity", "case", case.id)


def change_status(db: Session, principal: Principal, case: Case, data: s.CaseStatusIn) -> Case | None:
    action = data.action
    transitions = {
        "submit_review": ({"open"}, "under_review", "case:update"),
        "close": ({"open", "under_review"}, "closed", "case:close"),
        "reopen": ({"closed"}, "open", "case:close"),
        "archive": ({"closed"}, "archived", "case:archive"),
        "request_deletion": ({"closed", "archived"}, "pending_deletion", "case:delete_request"),
        "approve_deletion": ({"pending_deletion"}, None, "case:delete_approve"),
    }
    allowed_from, target, permission = transitions[action]
    if not principal.can(permission):
        raise ApiError(403, "missing_permission", permission)
    if case.status not in allowed_from:
        raise conflict("invalid_transition", f"{case.status} -> {action}")
    now = utcnow()
    if action == "request_deletion":
        rule = db.get(RetentionRule, case.retention_rule_id)
        expiry = ensure_aware(case.created_at) + timedelta(days=rule.retention_days)
        case.deletion_requested_by = principal.id
        case.deletion_justification = data.justification
        details = {"retention_expired": expiry <= now}
    elif action == "approve_deletion":
        if case.deletion_requested_by == principal.id:
            raise ApiError(403, "four_eyes_required", "Deletion must be approved by another person")
        audit.record(db, principal.audit, "case.delete", "case", "success", "case", case.id,
                     {"reference": case.reference, "requested_by": str(case.deletion_requested_by),
                      "justification": data.justification}, commit=False)
        db.delete(case)
        db.commit()
        return None
    else:
        details = {}
    case.status = target
    if target == "closed":
        case.closed_at = now
    if target == "archived":
        case.archived_at = now
    if action == "reopen":
        case.closed_at = None
    audit.record(db, principal.audit, f"case.{action}", "case", "success", "case", case.id,
                 {"justification": data.justification, **details}, commit=False)
    db.commit()
    return case


def lifecycle_access(db: Session, principal: Principal, case: Case) -> None:
    decision = decide_case(db, principal.user, case, MANAGE)
    if not decision.allowed and decision.reason != "case_read_only":
        audit.record(db, principal.audit, "case.access_denied", "access", "denied", "case", case.id,
                     {"level": MANAGE, "reason": decision.reason})
        raise not_found("case")


def add_member(db: Session, principal: Principal, case: Case, data: s.MemberIn) -> CaseMember:
    user = db.get(User, data.user_id)
    if user is None or not user.is_active:
        raise bad_request("unknown_user")
    if user.clearance_rank < case.classification_rank:
        raise bad_request("user_clearance_insufficient")
    if {r.case_scope for r in user.roles} <= {"none"}:
        raise bad_request("role_cannot_access_cases")
    member = db.scalar(select(CaseMember).where(CaseMember.case_id == case.id, CaseMember.user_id == user.id))
    if member is None:
        member = CaseMember(case_id=case.id, user_id=user.id, granted_by=principal.id,
                            justification=data.justification, granted_at=utcnow())
        db.add(member)
    member.access = data.access
    member.expires_at = data.expires_at
    member.justification = data.justification
    audit.record(db, principal.audit, "case.member_grant", "permission", "success", "case", case.id,
                 {"user_id": str(user.id), "access": data.access}, commit=False)
    notify(db, [user.id], "access_granted", "case", case.id)
    db.commit()
    return member


def remove_member(db: Session, principal: Principal, case: Case, user_id: uuid.UUID) -> None:
    member = db.scalar(select(CaseMember).where(CaseMember.case_id == case.id, CaseMember.user_id == user_id))
    if member is None:
        raise not_found("member")
    if user_id == case.owner_id:
        raise bad_request("cannot_remove_owner")
    db.delete(member)
    audit.record(db, principal.audit, "case.member_revoke", "permission", "success", "case", case.id,
                 {"user_id": str(user_id)}, commit=False)
    db.commit()


def link_cases(db: Session, principal: Principal, case: Case, target: Case, rationale: str) -> CaseLink:
    if target.id == case.id:
        raise bad_request("cannot_link_to_itself")
    link = CaseLink(from_case_id=case.id, to_case_id=target.id, rationale=rationale,
                    created_by=principal.id, created_at=utcnow())
    db.add(link)
    audit.record(db, principal.audit, "case.link", "case", "success", "case", case.id,
                 {"to_case_id": str(target.id)}, commit=False)
    db.commit()
    return link


def _case_child(db: Session, model, case: Case, obj_id: uuid.UUID | None, kind: str):
    """Load a child object and make sure it belongs to the same case (anti-IDOR)."""
    if obj_id is None:
        return None
    obj = db.get(model, obj_id)
    if obj is None or obj.case_id != case.id:
        raise bad_request(f"{kind}_not_in_case")
    return obj


def add_source(db: Session, principal: Principal, case: Case, data: s.SourceIn) -> Source:
    if data.kind == "human_protected" and not data.protected_reference:
        raise bad_request("protected_reference_required",
                          "Protected human sources are referenced by registry code only, never by identity")
    source = Source(case_id=case.id, created_by=principal.id,
                    collected_at=data.collected_at or utcnow(), **data.model_dump(exclude={"collected_at"}))
    db.add(source)
    db.flush()
    audit.record(db, principal.audit, "source.create", "case_content", "success", "source", source.id,
                 {"case_id": str(case.id), "kind": data.kind}, commit=False)
    db.commit()
    return source


def add_statement(db: Session, principal: Principal, case: Case, data: s.StatementIn) -> Statement:
    _case_child(db, Source, case, data.source_id, "source")
    _case_child(db, Statement, case, data.contradicts_id, "statement")
    statement = Statement(case_id=case.id, created_by=principal.id, **data.model_dump())
    db.add(statement)
    db.flush()
    audit.record(db, principal.audit, "statement.create", "case_content", "success", "statement", statement.id,
                 {"case_id": str(case.id), "kind": data.kind}, commit=False)
    db.commit()
    return statement


def verify_statement(db: Session, principal: Principal, case: Case, statement: Statement,
                     data: s.StatementVerifyIn) -> Statement:
    if statement.version != data.version:
        raise conflict("version_conflict")
    if statement.created_by == principal.id:
        raise ApiError(403, "four_eyes_required", "A fact must be confirmed by someone other than its author")
    _case_child(db, Source, case, data.source_id, "source")
    statement.kind = "confirmed_fact"
    statement.source_id = data.source_id
    statement.credibility = data.credibility
    statement.verified_by = principal.id
    statement.verified_at = utcnow()
    audit.record(db, principal.audit, "statement.verify", "case_content", "success", "statement", statement.id,
                 {"case_id": str(case.id)}, commit=False)
    db.commit()
    return statement


def add_event(db: Session, principal: Principal, case: Case, data: s.EventIn) -> Event:
    _case_child(db, Source, case, data.source_id, "source")
    _case_child(db, Document, case, data.document_id, "document")
    if data.latitude is None and data.location_precision != "unknown":
        raise bad_request("coordinates_required_for_precision")
    if data.latitude is not None and data.location_precision == "unknown":
        raise bad_request("precision_required_with_coordinates")
    if (data.latitude is None) != (data.longitude is None):
        raise bad_request("incomplete_coordinates")
    if data.occurred_until and data.occurred_at and data.occurred_until < data.occurred_at:
        raise bad_request("invalid_period")
    event = Event(case_id=case.id, created_by=principal.id, **data.model_dump())
    db.add(event)
    db.flush()
    audit.record(db, principal.audit, "event.create", "case_content", "success", "event", event.id,
                 {"case_id": str(case.id)}, commit=False)
    db.commit()
    return event


def add_entity(db: Session, principal: Principal, case: Case, data: s.EntityIn) -> Entity:
    entity = Entity(case_id=case.id, created_by=principal.id, **data.model_dump())
    db.add(entity)
    db.flush()
    audit.record(db, principal.audit, "entity.create", "case_content", "success", "entity", entity.id,
                 {"case_id": str(case.id), "kind": data.kind}, commit=False)
    db.commit()
    return entity


def add_relation(db: Session, principal: Principal, case: Case, data: s.RelationIn):
    from app.models import Relation

    _case_child(db, Entity, case, data.from_entity_id, "entity")
    _case_child(db, Entity, case, data.to_entity_id, "entity")
    _case_child(db, Source, case, data.source_id, "source")
    if data.is_causal_claim and (data.source_id is None or data.confidence == "low"):
        raise bad_request("causal_claim_requires_source",
                          "A causal relation needs a documented source and at least moderate confidence")
    relation = Relation(case_id=case.id, created_by=principal.id, **data.model_dump())
    db.add(relation)
    db.flush()
    audit.record(db, principal.audit, "relation.create", "case_content", "success", "relation", relation.id,
                 {"case_id": str(case.id)}, commit=False)
    db.commit()
    return relation


def upload_document(db: Session, principal: Principal, case: Case, title: str, filename: str, mime: str,
                    content: bytes, classification_rank: int, document_id: uuid.UUID | None,
                    source_id: uuid.UUID | None) -> Document:
    if len(content) == 0 or len(content) > MAX_DOCUMENT_BYTES:
        raise bad_request("invalid_size")
    if mime not in ALLOWED_MIME:
        raise bad_request("unsupported_type")
    if mime in _MAGIC and not any(content.startswith(m) for m in _MAGIC[mime]):
        raise bad_request("content_type_mismatch")
    if classification_rank < case.classification_rank:
        raise bad_request("document_below_case_classification")
    _check_classification(db, principal, classification_rank)
    _case_child(db, Source, case, source_id, "source")
    if document_id:
        document = _case_child(db, Document, case, document_id, "document")
    else:
        document = Document(case_id=case.id, title=title[:300], classification_rank=classification_rank,
                            source_id=source_id, created_by=principal.id)
        db.add(document)
        db.flush()
    document.current_version += 1
    aad = f"{document.id}:{document.current_version}".encode()
    sealed = ctx().cipher.seal(content, aad)
    db.add(DocumentBlob(
        document_id=document.id, version=document.current_version, filename=_safe_filename(filename),
        mime_type=mime, size_bytes=len(content), sha256=sha256_hex(content), wrapped_key=sealed.wrapped_key,
        key_id=sealed.key_id, nonce=sealed.nonce, ciphertext=sealed.ciphertext, uploaded_by=principal.id,
        uploaded_at=utcnow(),
    ))
    audit.record(db, principal.audit, "document.upload", "document", "success", "document", document.id,
                 {"case_id": str(case.id), "version": document.current_version, "size": len(content)}, commit=False)
    db.commit()
    return document


def _safe_filename(name: str) -> str:
    keep = "".join(c for c in name if c.isalnum() or c in "._- ")[:200].strip()
    return keep or "document"


def read_document(db: Session, principal: Principal, document: Document, version: int | None) -> tuple[DocumentBlob, bytes]:
    if not document.download_allowed:
        raise ApiError(403, "download_disabled")
    if principal.user.clearance_rank < document.classification_rank:
        raise not_found("document")
    level = db.scalar(select(ClassificationLevel).where(ClassificationLevel.rank == document.classification_rank))
    if level and level.export_requires_step_up and not principal.step_up_valid:
        audit.record(db, principal.audit, "document.download", "document", "denied", "document", document.id,
                     {"reason": "step_up_required"})
        raise ApiError(403, "step_up_required")
    wanted = version or document.current_version
    blob = next((b for b in document.versions if b.version == wanted), None)
    if blob is None:
        raise not_found("document version")
    try:
        plaintext = ctx().cipher.open(Sealed(blob.key_id, blob.wrapped_key, blob.nonce, blob.ciphertext),
                                      f"{document.id}:{blob.version}".encode())
    except (InvalidTag, KeyError):
        plaintext = None
    if plaintext is None or sha256_hex(plaintext) != blob.sha256:
        audit.record(db, principal.audit, "document.integrity_failure", "security", "failure", "document", document.id,
                     {"version": wanted})
        raise ApiError(500, "integrity_failure")
    audit.record(db, principal.audit, "document.download", "document", "success", "document", document.id,
                 {"version": wanted})
    return blob, plaintext


def add_assessment(db: Session, principal: Principal, case: Case, data: s.AssessmentIn) -> ThreatAssessment:
    for sid in data.source_ids:
        _case_child(db, Source, case, sid, "source")
    payload = data.model_dump()
    payload["source_ids"] = [str(x) for x in data.source_ids]
    assessment = ThreatAssessment(case_id=case.id, analyst_id=principal.id, last_assessed_at=utcnow(), **payload)
    db.add(assessment)
    db.flush()
    audit.record(db, principal.audit, "assessment.create", "analysis", "success", "assessment", assessment.id,
                 {"case_id": str(case.id), "level": data.level}, commit=False)
    db.commit()
    return assessment


def confirm_assessment(db: Session, principal: Principal, assessment: ThreatAssessment, justification: str):
    if assessment.analyst_id == principal.id:
        raise ApiError(403, "four_eyes_required")
    if not assessment.source_ids:
        raise bad_request("confirmation_requires_sources")
    assessment.level = "confirmed_threat"
    assessment.confirmed_by = principal.id
    assessment.last_assessed_at = utcnow()
    audit.record(db, principal.audit, "assessment.confirm", "analysis", "success", "assessment", assessment.id,
                 {"justification": justification}, commit=False)
    db.commit()
    return assessment

