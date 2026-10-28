"""Alerts, dashboard, authorised search, offline synchronisation, SIEM ingestion, health."""

from __future__ import annotations

import hmac
import uuid
from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.api.deps import Principal, anonymous_audit, get_principal, load_case, require
from app.authz.policy import READ, WRITE, accessible_case_filter, decide_case
from app.core.context import ctx
from app.core.errors import ApiError, not_found
from app.core.ratelimit import limiter
from app.core.security import ensure_aware, utcnow
from app.db.session import get_db
from app.models import (
    Alert,
    Case,
    Document,
    Event,
    Indicator,
    OfflineGrant,
    OsintItem,
    Report,
    ServiceAccount,
    Source,
    Statement,
    SyncOperation,
    ThreatAssessment,
)
from app.schemas import api as s
from app.services import audit, cyber
from app.services import cases as case_svc
from app.services.audit import AuditContext

router = APIRouter(tags=["operations"])


def _case_ids(db: Session, principal: Principal) -> set[uuid.UUID]:
    return set(db.scalars(select(Case.id).where(accessible_case_filter(db, principal.user))).all())


# --- Alerts -----------------------------------------------------------------

def _alert_filter(db: Session, principal: Principal):
    ids = _case_ids(db, principal)
    clauses = [Alert.case_id.in_(ids)] if ids else []
    if principal.can("user:manage") or principal.can("audit:read"):
        clauses.append((Alert.origin == "security") & Alert.case_id.is_(None))
    return or_(*clauses) if clauses else Alert.id.is_(None)


@router.get("/alerts", response_model=list[s.AlertOut])
def list_alerts(status: str | None = None, limit: int = Query(100, le=500), principal: Principal = Depends(get_principal),
                db: Session = Depends(get_db)):
    stmt = select(Alert).where(_alert_filter(db, principal), Alert.classification_rank <= principal.user.clearance_rank)
    if status:
        stmt = stmt.where(Alert.status == status)
    return db.scalars(stmt.order_by(Alert.created_at.desc()).limit(limit)).all()


@router.post("/alerts/{alert_id}/review", response_model=s.AlertOut)
def review_alert(alert_id: uuid.UUID, data: s.AlertReviewIn, principal: Principal = Depends(get_principal),
                 db: Session = Depends(get_db)):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, _alert_filter(db, principal)))
    if alert is None:
        raise not_found("alert")
    allowed = principal.can("alert:review") if alert.case_id else principal.can("user:manage")
    if not allowed:
        raise ApiError(403, "missing_permission", "alert:review")
    alert.status = data.status
    alert.review_note = data.note
    alert.reviewed_by = principal.id
    audit.record(db, principal.audit, "alert.review", "analysis", "success", "alert", alert.id, {"status": data.status})
    return alert


# --- Dashboard --------------------------------------------------------------

@router.get("/dashboard")
def dashboard(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    ids = _case_ids(db, principal)
    now = utcnow()
    out: dict = {
        "scope_notice": "Indicateurs limités aux données auxquelles vous avez accès. Ils ne constituent pas une "
                        "mesure exhaustive de la situation sécuritaire. / Limited to data you can access; not exhaustive.",
        "generated_at": now,
    }
    if ids:
        cases = db.scalars(select(Case).where(Case.id.in_(ids))).all()
        out["active_cases"] = sum(1 for c in cases if c.status in {"open", "under_review"})
        out["review_due_soon"] = [
            {"id": c.id, "reference": c.reference, "title": c.title, "review_date": c.review_date}
            for c in cases if c.status in {"open", "under_review"} and c.review_date <= (now + timedelta(days=14)).date()
        ]
        out["by_priority"] = Counter(c.priority for c in cases if c.status in {"open", "under_review"})
        out["recent_activity"] = sum(1 for c in cases if ensure_aware(c.updated_at) >= now - timedelta(days=7))
        recent = db.scalars(select(Event).where(Event.case_id.in_(ids), Event.occurred_at.is_not(None))
                            .order_by(Event.occurred_at.desc()).limit(10)).all()
        out["recent_events"] = [{"id": e.id, "case_id": e.case_id, "title": e.title, "occurred_at": e.occurred_at}
                                for e in recent]
        trend: dict[str, Counter] = defaultdict(Counter)
        for a in db.scalars(select(ThreatAssessment).where(ThreatAssessment.case_id.in_(ids),
                                                           ThreatAssessment.last_assessed_at >= now - timedelta(days=180))):
            trend[ensure_aware(a.last_assessed_at).strftime("%Y-%m")][a.category] += 1
        out["threat_category_trend"] = {k: dict(v) for k, v in sorted(trend.items())}
        reliabilities = Counter(db.scalars(select(Source.reliability).where(Source.case_id.in_(ids))).all())
        indicators = db.scalars(select(Indicator).where(Indicator.case_id.in_(ids))).all()
        out["source_quality"] = {
            "reliability_distribution": dict(reliabilities),
            "indicator_freshness": dict(Counter(cyber.freshness(i, now) for i in indicators)),
            "osint_items_last_30_days": db.scalar(select(func.count(OsintItem.id)).where(
                OsintItem.case_id.in_(ids), OsintItem.collected_at >= now - timedelta(days=30))),
        }
        out["alerts_to_verify"] = db.scalar(select(func.count(Alert.id)).where(
            Alert.case_id.in_(ids), Alert.status.in_(["new", "under_review"]),
            Alert.classification_rank <= principal.user.clearance_rank))
        if principal.can("report:validate"):
            out["reports_pending_validation"] = db.scalar(select(func.count(Report.id)).where(
                Report.case_id.in_(ids), Report.status == "submitted", Report.author_id != principal.id))
    else:
        out.update(active_cases=0, review_due_soon=[], recent_events=[], alerts_to_verify=0)
    if principal.can("system:health"):
        out["services"] = service_status(db)
    return out


def service_status(db: Session) -> dict:
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception:  # pragma: no cover - surfaced as status only
        database = "unavailable"
    settings = ctx().settings
    return {
        "database": database,
        "oidc": "configured" if settings.oidc_issuer else "not_configured",
        "threat_intel": "configured" if settings.misp_url else "not_configured",
        "llm": "configured" if settings.llm_endpoint else "not_configured",
        "push": "not_configured",
        "environment": settings.environment,
    }


# --- Search -----------------------------------------------------------------

def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/search")
def search(q: str = Query(..., min_length=2, max_length=200), principal: Principal = Depends(require("search:use")),
           db: Session = Depends(get_db)):
    """Search restricted, in SQL, to the cases and classification levels the user may read."""
    ids = _case_ids(db, principal)
    results: list[dict] = []
    if ids:
        pattern = _like(q)
        rank = principal.user.clearance_rank
        for c in db.scalars(select(Case).where(Case.id.in_(ids), or_(
                Case.title.ilike(pattern, escape="\\"), Case.reference.ilike(pattern, escape="\\"),
                Case.executive_summary.ilike(pattern, escape="\\"))).limit(25)):
            results.append({"type": "case", "id": c.id, "case_id": c.id, "title": c.title, "reference": c.reference})
        for st in db.scalars(select(Statement).where(Statement.case_id.in_(ids),
                                                     Statement.text.ilike(pattern, escape="\\")).limit(25)):
            results.append({"type": "statement", "id": st.id, "case_id": st.case_id, "title": st.text[:160], "kind": st.kind})
        for e in db.scalars(select(Event).where(Event.case_id.in_(ids), or_(
                Event.title.ilike(pattern, escape="\\"), Event.description.ilike(pattern, escape="\\"))).limit(25)):
            results.append({"type": "event", "id": e.id, "case_id": e.case_id, "title": e.title})
        for d in db.scalars(select(Document).where(Document.case_id.in_(ids), Document.classification_rank <= rank,
                                                   Document.title.ilike(pattern, escape="\\")).limit(25)):
            results.append({"type": "document", "id": d.id, "case_id": d.case_id, "title": d.title})
        for r in db.scalars(select(Report).where(Report.case_id.in_(ids), Report.classification_rank <= rank, or_(
                Report.title.ilike(pattern, escape="\\"), Report.summary.ilike(pattern, escape="\\"))).limit(25)):
            results.append({"type": "report", "id": r.id, "case_id": r.case_id, "title": r.title})
        for o in db.scalars(select(OsintItem).where(OsintItem.case_id.in_(ids), or_(
                OsintItem.title.ilike(pattern, escape="\\"), OsintItem.source_name.ilike(pattern, escape="\\"))).limit(25)):
            results.append({"type": "osint", "id": o.id, "case_id": o.case_id, "title": o.title})
        for i in db.scalars(select(Indicator).where(Indicator.case_id.in_(ids), Indicator.value.ilike(pattern, escape="\\"))
                            .limit(25)):
            results.append({"type": "indicator", "id": i.id, "case_id": i.case_id, "title": f"{i.type}: {i.value}"})
    # The query text itself may be sensitive: only its length is audited.
    audit.record(db, principal.audit, "search.run", "consultation", "success",
                 details={"query_length": len(q), "results": len(results)})
    return {"results": results, "count": len(results)}


# --- Offline synchronisation ------------------------------------------------

@router.post("/sync/offline-package/{case_id}")
def offline_package(case_id: uuid.UUID, principal: Principal = Depends(require("case:read")), db: Session = Depends(get_db)):
    """Time-limited package for offline consultation, under an explicit per-case policy."""
    case = load_case(db, principal, case_id, READ)
    settings = ctx().settings
    if principal.session.device_id is None:
        raise ApiError(400, "device_required")
    if not case.offline_allowed:
        raise ApiError(403, "offline_not_authorised")
    if case.classification_rank > settings.offline_max_classification_rank:
        raise ApiError(403, "classification_not_allowed_offline")
    now = utcnow()
    grant = OfflineGrant(user_id=principal.id, device_id=principal.session.device_id, case_id=case.id,
                         issued_at=now, expires_at=now + timedelta(hours=settings.offline_package_ttl_hours))
    db.add(grant)
    db.flush()
    audit.record(db, principal.audit, "sync.offline_package", "sync", "success", "case", case.id,
                 {"grant_id": str(grant.id), "expires_at": grant.expires_at.isoformat()}, commit=False)
    db.commit()
    return {
        "grant_id": grant.id,
        "expires_at": grant.expires_at,
        "case": s.CaseOut.model_validate(case),
        "statements": [s.StatementOut.model_validate(x) for x in db.scalars(select(Statement).where(Statement.case_id == case.id))],
        "events": [s.EventOut.model_validate(x) for x in db.scalars(select(Event).where(Event.case_id == case.id))],
        "sources": [s.SourceOut.model_validate(x) for x in db.scalars(select(Source).where(Source.case_id == case.id))],
        "documents_included": False,
    }


@router.get("/sync/grants")
def active_grants(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """The client must purge any cached package whose grant is not listed here."""
    now = utcnow()
    grants = db.scalars(select(OfflineGrant).where(OfflineGrant.user_id == principal.id,
                                                   OfflineGrant.device_id == principal.session.device_id,
                                                   OfflineGrant.revoked_at.is_(None))).all()
    return [{"grant_id": g.id, "case_id": g.case_id, "expires_at": g.expires_at}
            for g in grants if ensure_aware(g.expires_at) > now]


@router.post("/sync/push")
def sync_push(data: s.SyncPushIn, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """Apply queued offline operations after re-checking authorisation and versions."""
    if principal.session.device_id is None:
        raise ApiError(400, "device_required")
    results = []
    for op in data.operations:
        results.append(_apply_op(db, principal, op))
    return {"results": results}


def _apply_op(db: Session, principal: Principal, op: s.SyncOpIn) -> dict:
    device_id = principal.session.device_id
    done = db.scalar(select(SyncOperation).where(SyncOperation.device_id == device_id,
                                                 SyncOperation.client_op_id == op.client_op_id))
    if done:
        return {"client_op_id": op.client_op_id, "result": done.result, "detail": done.detail, "replayed": True}
    result, detail = "applied", ""
    case = db.get(Case, op.case_id)
    grant = db.scalar(select(OfflineGrant).where(OfflineGrant.device_id == device_id, OfflineGrant.case_id == op.case_id,
                                                 OfflineGrant.user_id == principal.id)
                      .order_by(OfflineGrant.issued_at.desc()))
    queued_at = ensure_aware(op.queued_at)
    if case is None or not decide_case(db, principal.user, case, WRITE).allowed:
        result, detail = "rejected", "not_authorised"
    elif grant is None or grant.revoked_at is not None or queued_at > ensure_aware(grant.expires_at) \
            or queued_at < ensure_aware(grant.issued_at):
        result, detail = "rejected", "no_valid_offline_grant"
    elif op.op_type in {"add_statement", "add_event"} and not principal.can("statement:write"):
        result, detail = "rejected", "missing_permission"
    else:
        try:
            if op.op_type == "add_statement":
                case_svc.add_statement(db, principal, case, s.StatementIn.model_validate(op.payload))
            elif op.op_type == "add_event":
                case_svc.add_event(db, principal, case, s.EventIn.model_validate(op.payload))
            elif op.op_type == "update_case_summary":
                if not principal.can("case:update"):
                    raise ApiError(403, "missing_permission")
                if op.base_version != case.version:
                    result, detail = "conflict", f"server_version={case.version}"
                else:
                    case_svc.update_case(db, principal, case, s.CaseUpdateIn(
                        version=case.version, executive_summary=str(op.payload.get("executive_summary", ""))[:20000]))
        except ApiError as exc:
            db.rollback()
            result, detail = "rejected", str(exc.detail.get("code") if isinstance(exc.detail, dict) else exc.detail)
        except ValueError as exc:
            db.rollback()
            result, detail = "rejected", f"invalid_payload: {str(exc)[:200]}"
    db.add(SyncOperation(client_op_id=op.client_op_id, device_id=device_id, user_id=principal.id, op_type=op.op_type,
                         result=result, detail=detail, processed_at=utcnow()))
    audit.record(db, principal.audit, "sync.operation", "sync", "success" if result == "applied" else "failure",
                 "case", op.case_id, {"op_type": op.op_type, "result": result}, commit=False)
    db.commit()
    return {"client_op_id": op.client_op_id, "result": result, "detail": detail}


# --- SIEM ingestion (machine-to-machine) ------------------------------------

def _service_account(request: Request, db: Session, api_key: str | None) -> tuple[ServiceAccount, AuditContext]:
    actx = anonymous_audit(request)
    if not limiter.allow(f"siem-ip:{actx.ip_address}", 120):
        raise ApiError(429, "rate_limited")
    prefix, _, _ = (api_key or "").partition(".")
    account = db.scalar(select(ServiceAccount).where(ServiceAccount.key_prefix == prefix)) if prefix else None
    if account is None or not account.is_active or not hmac.compare_digest(
            account.key_hash, ctx().cipher.keyed_hash(api_key or "")):
        audit.record(db, actx, "siem.auth", "integration", "denied")
        raise ApiError(401, "invalid_api_key")
    if "siem:ingest" not in account.scopes:
        raise ApiError(403, "missing_scope")
    actx.actor_label = f"svc:{account.name}"
    return account, actx


@router.post("/integrations/siem/events")
def siem_events(data: s.SiemBatchIn, request: Request, x_api_key: str | None = Header(default=None),
                db: Session = Depends(get_db)):
    account, actx = _service_account(request, db, x_api_key)
    return cyber.ingest_siem(db, account, data.events, actx)


# --- Health -----------------------------------------------------------------

@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/health/details")
def health_details(principal: Principal = Depends(require("system:health")), db: Session = Depends(get_db)):
    return service_status(db)
