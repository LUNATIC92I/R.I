"""Administration: users, roles, devices, sessions, recovery, referentials, integrations, audit."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_principal, require, require_step_up
from app.authz.policy import PERMISSIONS
from app.core.context import ctx
from app.core.errors import ApiError, bad_request, conflict, not_found
from app.core.security import (
    hash_password,
    password_policy_errors,
    random_token,
    utcnow,
)
from app.db.session import get_db
from app.models import (
    AuditLog,
    AuthSession,
    ClassificationLevel,
    Device,
    RecoveryRequest,
    ReferenceSite,
    RetentionRule,
    Role,
    Service,
    ServiceAccount,
    User,
)
from app.schemas import api as s
from app.services import audit
from app.services import auth as auth_svc

router = APIRouter(prefix="/admin", tags=["admin"])
audit_router = APIRouter(prefix="/audit", tags=["audit"])


def _roles(db: Session, codes: list[str]) -> list[Role]:
    roles = db.scalars(select(Role).where(Role.code.in_(codes))).all()
    if len(roles) != len(set(codes)):
        raise bad_request("unknown_role")
    return list(roles)


@router.get("/roles")
def list_roles(principal: Principal = Depends(require("user:manage")), db: Session = Depends(get_db)):
    return [{"code": r.code, "name_fr": r.name_fr, "name_en": r.name_en, "case_scope": r.case_scope,
             "permissions": sorted(p.code for p in r.permissions)} for r in db.scalars(select(Role))]


@router.get("/permissions")
def list_permissions(principal: Principal = Depends(require("user:manage"))):
    return [{"code": k, "description": v} for k, v in PERMISSIONS.items()]


@router.get("/services", response_model=list[s.ServiceOut])
def list_services(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return db.scalars(select(Service)).all()


@router.get("/users", response_model=list[s.UserOut])
def list_users(principal: Principal = Depends(require("user:manage")), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.username)).all()


@router.get("/directory")
def directory(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """Minimal colleague directory used to grant need-to-know (no clearance or role detail)."""
    if not (principal.can("case:manage_members") or principal.can("user:manage")):
        raise ApiError(403, "missing_permission")
    return [{"id": u.id, "display_name": u.display_name, "professional_id": u.professional_id}
            for u in db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.display_name))]


@router.post("/users", response_model=s.UserOut, status_code=201)
def create_user(data: s.UserCreateIn, principal: Principal = Depends(require("user:manage")), db: Session = Depends(get_db)):
    require_step_up(principal, db, "user.create")
    if not principal.can("role:manage"):
        raise ApiError(403, "missing_permission", "role:manage")
    if errors := password_policy_errors(data.initial_password):
        raise bad_request("weak_password", ",".join(errors))
    if db.get(Service, data.service_id) is None:
        raise bad_request("unknown_service")
    if db.scalar(select(User.id).where((User.username == data.username) | (User.professional_id == data.professional_id))):
        raise conflict("user_exists")
    user = User(username=data.username, display_name=data.display_name, professional_id=data.professional_id,
                service_id=data.service_id, clearance_rank=data.clearance_rank, external_subject=data.external_subject,
                password_hash=hash_password(data.initial_password), password_changed_at=utcnow(),
                roles=_roles(db, data.roles))
    db.add(user)
    db.flush()
    audit.record(db, principal.audit, "user.create", "administration", "success", "user", user.id,
                 {"roles": data.roles, "clearance_rank": data.clearance_rank}, commit=False)
    db.commit()
    return user


@router.patch("/users/{user_id}", response_model=s.UserOut)
def update_user(user_id: uuid.UUID, data: s.UserUpdateIn, principal: Principal = Depends(require("user:manage")),
                db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise not_found("user")
    if user.id == principal.id:
        raise ApiError(403, "self_modification_forbidden")
    changes = data.model_dump(exclude_unset=True)
    if {"roles", "clearance_rank", "service_id"} & changes.keys():
        if not principal.can("role:manage"):
            raise ApiError(403, "missing_permission", "role:manage")
        require_step_up(principal, db, "user.privileges")
    if "roles" in changes:
        user.roles = _roles(db, changes.pop("roles"))
    for key, value in changes.items():
        setattr(user, key, value)
    audit.record(db, principal.audit, "user.update", "permission", "success", "user", user.id,
                 {k: v for k, v in data.model_dump(exclude_unset=True).items()}, commit=False)
    db.commit()
    if data.is_active is False or "roles" in data.model_fields_set or "clearance_rank" in data.model_fields_set:
        # Privilege changes take effect immediately: existing sessions are closed.
        auth_svc.revoke_all_user_sessions(db, user, "privileges_changed", principal.audit)
    return user


@router.post("/users/{user_id}/unlock", status_code=204)
def unlock_user(user_id: uuid.UUID, principal: Principal = Depends(require("user:manage")), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise not_found("user")
    user.failed_logins = 0
    user.locked_until = None
    audit.record(db, principal.audit, "user.unlock", "administration", "success", "user", user.id)


@router.post("/users/{user_id}/revoke-sessions")
def revoke_user_sessions(user_id: uuid.UUID, principal: Principal = Depends(require("session:revoke_any")),
                         db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise not_found("user")
    return {"revoked": auth_svc.revoke_all_user_sessions(db, user, "admin_revoked", principal.audit)}


@router.get("/users/{user_id}/sessions", response_model=list[s.SessionOut])
def user_sessions(user_id: uuid.UUID, principal: Principal = Depends(require("session:revoke_any")),
                  db: Session = Depends(get_db)):
    return db.scalars(select(AuthSession).where(AuthSession.user_id == user_id)
                      .order_by(AuthSession.created_at.desc()).limit(100)).all()


@router.get("/devices", response_model=list[s.DeviceOut])
def list_devices(user_id: uuid.UUID | None = None, principal: Principal = Depends(require("device:revoke_any")),
                 db: Session = Depends(get_db)):
    stmt = select(Device)
    if user_id:
        stmt = stmt.where(Device.user_id == user_id)
    return db.scalars(stmt.order_by(Device.created_at.desc()).limit(500)).all()


@router.post("/devices/{device_id}/revoke", response_model=s.DeviceOut)
def revoke_device(device_id: uuid.UUID, data: s.DeviceRevokeIn, principal: Principal = Depends(require("device:revoke_any")),
                  db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if device is None:
        raise not_found("device")
    auth_svc.revoke_device(db, device, data.status, data.reason, principal.audit, data.wipe)
    return device


# --- Account recovery (two-person rule) -------------------------------------

@router.post("/recovery", status_code=201)
def request_recovery(data: s.RecoveryRequestIn, principal: Principal = Depends(require("recovery:request")),
                     db: Session = Depends(get_db)):
    user = db.get(User, data.user_id)
    if user is None:
        raise not_found("user")
    if user.id == principal.id:
        raise ApiError(403, "self_recovery_forbidden")
    req = RecoveryRequest(user_id=user.id, requested_by=principal.id, identity_check_reference=data.identity_check_reference)
    db.add(req)
    db.flush()
    audit.record(db, principal.audit, "recovery.request", "administration", "success", "user", user.id,
                 {"request_id": str(req.id)}, commit=False)
    db.commit()
    return {"id": req.id, "status": req.status}


@router.get("/recovery")
def list_recovery(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    if not (principal.can("recovery:approve") or principal.can("recovery:request")):
        raise ApiError(403, "missing_permission")
    return [{"id": r.id, "user_id": r.user_id, "requested_by": r.requested_by, "status": r.status,
             "identity_check_reference": r.identity_check_reference, "created_at": r.created_at}
            for r in db.scalars(select(RecoveryRequest).order_by(RecoveryRequest.created_at.desc()).limit(100))]


@router.post("/recovery/{request_id}/approve")
def approve_recovery(request_id: uuid.UUID, principal: Principal = Depends(require("recovery:approve")),
                     db: Session = Depends(get_db)):
    req = db.get(RecoveryRequest, request_id)
    if req is None or req.status != "pending":
        raise not_found("recovery request")
    if principal.id in {req.requested_by, req.user_id}:
        raise ApiError(403, "four_eyes_required")
    require_step_up(principal, db, "recovery.approve")
    code = random_token(24)
    req.code_hash = ctx().cipher.keyed_hash(code)
    req.status = "approved"
    req.approved_by = principal.id
    req.expires_at = utcnow() + timedelta(hours=24)
    user = db.get(User, req.user_id)
    auth_svc.revoke_all_user_sessions(db, user, "account_recovery_started", principal.audit)
    audit.record(db, principal.audit, "recovery.approve", "administration", "success", "user", req.user_id,
                 {"request_id": str(req.id)}, commit=False)
    db.commit()
    return {"recovery_code": code, "expires_at": req.expires_at,
            "instruction": "Remettre ce code en main propre selon la procédure institutionnelle. Il ne sera plus affiché."}


# --- Referentials -----------------------------------------------------------

@router.get("/classifications", response_model=list[s.ClassificationOut])
def list_classifications(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return db.scalars(select(ClassificationLevel).order_by(ClassificationLevel.rank)).all()


@router.post("/classifications", response_model=s.ClassificationOut, status_code=201)
def create_classification(data: s.ClassificationIn, principal: Principal = Depends(require("classification:manage")),
                          db: Session = Depends(get_db)):
    require_step_up(principal, db, "classification.create")
    if db.scalar(select(ClassificationLevel.id).where((ClassificationLevel.rank == data.rank)
                                                      | (ClassificationLevel.code == data.code))):
        raise conflict("classification_exists")
    level = ClassificationLevel(**data.model_dump())
    db.add(level)
    audit.record(db, principal.audit, "classification.create", "administration", "success", details=data.model_dump(),
                 commit=False)
    db.commit()
    return level


@router.get("/retention-rules", response_model=list[s.RetentionOut])
def list_retention(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return db.scalars(select(RetentionRule)).all()


@router.post("/retention-rules", response_model=s.RetentionOut, status_code=201)
def create_retention(data: s.RetentionIn, principal: Principal = Depends(require("retention:manage")),
                     db: Session = Depends(get_db)):
    require_step_up(principal, db, "retention.create")
    rule = RetentionRule(**data.model_dump())
    db.add(rule)
    audit.record(db, principal.audit, "retention.create", "administration", "success", details={"code": data.code},
                 commit=False)
    db.commit()
    return rule


@router.post("/reference-sites", status_code=201)
def add_site(data: s.SiteIn, principal: Principal = Depends(require("reference:manage")), db: Session = Depends(get_db)):
    if db.scalar(select(ClassificationLevel.id).where(ClassificationLevel.rank == data.classification_rank)) is None:
        raise bad_request("unknown_classification")
    site = ReferenceSite(**data.model_dump())
    db.add(site)
    db.flush()
    audit.record(db, principal.audit, "reference_site.create", "administration", "success", "site", site.id, commit=False)
    db.commit()
    return {"id": site.id}


@router.post("/service-accounts", status_code=201)
def create_service_account(data: s.ServiceAccountIn, principal: Principal = Depends(require("cyber:integrations_manage")),
                           db: Session = Depends(get_db)):
    require_step_up(principal, db, "service_account.create")
    prefix = random_token(6)[:8].replace("-", "x").replace("_", "y")
    key = f"{prefix}.{random_token(32)}"
    account = ServiceAccount(name=data.name, key_prefix=prefix, key_hash=ctx().cipher.keyed_hash(key),
                             scopes=list(data.scopes), service_id=data.service_id, created_by=principal.id)
    db.add(account)
    db.flush()
    audit.record(db, principal.audit, "service_account.create", "integration", "success", "service_account", account.id,
                 {"scopes": list(data.scopes)}, commit=False)
    db.commit()
    return {"id": account.id, "api_key": key, "notice": "Clé affichée une seule fois. À stocker dans le coffre du SIEM."}


@router.post("/service-accounts/{account_id}/disable", status_code=204)
def disable_service_account(account_id: uuid.UUID, principal: Principal = Depends(require("cyber:integrations_manage")),
                            db: Session = Depends(get_db)):
    account = db.get(ServiceAccount, account_id)
    if account is None:
        raise not_found("service account")
    account.is_active = False
    audit.record(db, principal.audit, "service_account.disable", "integration", "success", "service_account", account.id)


# --- Audit trail ------------------------------------------------------------

@audit_router.get("")
def read_audit(category: str | None = None, action: str | None = None, actor_id: uuid.UUID | None = None,
               since: datetime | None = None, until: datetime | None = None, before_seq: int | None = None,
               limit: int = Query(100, ge=1, le=500), principal: Principal = Depends(require("audit:read")),
               db: Session = Depends(get_db)):
    stmt = select(AuditLog)
    if category:
        stmt = stmt.where(AuditLog.category == category)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if since:
        stmt = stmt.where(AuditLog.occurred_at >= since)
    if until:
        stmt = stmt.where(AuditLog.occurred_at <= until)
    if before_seq:
        stmt = stmt.where(AuditLog.seq < before_seq)
    rows = db.scalars(stmt.order_by(AuditLog.seq.desc()).limit(limit)).all()
    # Reading the audit trail is itself audited.
    audit.record(db, principal.audit, "audit.read", "audit", "success",
                 details={"category": category, "action": action, "count": len(rows)})
    return [{"seq": r.seq, "occurred_at": r.occurred_at, "actor_id": r.actor_id, "actor": r.actor_label,
             "action": r.action, "category": r.category, "outcome": r.outcome, "target_type": r.target_type,
             "target_id": r.target_id, "ip_address": r.ip_address, "request_id": r.request_id,
             "details": r.details, "entry_hash": r.entry_hash} for r in rows]


@audit_router.get("/verify")
def verify_audit(principal: Principal = Depends(require("audit:read")), db: Session = Depends(get_db)):
    report = audit.verify_chain(db)
    audit.record(db, principal.audit, "audit.verify", "audit", "success" if report.valid else "failure",
                 details={"checked": report.checked, "valid": report.valid})
    return report.__dict__
