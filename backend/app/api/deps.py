"""Request dependencies: authentication, permission and step-up checks."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.authz.policy import decide_case, has_permission
from app.core.context import ctx
from app.core.errors import ApiError, not_found
from app.core.ratelimit import limiter
from app.core.security import TokenError, decode_access_token, ensure_aware, utcnow
from app.db.session import get_db
from app.models import AuthSession, Case, Device, User
from app.services import audit
from app.services.audit import AuditContext


def client_ip(request: Request) -> str:
    hops = ctx().settings.trusted_proxy_count
    forwarded = request.headers.get("x-forwarded-for")
    if hops and forwarded:
        parts = [p.strip() for p in forwarded.split(",")]
        if len(parts) >= hops:
            return parts[-hops]
    return request.client.host if request.client else "unknown"


def anonymous_audit(request: Request) -> AuditContext:
    return AuditContext(ip_address=client_ip(request), request_id=getattr(request.state, "request_id", None))


@dataclass
class Principal:
    user: User
    session: AuthSession
    audit: AuditContext

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    def can(self, permission: str) -> bool:
        return has_permission(self.user, permission)

    @property
    def step_up_valid(self) -> bool:
        until = ensure_aware(self.session.step_up_until)
        return until is not None and until > utcnow()


def _unauthorized(code: str = "unauthenticated") -> ApiError:
    return ApiError(401, code)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise _unauthorized()
    try:
        claims = decode_access_token(ctx().settings, header[7:].strip())
    except TokenError:
        raise _unauthorized("invalid_token") from None
    session = db.get(AuthSession, claims.session_id)
    now = utcnow()
    if (
        session is None
        or session.user_id != claims.user_id
        or session.revoked_at is not None
        or ensure_aware(session.expires_at) <= now
        or not session.mfa_verified
    ):
        raise _unauthorized("session_invalid")
    if session.device_id is not None:
        device = db.get(Device, session.device_id)
        if device is None or device.status != "active":
            raise _unauthorized("device_revoked")
    user = db.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise _unauthorized("account_disabled")

    settings = ctx().settings
    if not limiter.allow(f"user:{user.id}", settings.rate_limit_default_per_minute):
        raise ApiError(429, "rate_limited")
    session.last_used_at = now
    db.commit()
    audit_ctx = AuditContext(
        actor_id=user.id,
        actor_label=user.professional_id,
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", None),
        session_id=str(session.id),
    )
    return Principal(user=user, session=session, audit=audit_ctx)


def require(permission: str):
    def checker(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> Principal:
        if not principal.can(permission):
            audit.record(db, principal.audit, "permission.denied", "access", "denied", details={"permission": permission})
            raise ApiError(403, "missing_permission", permission)
        return principal

    return checker


def require_step_up(principal: Principal, db: Session, action: str) -> None:
    if not principal.step_up_valid:
        audit.record(db, principal.audit, "step_up.required", "access", "denied", details={"action": action})
        raise ApiError(403, "step_up_required", "Re-authentication required for this operation")


def load_case(db: Session, principal: Principal, case_id: uuid.UUID, level: str) -> Case:
    """Fetch a case and enforce ABAC. Denials are audited and answered with 404."""
    case = db.get(Case, case_id)
    if case is None:
        raise not_found("case")
    decision = decide_case(db, principal.user, case, level)
    if not decision.allowed:
        audit.record(
            db, principal.audit, "case.access_denied", "access", "denied",
            target_type="case", target_id=case.id, details={"level": level, "reason": decision.reason},
        )
        if decision.reason == "case_read_only":
            raise ApiError(409, "case_read_only")
        raise not_found("case")
    return case
