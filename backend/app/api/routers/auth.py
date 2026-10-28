"""Authentication, profile, sessions, devices and notifications of the current user."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, anonymous_audit, get_principal
from app.connectors.oidc import OidcError, OidcVerifier
from app.core.context import ctx
from app.core.errors import ApiError, not_found
from app.core.ratelimit import limiter
from app.core.security import (
    ensure_aware,
    hash_password,
    password_policy_errors,
    utcnow,
)
from app.db.session import get_db
from app.models import AuthSession, Device, Notification, RecoveryRequest, User
from app.schemas import api as s
from app.services import audit
from app.services import auth as svc

router = APIRouter(tags=["auth"])


def _throttle(request: Request, key: str) -> None:
    settings = ctx().settings
    ip = anonymous_audit(request).ip_address
    if not limiter.allow(f"auth-ip:{ip}", settings.rate_limit_auth_per_minute) or not limiter.allow(
        f"auth-key:{key}", settings.rate_limit_auth_per_minute
    ):
        raise ApiError(429, "rate_limited")


def _device(info: s.DeviceIn) -> svc.DeviceInfo:
    return svc.DeviceInfo(info.install_id, info.platform, info.label, info.integrity)


@router.post("/auth/login", response_model=s.LoginStepOut)
def login(data: s.LoginIn, request: Request, db: Session = Depends(get_db)):
    _throttle(request, data.username)
    step = svc.start_password_login(db, data.username, data.password, _device(data.device), anonymous_audit(request))
    return s.LoginStepOut(mfa_token=step.mfa_token, enrollment_required=step.enrollment_required,
                          totp_provisioning_uri=step.totp_provisioning_uri)


@router.post("/auth/oidc", response_model=s.LoginStepOut | s.TokenOut)
def oidc_login(data: s.OidcLoginIn, request: Request, db: Session = Depends(get_db)):
    _throttle(request, "oidc")
    try:
        identity = OidcVerifier(ctx().settings).verify(data.id_token, data.nonce)
    except OidcError as exc:
        audit.record(db, anonymous_audit(request), "auth.oidc", "authentication", "failure", details={"reason": str(exc)})
        raise ApiError(401, "invalid_credentials") from None
    result = svc.start_oidc_login(db, identity, _device(data.device), anonymous_audit(request),
                                  request.headers.get("user-agent"))
    if isinstance(result, svc.LoginStep):
        return s.LoginStepOut(mfa_token=result.mfa_token, enrollment_required=result.enrollment_required,
                              totp_provisioning_uri=result.totp_provisioning_uri)
    return s.TokenOut(access_token=result.access_token, refresh_token=result.refresh_token,
                      expires_at=result.expires_at, session_id=result.session_id)


@router.post("/auth/mfa", response_model=s.TokenOut)
def mfa(data: s.MfaIn, request: Request, db: Session = Depends(get_db)):
    _throttle(request, data.mfa_token[:16])
    pair = svc.complete_mfa(db, data.mfa_token, data.code, anonymous_audit(request), request.headers.get("user-agent"))
    return s.TokenOut(access_token=pair.access_token, refresh_token=pair.refresh_token,
                      expires_at=pair.expires_at, session_id=pair.session_id)


@router.post("/auth/refresh", response_model=s.TokenOut)
def refresh(data: s.RefreshIn, request: Request, db: Session = Depends(get_db)):
    _throttle(request, data.refresh_token[:36])
    pair = svc.refresh(db, data.refresh_token, anonymous_audit(request))
    return s.TokenOut(access_token=pair.access_token, refresh_token=pair.refresh_token,
                      expires_at=pair.expires_at, session_id=pair.session_id)


@router.post("/auth/logout", status_code=204)
def logout(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    svc.revoke_session(db, principal.session, "logout", principal.audit)


@router.post("/auth/step-up", status_code=204)
def step_up(data: s.StepUpIn, request: Request, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    _throttle(request, f"stepup:{principal.id}")
    svc.step_up(db, principal.session, principal.user, data.password, data.code, principal.audit)


@router.post("/auth/recovery/complete", status_code=204)
def recovery_complete(data: s.RecoveryCompleteIn, request: Request, db: Session = Depends(get_db)):
    """Final step of the institutional recovery procedure (two-person approved code)."""
    _throttle(request, f"recovery:{data.username}")
    actx = anonymous_audit(request)
    user = db.scalar(select(User).where(User.username == data.username))
    req = None
    if user is not None:
        req = db.scalar(select(RecoveryRequest).where(RecoveryRequest.user_id == user.id,
                                                       RecoveryRequest.status == "approved"))
    valid = (
        req is not None and req.code_hash == ctx().cipher.keyed_hash(data.recovery_code)
        and ensure_aware(req.expires_at) > utcnow()
    )
    if not valid:
        audit.record(db, actx, "recovery.complete", "authentication", "failure")
        raise ApiError(401, "invalid_recovery")
    if password_policy_errors(data.new_password):
        raise ApiError(400, "weak_password", ",".join(password_policy_errors(data.new_password)))
    actx.actor_id, actx.actor_label = user.id, user.professional_id
    user.password_hash = hash_password(data.new_password)
    user.password_changed_at = utcnow()
    user.mfa_enrolled = False  # TOTP must be re-enrolled at next login
    user.totp_secret_enc = None
    user.totp_last_step = None
    user.failed_logins = 0
    user.locked_until = None
    req.status = "used"
    svc.revoke_all_user_sessions(db, user, "account_recovery", actx)
    audit.record(db, actx, "recovery.complete", "authentication", "success", "user", user.id)


# --- Current user -----------------------------------------------------------

me = APIRouter(prefix="/me", tags=["me"])


@me.get("", response_model=s.MeOut)
def get_me(principal: Principal = Depends(get_principal)):
    out = s.MeOut.model_validate(principal.user)
    out.permissions = sorted(principal.user.permission_codes)
    return out


@me.get("/sessions", response_model=list[s.SessionOut])
def my_sessions(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return db.scalars(select(AuthSession).where(AuthSession.user_id == principal.id)
                      .order_by(AuthSession.created_at.desc()).limit(50)).all()


@me.delete("/sessions/{session_id}", status_code=204)
def revoke_my_session(session_id: uuid.UUID, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    session = db.get(AuthSession, session_id)
    if session is None or session.user_id != principal.id:
        raise not_found("session")
    svc.revoke_session(db, session, "user_revoked", principal.audit)


@me.get("/devices", response_model=list[s.DeviceOut])
def my_devices(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return db.scalars(select(Device).where(Device.user_id == principal.id)).all()


@me.post("/devices/{device_id}/report-lost", response_model=s.DeviceOut)
def report_lost(device_id: uuid.UUID, data: s.DeviceRevokeIn, principal: Principal = Depends(get_principal),
                db: Session = Depends(get_db)):
    """A user may declare one of their own devices lost or stolen at any time."""
    device = db.get(Device, device_id)
    if device is None or device.user_id != principal.id:
        raise not_found("device")
    svc.revoke_device(db, device, data.status, data.reason, principal.audit, data.wipe)
    return device


@me.post("/devices/current/push-token", status_code=204)
def register_push(data: s.PushTokenIn, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    if principal.session.device_id is None:
        raise ApiError(400, "no_device")
    device = db.get(Device, principal.session.device_id)
    device.push_token_enc = ctx().cipher.encrypt_field(data.push_token)
    db.commit()


@me.get("/devices/current/status")
def current_device_status(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    device = db.get(Device, principal.session.device_id) if principal.session.device_id else None
    if device:
        device.last_seen_at = utcnow()
        db.commit()
    return {"status": device.status if device else "none", "wipe_requested": bool(device and device.wipe_requested)}


@me.get("/notifications", response_model=list[s.NotificationOut])
def notifications(unread_only: bool = False, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    stmt = select(Notification).where(Notification.user_id == principal.id)
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    return db.scalars(stmt.order_by(Notification.created_at.desc()).limit(100)).all()


@me.post("/notifications/{notification_id}/read", status_code=204)
def mark_read(notification_id: uuid.UUID, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    n = db.get(Notification, notification_id)
    if n is None or n.user_id != principal.id:
        raise not_found("notification")
    n.read_at = utcnow()
    db.commit()


@me.patch("/locale", status_code=204)
def set_locale(locale: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    if locale not in {"fr", "en"}:
        raise ApiError(400, "unsupported_locale")
    principal.user.preferred_locale = locale
    db.commit()
