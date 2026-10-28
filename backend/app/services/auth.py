"""Authentication flows: password + TOTP, OIDC, refresh rotation, step-up, lockout."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.context import ctx
from app.core.errors import ApiError
from app.core.security import (
    ensure_aware,
    issue_access_token,
    new_totp_secret,
    random_token,
    totp_uri,
    utcnow,
    verify_password,
    verify_totp,
)
from app.models import Alert, AuthSession, Device, MfaChallenge, User
from app.services import audit
from app.services.audit import AuditContext

MFA_CHALLENGE_TTL = timedelta(minutes=5)
MFA_MAX_ATTEMPTS = 5


def invalid_credentials() -> ApiError:
    # One generic answer for unknown user, wrong password, locked or disabled account.
    return ApiError(401, "invalid_credentials")


@dataclass
class DeviceInfo:
    install_id: str
    platform: str
    label: str
    integrity: dict | None = None


@dataclass
class LoginStep:
    mfa_token: str
    enrollment_required: bool
    totp_provisioning_uri: str | None


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    expires_at: int
    session_id: uuid.UUID


def _is_locked(user: User) -> bool:
    locked = ensure_aware(user.locked_until)
    return locked is not None and locked > utcnow()


def _register_failure(db: Session, user: User, actx: AuditContext, stage: str) -> None:
    settings = ctx().settings
    user.failed_logins += 1
    details = {"stage": stage, "failed_logins": user.failed_logins}
    if user.failed_logins >= settings.max_failed_logins:
        user.locked_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
        details["locked"] = True
        db.add(Alert(
            service_id=user.service_id, kind="account_locked", origin="security", severity="medium",
            title="Verrouillage de compte après échecs répétés",
            detail="Plusieurs échecs d'authentification consécutifs ont été détectés.",
            evidence={"user_id": str(user.id)},
        ))
    audit.record(db, actx, "auth.login", "authentication", "failure", "user", user.id, details, commit=False)
    db.commit()


def _upsert_device(db: Session, user: User, info: DeviceInfo, actx: AuditContext) -> tuple[Device, bool]:
    device = db.scalar(select(Device).where(Device.user_id == user.id, Device.install_id == info.install_id))
    created = False
    if device is None:
        device = Device(
            user_id=user.id, install_id=info.install_id, platform=info.platform,
            label=info.label[:120], integrity_report=info.integrity,
        )
        db.add(device)
        db.flush()
        created = True
    elif device.status != "active":
        audit.record(db, actx, "auth.login", "authentication", "denied", "device", device.id, {"reason": "device_revoked"})
        raise invalid_credentials()
    device.integrity_report = info.integrity
    return device, created


def start_password_login(db: Session, username: str, password: str, info: DeviceInfo, actx: AuditContext) -> LoginStep:
    user = db.scalar(select(User).where(User.username == username))
    password_ok = verify_password(password, user.password_hash if user else None)
    if user is None:
        audit.record(db, actx, "auth.login", "authentication", "failure", details={"stage": "password", "reason": "unknown_user"})
        raise invalid_credentials()
    actx.actor_id, actx.actor_label = user.id, user.professional_id
    if not user.is_active or _is_locked(user):
        audit.record(db, actx, "auth.login", "authentication", "denied", "user", user.id,
                     {"reason": "locked" if user.is_active else "disabled"})
        raise invalid_credentials()
    if not password_ok:
        _register_failure(db, user, actx, "password")
        raise invalid_credentials()
    device, _ = _upsert_device(db, user, info, actx)
    return _issue_challenge(db, user, device, actx, "login")


def _issue_challenge(db: Session, user: User, device: Device | None, actx: AuditContext, purpose: str) -> LoginStep:
    cipher = ctx().cipher
    token = random_token()
    uri = None
    if not user.mfa_enrolled:
        secret = new_totp_secret()
        user.totp_secret_enc = cipher.encrypt_field(secret)
        uri = totp_uri(secret, user.username, ctx().settings.institution_name)
    db.add(MfaChallenge(
        user_id=user.id, token_hash=cipher.keyed_hash(token), device_id=device.id if device else None,
        expires_at=utcnow() + MFA_CHALLENGE_TTL, purpose=purpose,
    ))
    audit.record(db, actx, "auth.first_factor", "authentication", "success", "user", user.id,
                 {"purpose": purpose, "enrollment": not user.mfa_enrolled}, commit=False)
    db.commit()
    return LoginStep(mfa_token=token, enrollment_required=not user.mfa_enrolled, totp_provisioning_uri=uri)


def complete_mfa(db: Session, mfa_token: str, code: str, actx: AuditContext, user_agent: str | None) -> TokenPair:
    cipher = ctx().cipher
    challenge = db.scalar(
        select(MfaChallenge).where(MfaChallenge.token_hash == cipher.keyed_hash(mfa_token)).with_for_update()
    )
    if (
        challenge is None
        or challenge.consumed_at is not None
        or ensure_aware(challenge.expires_at) <= utcnow()
        or challenge.attempts >= MFA_MAX_ATTEMPTS
    ):
        audit.record(db, actx, "auth.mfa", "authentication", "failure", details={"reason": "invalid_challenge"})
        raise ApiError(401, "invalid_mfa_challenge")
    user = db.get(User, challenge.user_id)
    assert user is not None
    actx.actor_id, actx.actor_label = user.id, user.professional_id
    if not user.is_active or _is_locked(user) or not user.totp_secret_enc:
        raise invalid_credentials()
    step = verify_totp(cipher.decrypt_field(user.totp_secret_enc), code, user.totp_last_step)
    if step is None:
        challenge.attempts += 1
        _register_failure(db, user, actx, "mfa")
        raise ApiError(401, "invalid_mfa_code")

    challenge.consumed_at = utcnow()
    user.totp_last_step = step
    user.failed_logins = 0
    user.locked_until = None
    enrolled_now = not user.mfa_enrolled
    user.mfa_enrolled = True
    pair = _open_session(db, user, challenge.device_id, actx, user_agent)
    _detect_anomalies(db, user, challenge.device_id, actx)
    audit.record(db, actx, "auth.login", "authentication", "success", "session", pair.session_id,
                 {"mfa_enrolled_now": enrolled_now, "device_id": str(challenge.device_id)}, commit=False)
    db.commit()
    return pair


def _open_session(db: Session, user: User, device_id: uuid.UUID | None, actx: AuditContext, user_agent: str | None) -> TokenPair:
    settings = ctx().settings
    session = AuthSession(
        id=uuid.uuid4(), user_id=user.id, device_id=device_id, refresh_token_hash="pending",  # noqa: S106 - replaced below
        mfa_verified=True, expires_at=utcnow() + timedelta(seconds=settings.refresh_token_ttl_seconds),
        ip_address=actx.ip_address, user_agent=(user_agent or "")[:300],
    )
    refresh = _new_refresh(session)
    db.add(session)
    access, exp = issue_access_token(settings, user.id, session.id)
    actx.session_id = str(session.id)
    return TokenPair(access, refresh, exp, session.id)


def _new_refresh(session: AuthSession) -> str:
    """Refresh token = ``<session id>.<random>``; only its keyed hash is stored."""
    token = f"{session.id}.{random_token()}"
    session.refresh_token_hash = ctx().cipher.keyed_hash(token)
    return token


def refresh(db: Session, refresh_token: str, actx: AuditContext) -> TokenPair:
    settings = ctx().settings
    sid_text, _, _ = refresh_token.partition(".")
    try:
        sid = uuid.UUID(sid_text)
    except ValueError:
        raise ApiError(401, "invalid_refresh_token") from None
    session = db.execute(select(AuthSession).where(AuthSession.id == sid).with_for_update()).scalar_one_or_none()
    if session is None or session.revoked_at is not None or ensure_aware(session.expires_at) <= utcnow():
        raise ApiError(401, "invalid_refresh_token")
    actx.session_id = str(session.id)
    if ctx().cipher.keyed_hash(refresh_token) != session.refresh_token_hash:
        # A previously rotated token was presented: assume theft, kill the session.
        revoke_session(db, session, "refresh_token_reuse", actx)
        db.add(Alert(
            service_id=db.get(User, session.user_id).service_id, kind="token_reuse", origin="security",
            severity="high", title="Réutilisation d'un jeton de session détectée",
            detail="La session a été révoquée automatiquement.", evidence={"session_id": str(session.id)},
        ))
        db.commit()
        raise ApiError(401, "invalid_refresh_token")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise ApiError(401, "account_disabled")
    if session.device_id:
        device = db.get(Device, session.device_id)
        if device is None or device.status != "active":
            raise ApiError(401, "device_revoked")
    session.refresh_generation += 1
    session.last_used_at = utcnow()
    new_refresh = _new_refresh(session)
    access, exp = issue_access_token(settings, user.id, session.id)
    actx.actor_id, actx.actor_label = user.id, user.professional_id
    audit.record(db, actx, "auth.refresh", "authentication", "success", "session", session.id, commit=False)
    db.commit()
    return TokenPair(access, new_refresh, exp, session.id)


def revoke_session(db: Session, session: AuthSession, reason: str, actx: AuditContext) -> None:
    if session.revoked_at is None:
        session.revoked_at = utcnow()
        session.revoked_reason = reason
    audit.record(db, actx, "session.revoke", "session", "success", "session", session.id, {"reason": reason}, commit=False)
    db.commit()


def revoke_device(db: Session, device: Device, status: str, reason: str, actx: AuditContext, wipe: bool) -> int:
    """Mark a device lost/stolen/revoked and revoke every session bound to it."""
    now = utcnow()
    device.status = status
    device.revoked_at = now
    device.revoked_reason = reason[:300]
    device.wipe_requested = wipe
    result = db.execute(
        update(AuthSession)
        .where(AuthSession.device_id == device.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=f"device_{status}")
    )
    from app.models import OfflineGrant

    db.execute(update(OfflineGrant).where(OfflineGrant.device_id == device.id, OfflineGrant.revoked_at.is_(None))
               .values(revoked_at=now))
    audit.record(db, actx, "device.revoke", "device", "success", "device", device.id,
                 {"status": status, "sessions_revoked": result.rowcount, "wipe_requested": wipe}, commit=False)
    db.commit()
    return result.rowcount


def revoke_all_user_sessions(db: Session, user: User, reason: str, actx: AuditContext) -> int:
    result = db.execute(
        update(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoked_reason=reason)
    )
    audit.record(db, actx, "session.revoke_all", "session", "success", "user", user.id,
                 {"reason": reason, "count": result.rowcount}, commit=False)
    db.commit()
    return result.rowcount


def step_up(db: Session, session: AuthSession, user: User, password: str, code: str, actx: AuditContext) -> None:
    cipher = ctx().cipher
    ok_password = verify_password(password, user.password_hash) if user.password_hash else True
    step = verify_totp(cipher.decrypt_field(user.totp_secret_enc), code, user.totp_last_step) if user.totp_secret_enc else None
    if not ok_password or step is None:
        _register_failure(db, user, actx, "step_up")
        raise ApiError(401, "step_up_failed")
    user.totp_last_step = step
    session.step_up_until = utcnow() + timedelta(seconds=ctx().settings.step_up_ttl_seconds)
    audit.record(db, actx, "auth.step_up", "authentication", "success", "session", session.id, commit=False)
    db.commit()


def _detect_anomalies(db: Session, user: User, device_id: uuid.UUID | None, actx: AuditContext) -> None:
    """Heuristics only: they raise alerts for human review, never block on their own."""
    previous = db.scalars(
        select(AuthSession).where(AuthSession.user_id == user.id).order_by(AuthSession.created_at.desc()).limit(20)
    ).all()
    known_ips = {s.ip_address for s in previous if s.ip_address}
    known_devices = {s.device_id for s in previous if s.device_id}
    reasons = []
    if previous and device_id and device_id not in known_devices:
        reasons.append("new_device")
    if previous and actx.ip_address and actx.ip_address not in known_ips:
        reasons.append("new_network_address")
    if reasons:
        db.add(Alert(
            service_id=user.service_id, kind="unusual_login", origin="security", severity="low",
            title="Connexion inhabituelle à vérifier",
            detail="Connexion depuis un appareil ou une adresse réseau non encore observés pour ce compte. "
                   "Signal technique à vérifier : ce n'est pas une preuve de compromission.",
            evidence={"user_id": str(user.id), "reasons": reasons},
        ))
        audit.record(db, actx, "auth.anomaly", "security", "success", "user", user.id, {"reasons": reasons}, commit=False)


def start_oidc_login(db: Session, identity, info: DeviceInfo, actx: AuditContext, user_agent: str | None):
    """Map a verified IdP identity to a local account.

    If the IdP asserted multi-factor authentication the session opens directly,
    otherwise the local TOTP factor is still required.
    """
    user = db.scalar(select(User).where(User.external_subject == identity.subject))
    if user is None or not user.is_active or _is_locked(user):
        audit.record(db, actx, "auth.oidc", "authentication", "denied", details={"reason": "no_active_account"})
        raise invalid_credentials()
    actx.actor_id, actx.actor_label = user.id, user.professional_id
    device, _ = _upsert_device(db, user, info, actx)
    if not identity.multi_factor:
        return _issue_challenge(db, user, device, actx, "login")
    pair = _open_session(db, user, device.id, actx, user_agent)
    _detect_anomalies(db, user, device.id, actx)
    audit.record(db, actx, "auth.login", "authentication", "success", "session", pair.session_id,
                 {"method": "oidc_mfa"}, commit=False)
    db.commit()
    return pair
