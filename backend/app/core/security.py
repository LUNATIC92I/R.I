"""Password hashing, token issuance and TOTP verification."""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings

_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)
# Pre-computed hash used to equalise timing when the username is unknown.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

ISSUER = "aic-backend"
AUDIENCE = "aic-mobile"
MIN_PASSWORD_LENGTH = 12


class TokenError(Exception):
    pass


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_policy_errors(password: str) -> list[str]:
    errors = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append("too_short")
    classes = sum(
        [any(c.islower() for c in password), any(c.isupper() for c in password),
         any(c.isdigit() for c in password), any(not c.isalnum() for c in password)]
    )
    if classes < 3:
        errors.append("not_enough_character_classes")
    return errors


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


@dataclass
class AccessClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    jti: str
    issued_at: int
    expires_at: int


def issue_access_token(settings: Settings, user_id: uuid.UUID, session_id: uuid.UUID) -> tuple[str, int]:
    now = int(time.time())
    exp = now + settings.access_token_ttl_seconds
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": str(user_id),
        "sid": str(session_id),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "typ": "access",
    }
    kid = settings.jwt_active_kid
    token = jwt.encode(payload, settings.jwt_signing_keys[kid], algorithm="HS256", headers={"kid": kid})
    return token, exp


def decode_access_token(settings: Settings, token: str) -> AccessClaims:
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if header.get("alg") != "HS256" or kid not in settings.jwt_signing_keys:
            raise TokenError("invalid_header")
        payload = jwt.decode(
            token,
            settings.jwt_signing_keys[kid],
            algorithms=["HS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "sid", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("invalid_token") from exc
    if payload.get("typ") != "access":
        raise TokenError("wrong_token_type")
    return AccessClaims(
        user_id=uuid.UUID(payload["sub"]),
        session_id=uuid.UUID(payload["sid"]),
        jti=payload["jti"],
        issued_at=payload["iat"],
        expires_at=payload["exp"],
    )


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str, last_step: int | None, at: float | None = None) -> int | None:
    """Return the matched time step, or ``None``. A step already used is refused (anti-replay)."""
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = at if at is not None else time.time()
    current = int(now // totp.interval)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if secrets.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def utcnow() -> datetime:
    return datetime.now(UTC)


def in_future(**kwargs) -> datetime:
    return utcnow() + timedelta(**kwargs)


def ensure_aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; every stored datetime is UTC."""
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=UTC)
