"""Runtime configuration.

Every secret is read from the environment (or from files mounted by the
orchestrator, see ``*_FILE`` variants). Nothing sensitive has a default value:
the application refuses to start in preproduction or production when a
secret is missing or too weak.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from functools import lru_cache


class ConfigurationError(RuntimeError):
    pass


def _read(name: str, default: str | None = None) -> str | None:
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        with open(file_path, encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(name, default)


def _bool(name: str, default: bool) -> bool:
    value = _read(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = _read(name)
    return int(value) if value is not None else default


@dataclass(frozen=True)
class Settings:
    environment: str
    database_url: str
    jwt_signing_keys: dict[str, str]
    jwt_active_kid: str
    master_key_b64: str
    institution_name: str = "AFRICAN INTELLIGENCE CORE"
    country_code: str = "XX"
    access_token_ttl_seconds: int = 600
    refresh_token_ttl_seconds: int = 8 * 3600
    step_up_ttl_seconds: int = 300
    max_failed_logins: int = 5
    lockout_minutes: int = 30
    rate_limit_auth_per_minute: int = 10
    rate_limit_default_per_minute: int = 240
    cors_origins: list[str] = field(default_factory=list)
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    offline_max_classification_rank: int = 1
    offline_package_ttl_hours: int = 24
    llm_endpoint: str | None = None
    llm_max_classification_rank: int = 0
    misp_url: str | None = None
    misp_api_key: str | None = None
    trusted_proxy_count: int = 0

    @property
    def is_production_like(self) -> bool:
        return self.environment in {"preproduction", "production"}

    @property
    def master_key(self) -> bytes:
        key = base64.b64decode(self.master_key_b64)
        if len(key) != 32:
            raise ConfigurationError("AIC_MASTER_KEY must be 32 bytes, base64 encoded")
        return key


def _parse_signing_keys(raw: str | None) -> dict[str, str]:
    """Format: ``kid1:secret1,kid2:secret2``. Several keys allow rotation."""
    keys: dict[str, str] = {}
    if not raw:
        return keys
    for item in raw.split(","):
        kid, _, secret = item.partition(":")
        if kid and secret:
            keys[kid.strip()] = secret.strip()
    return keys


def load_settings() -> Settings:
    environment = (_read("AIC_ENV", "development") or "development").lower()
    if environment not in {"development", "test", "preproduction", "production"}:
        raise ConfigurationError(f"Unknown AIC_ENV: {environment}")

    database_url = _read("AIC_DATABASE_URL")
    signing_keys = _parse_signing_keys(_read("AIC_JWT_KEYS"))
    active_kid = _read("AIC_JWT_ACTIVE_KID") or (next(iter(signing_keys), ""))
    master_key = _read("AIC_MASTER_KEY")

    missing = [
        name
        for name, value in (
            ("AIC_DATABASE_URL", database_url),
            ("AIC_JWT_KEYS", signing_keys),
            ("AIC_MASTER_KEY", master_key),
        )
        if not value
    ]
    if missing:
        raise ConfigurationError(
            "Missing required configuration: " + ", ".join(missing)
            + ". Copy backend/.env.example and generate real values (see docs/INSTALL_BACKEND.md)."
        )
    if active_kid not in signing_keys:
        raise ConfigurationError("AIC_JWT_ACTIVE_KID does not match any key in AIC_JWT_KEYS")
    for kid, secret in signing_keys.items():
        if len(secret) < 32:
            raise ConfigurationError(f"JWT key '{kid}' must be at least 32 characters")

    settings = Settings(
        environment=environment,
        database_url=database_url,  # type: ignore[arg-type]
        jwt_signing_keys=signing_keys,
        jwt_active_kid=active_kid,
        master_key_b64=master_key,  # type: ignore[arg-type]
        institution_name=_read("AIC_INSTITUTION_NAME", "AFRICAN INTELLIGENCE CORE") or "",
        country_code=_read("AIC_COUNTRY_CODE", "XX") or "XX",
        access_token_ttl_seconds=_int("AIC_ACCESS_TTL", 600),
        refresh_token_ttl_seconds=_int("AIC_REFRESH_TTL", 8 * 3600),
        step_up_ttl_seconds=_int("AIC_STEP_UP_TTL", 300),
        max_failed_logins=_int("AIC_MAX_FAILED_LOGINS", 5),
        lockout_minutes=_int("AIC_LOCKOUT_MINUTES", 30),
        rate_limit_auth_per_minute=_int("AIC_RATE_LIMIT_AUTH", 10),
        rate_limit_default_per_minute=_int("AIC_RATE_LIMIT_DEFAULT", 240),
        cors_origins=[o for o in (_read("AIC_CORS_ORIGINS", "") or "").split(",") if o],
        oidc_issuer=_read("AIC_OIDC_ISSUER"),
        oidc_audience=_read("AIC_OIDC_AUDIENCE"),
        oidc_jwks_url=_read("AIC_OIDC_JWKS_URL"),
        offline_max_classification_rank=_int("AIC_OFFLINE_MAX_CLASSIFICATION_RANK", 1),
        offline_package_ttl_hours=_int("AIC_OFFLINE_TTL_HOURS", 24),
        llm_endpoint=_read("AIC_LLM_ENDPOINT"),
        llm_max_classification_rank=_int("AIC_LLM_MAX_CLASSIFICATION_RANK", 0),
        misp_url=_read("AIC_MISP_URL"),
        misp_api_key=_read("AIC_MISP_API_KEY"),
        trusted_proxy_count=_int("AIC_TRUSTED_PROXY_COUNT", 0),
    )
    _ = settings.master_key  # validates length early
    if settings.is_production_like:
        if not settings.database_url.startswith("postgresql"):
            raise ConfigurationError("PostgreSQL is mandatory outside development")
        if "sslmode=" not in settings.database_url and "localhost" not in settings.database_url:
            raise ConfigurationError("Database connections must set sslmode outside development")
        if settings.llm_endpoint and not settings.llm_endpoint.startswith("https://"):
            raise ConfigurationError("AIC_LLM_ENDPOINT must use HTTPS")
    return settings


@lru_cache
def get_settings() -> Settings:
    return load_settings()
