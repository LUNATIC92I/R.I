"""OpenID Connect connector for an institutional identity provider.

Requires ``AIC_OIDC_ISSUER``, ``AIC_OIDC_AUDIENCE`` and ``AIC_OIDC_JWKS_URL``.
The mobile app performs the authorisation-code + PKCE flow against the IdP and
sends the resulting ID token here; the backend validates it and opens its own
session. Not exercised against a live IdP in this repository: see
docs/PRODUCTION_READINESS.md.
"""

from __future__ import annotations

from dataclasses import dataclass

import jwt

from app.core.config import Settings

# Authentication method references that count as multi-factor (RFC 8176).
STRONG_AMR = {"mfa", "hwk", "otp", "sc", "fido"}


class OidcError(Exception):
    pass


@dataclass
class OidcIdentity:
    subject: str
    multi_factor: bool


class OidcVerifier:
    def __init__(self, settings: Settings, jwk_client: jwt.PyJWKClient | None = None):
        if not (settings.oidc_issuer and settings.oidc_audience and settings.oidc_jwks_url):
            raise OidcError("oidc_not_configured")
        self.issuer = settings.oidc_issuer
        self.audience = settings.oidc_audience
        self.jwk_client = jwk_client or jwt.PyJWKClient(settings.oidc_jwks_url, cache_keys=True)

    def verify(self, id_token: str, nonce: str) -> OidcIdentity:
        try:
            key = self.jwk_client.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token, key.key, algorithms=["RS256", "ES256", "PS256"], audience=self.audience,
                issuer=self.issuer, options={"require": ["exp", "iat", "sub", "nonce"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("invalid_id_token") from exc
        if claims.get("nonce") != nonce:
            raise OidcError("nonce_mismatch")
        amr = set(claims.get("amr") or [])
        return OidcIdentity(subject=str(claims["sub"]), multi_factor=bool(amr & STRONG_AMR))
