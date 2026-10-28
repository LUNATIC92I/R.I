"""Test fixtures. Only synthetic data is used.

Set ``AIC_TEST_DATABASE_URL`` to a disposable PostgreSQL database to run the
suite against PostgreSQL (recommended, used in CI); otherwise SQLite is used.
"""

from __future__ import annotations

import base64
import os
import secrets
import urllib.parse
from dataclasses import dataclass
from datetime import date, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

TEST_PASSWORD = "Synthetic-Test-Pass-2026!"


def _settings():
    from app.core.config import Settings

    url = os.environ.get("AIC_TEST_DATABASE_URL", "sqlite:///./.pytest-aic.db")
    return Settings(
        environment="test",
        database_url=url,
        jwt_signing_keys={"test-k1": secrets.token_urlsafe(48)},
        jwt_active_kid="test-k1",
        master_key_b64=base64.b64encode(os.urandom(32)).decode(),
        rate_limit_auth_per_minute=1000,
        rate_limit_default_per_minute=10000,
        offline_max_classification_rank=1,
    )


@pytest.fixture()
def app_env():
    from app.core.ratelimit import limiter
    from app.db.base import Base
    from app.db.session import get_engine
    from app.main import create_app
    from app.seed import seed_demo, seed_reference

    settings = _settings()
    application = create_app(settings)
    engine = get_engine()
    _reset_schema(engine)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        seed_reference(db)
        seed_demo(db, TEST_PASSWORD)
    limiter.reset()
    yield application, settings, engine
    engine.dispose()


def _reset_schema(engine) -> None:
    from app.db.base import Base

    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
    else:
        with engine.begin() as conn:
            conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
            for table in reversed(Base.metadata.sorted_tables):
                conn.exec_driver_sql(f'DROP TABLE IF EXISTS "{table.name}"')
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")


@pytest.fixture()
def client(app_env):
    application, _, _ = app_env
    return TestClient(application)


@pytest.fixture()
def db(app_env):
    _, _, engine = app_env
    with Session(engine) as session:
        yield session


@dataclass
class Actor:
    username: str
    token: str
    refresh: str
    session_id: str
    client: TestClient
    secret: str
    install_id: str

    @property
    def h(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, url, **kw):
        return self.client.get(url, headers=self.h, **kw)

    def post(self, url, **kw):
        return self.client.post(url, headers=self.h, **kw)

    def patch(self, url, **kw):
        return self.client.patch(url, headers=self.h, **kw)

    def delete(self, url, **kw):
        return self.client.delete(url, headers=self.h, **kw)

    def step_up(self, engine):
        _reset_totp_step(engine, self.username)
        r = self.post("/api/v1/auth/step-up", json={"password": TEST_PASSWORD, "code": pyotp.TOTP(self.secret).now()})
        assert r.status_code == 204, r.text


def _reset_totp_step(engine, username: str) -> None:
    """TOTP codes are single-use; tests that log in repeatedly within 30 s reset the marker."""
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET totp_last_step = NULL WHERE username = :u"), {"u": username})


def device(install_id: str) -> dict:
    return {"install_id": install_id, "platform": "test", "label": "Synthetic test device"}


_secrets: dict[str, str] = {}


def login(client: TestClient, engine, username: str, install_id: str | None = None) -> Actor:
    install_id = install_id or f"dev-{username.replace('.', '-')}-0001"
    r = client.post("/api/v1/auth/login", json={"username": username, "password": TEST_PASSWORD,
                                                "device": device(install_id)})
    assert r.status_code == 200, r.text
    body = r.json()
    if body["enrollment_required"]:
        uri = body["totp_provisioning_uri"]
        _secrets[(id(engine), username)] = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)["secret"][0]
    secret = _secrets[(id(engine), username)]
    _reset_totp_step(engine, username)
    r = client.post("/api/v1/auth/mfa", json={"mfa_token": body["mfa_token"], "code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    tok = r.json()
    return Actor(username, tok["access_token"], tok["refresh_token"], tok["session_id"], client, secret, install_id)


@pytest.fixture()
def actors(client, app_env):
    _, _, engine = app_env
    cache: dict[str, Actor] = {}

    def get(username: str) -> Actor:
        if username not in cache:
            cache[username] = login(client, engine, username)
        return cache[username]

    return get


@pytest.fixture()
def engine(app_env):
    return app_env[2]


def case_payload(**overrides) -> dict:
    data = {
        "title": "Dossier fictif de test",
        "category": "critical_infrastructure",
        "country_code": "XX",
        "jurisdiction": "Juridiction fictive",
        "classification_rank": 1,
        "priority": "high",
        "executive_summary": "Synthèse fictive.",
        "analysis_context": "Contexte fictif.",
        "legal_basis": "Base légale fictive, article 0",
        "review_date": (date.today() + timedelta(days=10)).isoformat(),
        "retention_rule_code": "STANDARD_5Y",
    }
    data.update(overrides)
    return data


@pytest.fixture()
def nord_case(actors):
    analyst = actors("analyste.nord")
    r = analyst.post("/api/v1/cases", json=case_payload())
    assert r.status_code == 201, r.text
    return r.json()


def user_id(db: Session, username: str):
    from app.models import User

    return db.scalar(select(User.id).where(User.username == username))
