"""API hardening, configuration safety, notifications, recovery, migrations."""

import os
import subprocess
import sys

import pyotp
import pytest
from sqlalchemy import select

from app.connectors import push
from app.core.config import ConfigurationError, load_settings
from app.models import Notification
from tests.conftest import TEST_PASSWORD, case_payload, device, login, user_id


def test_security_headers_present(client):
    r = client.get("/api/v1/health")
    for header in ("strict-transport-security", "x-content-type-options", "x-frame-options",
                   "content-security-policy", "cache-control", "x-request-id"):
        assert header in r.headers


def test_unauthenticated_requests_rejected(client):
    for path in ("/api/v1/cases", "/api/v1/me", "/api/v1/dashboard", "/api/v1/audit", "/api/v1/alerts"):
        assert client.get(path).status_code == 401


def test_validation_errors_do_not_echo_input(actors):
    r = actors("analyste.nord").post("/api/v1/cases", json=case_payload(category="<script>alert(1)</script>"))
    assert r.status_code == 422 and "<script>" not in r.text


def test_sql_injection_payloads_are_inert(actors, nord_case):
    a = actors("analyste.nord")
    for q in ("' OR 1=1 --", "%' UNION SELECT password_hash FROM users --", "_%"):
        r = a.get("/api/v1/search", params={"q": q})
        assert r.status_code == 200 and r.json()["count"] == 0
        assert a.get("/api/v1/cases", params={"q": q}).json() == []


def test_unhandled_errors_are_generic(app_env, actors, monkeypatch):
    from fastapi.testclient import TestClient

    from app.services import correlation

    def boom(*a, **k):
        raise RuntimeError("internal detail /etc/secret")

    monkeypatch.setattr(correlation, "gaps", boom)
    c = TestClient(app_env[0], raise_server_exceptions=False)
    a = actors("analyste.nord")
    case = a.post("/api/v1/cases", json=case_payload()).json()
    r = c.get(f"/api/v1/cases/{case['id']}/gaps", headers=a.h)
    assert r.status_code == 500 and "secret" not in r.text and r.json()["code"] == "internal_error"


def test_payload_too_large_rejected(client):
    r = client.post("/api/v1/auth/login", content=b"x", headers={"content-length": str(40 * 1024 * 1024),
                                                                   "content-type": "application/json"})
    assert r.status_code == 413


def test_notifications_are_generic(actors, nord_case, db):
    push.gateway.sent.clear()
    sup = actors("superviseur.nord")
    sup.post(f"/api/v1/cases/{nord_case['id']}/members", json={
        "user_id": str(user_id(db, "analyste.sud")), "justification": "Mission fictive"})
    notes = actors("analyste.sud").get("/api/v1/me/notifications").json()
    assert notes and notes[0]["generic_text"] == "Vos accès ont été mis à jour"
    rows = db.scalars(select(Notification)).all()
    assert all(nord_case["title"] not in n.generic_text and nord_case["reference"] not in n.generic_text for n in rows)


def test_account_recovery_two_person_rule(client, engine, db):
    admin = login(client, engine, "admin.tech")
    director = login(client, engine, "directeur")
    target = user_id(db, "analyste.nord")
    req = admin.post("/api/v1/admin/recovery", json={"user_id": str(target),
                                                     "identity_check_reference": "PV-FICTIF-001"}).json()
    # The technical admin cannot approve (lacks permission); the director can, after step-up.
    assert admin.post(f"/api/v1/admin/recovery/{req['id']}/approve").status_code == 403
    director.step_up(engine)
    code = director.post(f"/api/v1/admin/recovery/{req['id']}/approve").json()["recovery_code"]
    new_password = "Nouveau-Mot-De-Passe-2026!"
    r = client.post("/api/v1/auth/recovery/complete", json={"username": "analyste.nord", "recovery_code": code,
                                                            "new_password": new_password})
    assert r.status_code == 204
    again = client.post("/api/v1/auth/recovery/complete", json={"username": "analyste.nord", "recovery_code": code,
                                                                "new_password": new_password})
    assert again.status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": new_password,
                                                "device": device("dev-recov-0001")})
    assert r.status_code == 200 and r.json()["enrollment_required"] is True


def test_privilege_creation_requires_step_up(client, engine, db):
    admin = login(client, engine, "admin.tech")
    payload = {"username": "nouvel.agent", "display_name": "Agent fictif", "professional_id": "ANA-9999",
               "service_id": str(db.scalar(select(__import__("app.models", fromlist=["Service"]).Service.id))),
               "clearance_rank": 1, "roles": ["analyst"], "initial_password": TEST_PASSWORD}
    assert admin.post("/api/v1/admin/users", json=payload).json()["code"] == "step_up_required"
    admin.step_up(engine)
    assert admin.post("/api/v1/admin/users", json=dict(payload, initial_password="short")).status_code == 422
    assert admin.post("/api/v1/admin/users", json=payload).status_code == 201


def test_config_refuses_missing_secrets(monkeypatch):
    for k in ("AIC_DATABASE_URL", "AIC_JWT_KEYS", "AIC_MASTER_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ConfigurationError):
        load_settings()


def test_config_refuses_weak_jwt_key_and_sqlite_in_production(monkeypatch):
    monkeypatch.setenv("AIC_MASTER_KEY", "A" * 43 + "=")
    monkeypatch.setenv("AIC_DATABASE_URL", "sqlite:///x.db")
    monkeypatch.setenv("AIC_JWT_KEYS", "k1:short")
    with pytest.raises(ConfigurationError):
        load_settings()
    monkeypatch.setenv("AIC_JWT_KEYS", "k1:" + "x" * 40)
    monkeypatch.setenv("AIC_ENV", "production")
    with pytest.raises(ConfigurationError):
        load_settings()


def test_no_secrets_committed_in_repository():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True).stdout.split()
    assert not [f for f in out if f.endswith((".env", ".pem", ".key", ".jks", ".keystore", ".p12"))]


@pytest.mark.skipif(not os.environ.get("AIC_TEST_DATABASE_URL", "").startswith("postgresql"),
                    reason="Alembic migration test runs against PostgreSQL")
def test_alembic_migration_matches_models(app_env):
    from sqlalchemy import text

    engine = app_env[2]
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    env = dict(os.environ, AIC_DATABASE_URL=os.environ["AIC_TEST_DATABASE_URL"])
    cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    up = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=cwd, env=env, capture_output=True, text=True)
    assert up.returncode == 0, up.stderr
    check = subprocess.run([sys.executable, "-m", "alembic", "check"], cwd=cwd, env=env, capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr


def test_totp_helper_rejects_malformed_codes():
    from app.core.security import verify_totp

    secret = pyotp.random_base32()
    assert verify_totp(secret, "12345", None) is None
    assert verify_totp(secret, "abcdef", None) is None
    assert verify_totp(secret, pyotp.TOTP(secret).now(), None) is not None
