"""Authentication, MFA, sessions, lockout, step-up."""

import pyotp
from sqlalchemy import select

from app.models import AuditLog, AuthSession, User
from tests.conftest import TEST_PASSWORD, _reset_totp_step, device, login


def test_full_login_with_totp_enrollment(client, engine):
    actor = login(client, engine, "analyste.nord")
    me = actor.get("/api/v1/me")
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "analyste.nord"
    assert body["mfa_enrolled"] is True
    assert "case:read" in body["permissions"]


def test_unknown_user_and_wrong_password_return_same_error(client):
    r1 = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "x", "device": device("dev-aaaa-0001")})
    r2 = client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": "wrong",
                                                 "device": device("dev-aaaa-0001")})
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json() == {"code": "invalid_credentials", "message": "invalid_credentials"}


def test_password_alone_never_yields_a_token(client):
    r = client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": TEST_PASSWORD,
                                                "device": device("dev-bbbb-0001")})
    assert r.status_code == 200
    assert "access_token" not in r.json()
    assert r.json()["mfa_required"] is True


def test_lockout_after_repeated_failures(client, db):
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"username": "analyste.sud", "password": "wrong",
                                                "device": device("dev-cccc-0001")})
    r = client.post("/api/v1/auth/login", json={"username": "analyste.sud", "password": TEST_PASSWORD,
                                                "device": device("dev-cccc-0001")})
    assert r.status_code == 401
    user = db.scalar(select(User).where(User.username == "analyste.sud"))
    assert user.locked_until is not None


def test_totp_code_cannot_be_replayed(client, engine):
    actor = login(client, engine, "analyste.nord")
    r = client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": TEST_PASSWORD,
                                                "device": device(actor.install_id)})
    _reset_totp_step(engine, "analyste.nord")
    code = pyotp.TOTP(actor.secret).now()
    first = client.post("/api/v1/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code})
    assert first.status_code == 200
    r2 = client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": TEST_PASSWORD,
                                                 "device": device(actor.install_id)})
    replay = client.post("/api/v1/auth/mfa", json={"mfa_token": r2.json()["mfa_token"], "code": code})
    assert replay.status_code == 401


def test_mfa_challenge_is_single_use(client, engine):
    actor = login(client, engine, "analyste.nord")
    r = client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": TEST_PASSWORD,
                                                "device": device(actor.install_id)})
    token = r.json()["mfa_token"]
    _reset_totp_step(engine, "analyste.nord")
    assert client.post("/api/v1/auth/mfa", json={"mfa_token": token, "code": pyotp.TOTP(actor.secret).now()}).status_code == 200
    _reset_totp_step(engine, "analyste.nord")
    again = client.post("/api/v1/auth/mfa", json={"mfa_token": token, "code": pyotp.TOTP(actor.secret).now()})
    assert again.status_code == 401


def test_refresh_rotation_and_reuse_detection(client, engine, db):
    actor = login(client, engine, "analyste.nord")
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": actor.refresh})
    assert r.status_code == 200
    new_refresh = r.json()["refresh_token"]
    assert new_refresh != actor.refresh
    # Presenting the old token again is treated as theft: the whole session dies.
    reuse = client.post("/api/v1/auth/refresh", json={"refresh_token": actor.refresh})
    assert reuse.status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh}).status_code == 401
    me = client.get("/api/v1/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert me.status_code == 401
    session = db.get(AuthSession, __import__("uuid").UUID(actor.session_id))
    assert session.revoked_reason == "refresh_token_reuse"


def test_logout_invalidates_access_token_immediately(client, engine):
    actor = login(client, engine, "analyste.nord")
    assert actor.post("/api/v1/auth/logout").status_code == 204
    assert actor.get("/api/v1/me").status_code == 401


def test_tampered_or_foreign_token_rejected(client, engine):
    actor = login(client, engine, "analyste.nord")
    header, payload, sig = actor.token.split(".")
    forged = f"{header}.{payload}.{sig[:-2]}AA"
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_alg = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + payload + "."
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401


def test_step_up_wrong_code_rejected(client, engine):
    actor = login(client, engine, "superviseur.nord")
    r = actor.post("/api/v1/auth/step-up", json={"password": TEST_PASSWORD, "code": "000000"})
    assert r.status_code == 401


def test_login_events_are_audited_without_secrets(client, engine, db):
    login(client, engine, "analyste.nord")
    client.post("/api/v1/auth/login", json={"username": "analyste.nord", "password": "Wrong-Password-123",
                                            "device": device("dev-dddd-0001")})
    rows = db.scalars(select(AuditLog).where(AuditLog.action == "auth.login")).all()
    outcomes = {r.outcome for r in rows}
    assert {"success", "failure"} <= outcomes
    dump = " ".join(str(r.details) for r in db.scalars(select(AuditLog)).all())
    assert TEST_PASSWORD not in dump and "Wrong-Password-123" not in dump


def test_auth_rate_limit(client, app_env):
    from app.core import ratelimit

    settings = app_env[1]
    object.__setattr__(settings, "rate_limit_auth_per_minute", 3)
    ratelimit.limiter.reset()
    codes = [client.post("/api/v1/auth/login", json={"username": "x", "password": "y",
                                                     "device": device("dev-eeee-0001")}).status_code for _ in range(5)]
    assert 429 in codes
