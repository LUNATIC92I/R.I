"""Reference data and synthetic demonstration data.

``seed_reference`` installs roles, permissions, an example classification
scale and retention rules. The scale is an *example*: each institution must
replace it with the nomenclature its own law defines.

``seed_demo`` creates fictitious services and users for development only.
"""

from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authz.policy import PERMISSIONS, ROLES
from app.core.security import hash_password, utcnow
from app.models import (
    ClassificationLevel,
    Permission,
    RetentionRule,
    Role,
    Service,
    User,
)

EXAMPLE_CLASSIFICATIONS = [
    (0, "UNCLASSIFIED", "Non classifié", "Unclassified", "NON CLASSIFIÉ / UNCLASSIFIED", False),
    (1, "RESTRICTED", "Diffusion restreinte", "Restricted", "DIFFUSION RESTREINTE / RESTRICTED", True),
    (2, "CONFIDENTIAL", "Confidentiel", "Confidential", "CONFIDENTIEL / CONFIDENTIAL", True),
    (3, "SECRET", "Secret", "Secret", "SECRET / SECRET", True),
]
EXAMPLE_RETENTION = [
    ("STANDARD_5Y", "Dossier standard, révision après 5 ans", 5 * 365, "À préciser selon la loi nationale", "review"),
    ("ADMIN_2Y", "Enquête administrative close", 2 * 365, "À préciser selon la loi nationale", "delete"),
    ("CYBER_1Y", "Indicateurs techniques", 365, "À préciser selon la loi nationale", "review"),
]


def seed_reference(db: Session) -> None:
    perms = {p.code: p for p in db.scalars(select(Permission))}
    for code, description in PERMISSIONS.items():
        if code not in perms:
            perms[code] = Permission(code=code, description=description)
            db.add(perms[code])
    for code, spec in ROLES.items():
        role = db.scalar(select(Role).where(Role.code == code))
        if role is None:
            role = Role(code=code, name_fr=spec["name_fr"], name_en=spec["name_en"], case_scope=spec["scope"])
            db.add(role)
        role.case_scope = spec["scope"]
        role.permissions = [perms[p] for p in sorted(spec["permissions"])]
    for rank, code, fr, en, marking, step_up in EXAMPLE_CLASSIFICATIONS:
        if db.scalar(select(ClassificationLevel).where(ClassificationLevel.rank == rank)) is None:
            db.add(ClassificationLevel(rank=rank, code=code, label_fr=fr, label_en=en, marking=marking,
                                       export_requires_step_up=step_up))
    for code, desc, days, basis, action in EXAMPLE_RETENTION:
        if db.scalar(select(RetentionRule).where(RetentionRule.code == code)) is None:
            db.add(RetentionRule(code=code, description=desc, retention_days=days, legal_basis=basis,
                                 action_on_expiry=action))
    db.commit()


DEMO_USERS = [
    ("admin.tech", "Administrateur Technique (fictif)", "ADM-0001", "HQ", 0, ["tech_admin"]),
    ("directeur", "Direction (fictive)", "DIR-0001", "HQ", 3, ["director"]),
    ("superviseur.nord", "Superviseur Nord (fictif)", "SUP-0101", "NORD", 2, ["supervisor"]),
    ("analyste.nord", "Analyste Nord (fictive)", "ANA-0102", "NORD", 2, ["analyst"]),
    ("enqueteur.nord", "Enquêteur Nord (fictif)", "ENQ-0103", "NORD", 1, ["investigator"]),
    ("analyste.sud", "Analyste Sud (fictif)", "ANA-0201", "SUD", 2, ["analyst"]),
    ("auditeur", "Auditeur Sécurité (fictif)", "AUD-0001", "HQ", 0, ["auditor"]),
    ("consultant", "Consultant (fictif)", "CON-0001", "HQ", 1, ["consultant"]),
]


def seed_demo(db: Session, password: str | None = None) -> str:
    """Create synthetic services and users. Returns the shared demo password."""
    password = password or "Demo-" + secrets.token_urlsafe(12)
    services = {}
    hq = db.scalar(select(Service).where(Service.code == "HQ"))
    if hq is None:
        hq = Service(code="HQ", name="Direction centrale (fictive)")
        db.add(hq)
        db.flush()
    services["HQ"] = hq
    for code, name in (("NORD", "Antenne régionale Nord (fictive)"), ("SUD", "Antenne régionale Sud (fictive)")):
        svc = db.scalar(select(Service).where(Service.code == code))
        if svc is None:
            svc = Service(code=code, name=name, parent_id=hq.id)
            db.add(svc)
            db.flush()
        services[code] = svc
    roles = {r.code: r for r in db.scalars(select(Role))}
    for username, name, pro_id, service, clearance, role_codes in DEMO_USERS:
        if db.scalar(select(User).where(User.username == username)) is None:
            db.add(User(username=username, display_name=name, professional_id=pro_id,
                        service_id=services[service].id, clearance_rank=clearance,
                        password_hash=hash_password(password), password_changed_at=utcnow(),
                        roles=[roles[c] for c in role_codes]))
    db.commit()
    return password


