"""Role- and attribute-based access control.

A request on a case is allowed only when ALL of the following hold:

1. the user holds the functional permission (RBAC), e.g. ``case:read``;
2. the user's clearance rank is >= the case classification rank;
3. the user has a need to know: either an explicit, non-expired membership on
   the case, or a role with ``service`` scope covering the case's service
   (own service and its sub-services);
4. the case lifecycle allows the action (closed/archived cases are read-only).

Roles with ``none`` scope (technical administrator, security auditor) never
see operational case content, whatever their other permissions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.security import ensure_aware, utcnow
from app.models import Case, CaseMember, Service, User

PERMISSIONS: dict[str, str] = {
    "case:create": "Create a case",
    "case:read": "Read cases within need-to-know",
    "case:update": "Edit case content",
    "case:close": "Close or reopen a case",
    "case:archive": "Archive a closed case",
    "case:delete_request": "Request controlled deletion of a case",
    "case:delete_approve": "Approve controlled deletion of a case",
    "case:manage_members": "Grant or revoke need-to-know on a case",
    "case:offline_authorize": "Authorise offline availability of a case",
    "statement:write": "Record statements, sources, events and entities",
    "statement:verify": "Mark a statement as a confirmed fact",
    "document:upload": "Attach documents",
    "document:download": "Download documents",
    "assessment:write": "Write threat assessments",
    "assessment:confirm": "Confirm a threat assessment",
    "osint:write": "Record open-source items",
    "cyber:write": "Manage indicators of compromise",
    "cyber:verdict": "Issue a malicious verdict on an indicator",
    "cyber:integrations_manage": "Configure SIEM and threat-intel integrations",
    "report:write": "Draft reports",
    "report:validate": "Validate or reject reports",
    "report:export": "Export approved reports",
    "alert:review": "Review alerts",
    "assistant:use": "Use the analytical assistant",
    "search:use": "Use the authorised global search",
    "dashboard:service": "See service-level statistics",
    "audit:read": "Read the audit trail",
    "user:manage": "Manage user accounts",
    "role:manage": "Assign roles",
    "session:revoke_any": "Revoke any session",
    "device:revoke_any": "Revoke any device",
    "recovery:request": "Open an account recovery request",
    "recovery:approve": "Approve an account recovery request",
    "classification:manage": "Configure classification levels",
    "retention:manage": "Configure retention rules",
    "reference:manage": "Manage authorised geographic referentials",
    "system:health": "See technical service status",
}

_ANALYST_CORE = {
    "case:read", "case:update", "statement:write", "document:upload", "document:download",
    "assessment:write", "osint:write", "cyber:write", "report:write", "assistant:use", "search:use",
}

ROLES: dict[str, dict] = {
    "tech_admin": {
        "name_fr": "Administrateur technique",
        "name_en": "Technical administrator",
        "scope": "none",
        "permissions": {
            "user:manage", "role:manage", "session:revoke_any", "device:revoke_any", "recovery:request",
            "classification:manage", "retention:manage", "cyber:integrations_manage", "reference:manage",
            "system:health",
        },
    },
    "director": {
        "name_fr": "Directeur du renseignement",
        "name_en": "Intelligence director",
        "scope": "service",
        "permissions": _ANALYST_CORE | {
            "case:create", "case:close", "case:archive", "case:delete_request", "case:delete_approve",
            "case:manage_members", "case:offline_authorize", "statement:verify", "assessment:confirm",
            "cyber:verdict", "report:validate", "report:export", "alert:review", "dashboard:service",
            "recovery:approve", "system:health",
        },
    },
    "supervisor": {
        "name_fr": "Superviseur opérationnel",
        "name_en": "Operational supervisor",
        "scope": "service",
        "permissions": _ANALYST_CORE | {
            "case:create", "case:close", "case:archive", "case:delete_request", "case:manage_members",
            "case:offline_authorize", "statement:verify", "assessment:confirm", "cyber:verdict",
            "report:validate", "report:export", "alert:review", "dashboard:service",
        },
    },
    "analyst": {
        "name_fr": "Analyste du renseignement",
        "name_en": "Intelligence analyst",
        "scope": "membership",
        "permissions": _ANALYST_CORE | {"case:create", "statement:verify", "cyber:verdict", "alert:review"},
    },
    "investigator": {
        "name_fr": "Enquêteur habilité",
        "name_en": "Authorised investigator",
        "scope": "membership",
        "permissions": {
            "case:read", "case:update", "statement:write", "document:upload", "document:download",
            "osint:write", "report:write", "assistant:use", "search:use",
        },
    },
    "auditor": {
        "name_fr": "Auditeur de sécurité",
        "name_en": "Security auditor",
        "scope": "none",
        "permissions": {"audit:read", "system:health"},
    },
    "consultant": {
        "name_fr": "Consultant en lecture seule",
        "name_en": "Read-only consultant",
        "scope": "membership",
        "permissions": {"case:read", "search:use"},
    },
}

READ, WRITE, MANAGE = "read", "write", "manage"
_READ_ONLY_STATUSES = {"closed", "archived", "pending_deletion"}


@dataclass
class CaseDecision:
    allowed: bool
    reason: str


def service_subtree(db: Session, root_id: uuid.UUID) -> set[uuid.UUID]:
    rows = db.execute(select(Service.id, Service.parent_id)).all()
    children: dict[uuid.UUID, list[uuid.UUID]] = {}
    for sid, parent in rows:
        if parent is not None:
            children.setdefault(parent, []).append(sid)
    result, stack = set(), [root_id]
    while stack:
        current = stack.pop()
        if current in result:
            continue
        result.add(current)
        stack.extend(children.get(current, []))
    return result


def _scopes(user: User) -> set[str]:
    return {r.case_scope for r in user.roles}


def has_permission(user: User, permission: str) -> bool:
    return user.is_active and permission in user.permission_codes


def _membership(db: Session, user: User, case_id: uuid.UUID) -> CaseMember | None:
    member = db.scalar(select(CaseMember).where(CaseMember.case_id == case_id, CaseMember.user_id == user.id))
    if member and member.expires_at and ensure_aware(member.expires_at) <= utcnow():
        return None
    return member


def decide_case(db: Session, user: User, case: Case, level: str) -> CaseDecision:
    if not user.is_active:
        return CaseDecision(False, "inactive_user")
    scopes = _scopes(user)
    if scopes <= {"none"}:
        return CaseDecision(False, "role_without_case_access")
    if user.clearance_rank < case.classification_rank:
        return CaseDecision(False, "insufficient_clearance")

    decision = _need_to_know(db, user, case, level)
    if decision.allowed and level != READ and case.status in _READ_ONLY_STATUSES:
        return CaseDecision(False, "case_read_only")
    return decision


def _need_to_know(db: Session, user: User, case: Case, level: str) -> CaseDecision:
    if "service" in _scopes(user) and case.service_id in service_subtree(db, user.service_id):
        return CaseDecision(True, "service_scope")
    if case.owner_id == user.id:
        return CaseDecision(True, "owner")
    member = _membership(db, user, case.id)
    if member is None:
        return CaseDecision(False, "no_need_to_know")
    if level == READ:
        return CaseDecision(True, "member")
    if level == WRITE and member.access == "write":
        return CaseDecision(True, "member_write")
    return CaseDecision(False, "member_read_only")

def accessible_case_filter(db: Session, user: User) -> ColumnElement[bool]:
    """SQL predicate selecting every case the user may read.

    Used by lists, search, dashboard, correlation and maps so that no
    aggregate ever includes a case outside the user's need to know.
    """
    scopes = _scopes(user)
    if not user.is_active or scopes <= {"none"} or "case:read" not in user.permission_codes:
        return Case.id.is_(None)  # matches nothing
    now = utcnow()
    member_case_ids = select(CaseMember.case_id).where(
        CaseMember.user_id == user.id,
        or_(CaseMember.expires_at.is_(None), CaseMember.expires_at > now),
    )
    clauses = [Case.owner_id == user.id, Case.id.in_(member_case_ids)]
    if "service" in scopes:
        clauses.append(Case.service_id.in_(service_subtree(db, user.service_id)))
    return (Case.classification_rank <= user.clearance_rank) & or_(*clauses)
