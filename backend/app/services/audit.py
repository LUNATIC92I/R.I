"""Hash-chained audit trail."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.models import AuditChainHead, AuditLog

GENESIS = "0" * 64
# Keys that must never be written to the audit trail, whatever the caller passes.
_FORBIDDEN_KEYS = {"password", "token", "refresh_token", "access_token", "secret", "code", "otp", "content", "api_key"}


@dataclass
class AuditContext:
    actor_id: uuid.UUID | None = None
    actor_label: str = "anonymous"
    ip_address: str | None = None
    request_id: str | None = None
    session_id: str | None = None


def _scrub(details: dict) -> dict:
    clean = {}
    for key, value in details.items():
        if key.lower() in _FORBIDDEN_KEYS:
            clean[key] = "[redacted]"
        elif isinstance(value, dict):
            clean[key] = _scrub(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            clean[key] = value[:300] if isinstance(value, str) else value
        else:
            clean[key] = str(value)[:300]
    return clean


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str).encode()


def _hash_entry(prev_hash: str, entry: dict) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(entry)).hexdigest()


def _entry_payload(log: AuditLog) -> dict:
    occurred: datetime = log.occurred_at
    if occurred.tzinfo is not None:
        occurred = occurred.astimezone(UTC)
    return {
        "seq": log.seq,
        "occurred_at": occurred.replace(tzinfo=None).isoformat(timespec="microseconds"),
        "actor_id": str(log.actor_id) if log.actor_id else None,
        "actor_label": log.actor_label,
        "action": log.action,
        "category": log.category,
        "outcome": log.outcome,
        "target_type": log.target_type,
        "target_id": log.target_id,
        "ip_address": log.ip_address,
        "request_id": log.request_id,
        "session_id": log.session_id,
        "details": log.details,
    }


def record(
    db: Session,
    ctx: AuditContext,
    action: str,
    category: str,
    outcome: str = "success",
    target_type: str | None = None,
    target_id: object | None = None,
    details: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    """Append an audit entry. The chain head row is locked to serialise writers."""
    head = db.execute(select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()).scalar_one_or_none()
    if head is None:
        head = AuditChainHead(id=1, last_seq=0, last_hash=GENESIS)
        db.add(head)
        db.flush()
    log = AuditLog(
        seq=head.last_seq + 1,
        occurred_at=utcnow(),
        actor_id=ctx.actor_id,
        actor_label=ctx.actor_label,
        action=action,
        category=category,
        outcome=outcome,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip_address=ctx.ip_address,
        request_id=ctx.request_id,
        session_id=ctx.session_id,
        details=_scrub(details or {}),
        prev_hash=head.last_hash,
        entry_hash="",
    )
    log.entry_hash = _hash_entry(log.prev_hash, _entry_payload(log))
    db.add(log)
    head.last_seq = log.seq
    head.last_hash = log.entry_hash
    if commit:
        db.commit()
    else:
        db.flush()
    return log


@dataclass
class ChainReport:
    valid: bool
    checked: int
    first_broken_seq: int | None = None
    reason: str | None = None


def verify_chain(db: Session, batch: int = 1000) -> ChainReport:
    prev = GENESIS
    checked = 0
    last_seq = 0
    while True:
        rows = db.scalars(select(AuditLog).where(AuditLog.seq > last_seq).order_by(AuditLog.seq).limit(batch)).all()
        if not rows:
            break
        for log in rows:
            if log.seq != last_seq + 1:
                return ChainReport(False, checked, log.seq, "sequence_gap")
            if log.prev_hash != prev:
                return ChainReport(False, checked, log.seq, "prev_hash_mismatch")
            if _hash_entry(prev, _entry_payload(log)) != log.entry_hash:
                return ChainReport(False, checked, log.seq, "entry_hash_mismatch")
            prev = log.entry_hash
            last_seq = log.seq
            checked += 1
    head = db.get(AuditChainHead, 1)
    if head and (head.last_seq != last_seq or head.last_hash != prev):
        return ChainReport(False, checked, last_seq + 1, "truncated_tail")
    return ChainReport(True, checked)
