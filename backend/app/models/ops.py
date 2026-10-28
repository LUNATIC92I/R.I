"""Cyber intelligence, reports, alerts, notifications, sync and audit entities."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk

INDICATOR_TYPES = ("ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email")
INDICATOR_VERDICTS = ("unassessed", "suspicious", "malicious_confirmed", "benign", "false_positive")
REPORT_TYPES = (
    "intelligence_note",
    "daily_summary",
    "situation_report",
    "threat_assessment",
    "incident_report",
    "analytical_chronology",
    "strategic_watch_note",
    "executive_briefing",
    "case_closure_report",
)


class Indicator(UUIDPk, Timestamps, Base):
    __tablename__ = "indicators"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(10), nullable=False)
    value: Mapped[str] = mapped_column(String(2000), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provenance: Mapped[str] = mapped_column(String(300), nullable=False)
    context: Mapped[str] = mapped_column(Text, default="", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tlp: Mapped[str] = mapped_column(String(12), default="amber", nullable=False)
    verdict: Mapped[str] = mapped_column(String(30), default="unassessed", nullable=False)
    verdict_justification: Mapped[str | None] = mapped_column(Text)
    verdict_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    independent_source_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    campaign: Mapped[str | None] = mapped_column(String(200))
    enrichment: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    __table_args__ = (
        UniqueConstraint("case_id", "type", "value_hash", name="uq_indicator_case_value"),
        CheckConstraint(f"type IN {INDICATOR_TYPES}", name="indicator_type_valid"),
        CheckConstraint(f"verdict IN {INDICATOR_VERDICTS}", name="indicator_verdict_valid"),
        CheckConstraint("tlp IN ('clear','green','amber','amber+strict','red')", name="indicator_tlp_valid"),
        CheckConstraint("last_seen >= first_seen", name="indicator_seen_order"),
        CheckConstraint(
            "verdict <> 'malicious_confirmed' OR (verdict_by IS NOT NULL AND verdict_justification IS NOT NULL)",
            name="malicious_requires_analyst",
        ),
    )


class SecurityEvent(UUIDPk, Base):
    """Event forwarded by an institutional SIEM through a service account."""

    __tablename__ = "security_events"

    service_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("service_accounts.id", ondelete="RESTRICT"), nullable=False
    )
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sensor: Mapped[str] = mapped_column(String(200), nullable=False)
    observable_type: Mapped[str] = mapped_column(String(10), nullable=False)
    observable_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    observable_value: Mapped[str] = mapped_column(String(2000), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), default="info", nullable=False)
    raw: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    __table_args__ = (UniqueConstraint("service_account_id", "external_id", name="uq_security_event_external"),)


class Report(UUIDPk, Timestamps, Base):
    __tablename__ = "reports"

    reference: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    classification_rank: Mapped[int] = mapped_column(
        Integer, ForeignKey("classification_levels.rank", ondelete="RESTRICT"), nullable=False
    )
    dissemination: Mapped[str] = mapped_column(String(300), default="Diffusion restreinte", nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    analysis: Mapped[str] = mapped_column(Text, default="", nullable=False)
    uncertainties: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommendations: Mapped[str] = mapped_column(Text, default="", nullable=False)
    source_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    statement_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="draft", nullable=False, index=True)
    author_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __mapper_args__ = {"version_id_col": version}
    __table_args__ = (
        CheckConstraint(f"report_type IN {REPORT_TYPES}", name="report_type_valid"),
        CheckConstraint(
            "status IN ('draft','submitted','approved','rejected','disseminated')", name="report_status_valid"
        ),
    )


class Validation(UUIDPk, Base):
    """Human decision on a report or another validable object (four-eyes rule)."""

    __tablename__ = "validations"

    object_type: Mapped[str] = mapped_column(String(30), nullable=False)
    object_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    comment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    validator_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("decision IN ('approved','rejected')", name="validation_decision_valid"),
    )


class ExportRecord(UUIDPk, Base):
    __tablename__ = "export_records"

    report_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    trace_reference: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Alert(UUIDPk, Timestamps, Base):
    """Automated or manual signal requiring human review. Never proof of guilt."""

    __tablename__ = "alerts"

    case_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    service_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("services.id", ondelete="RESTRICT"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
    origin: Mapped[str] = mapped_column(String(20), default="automated", nullable=False)
    severity: Mapped[str] = mapped_column(String(10), default="low", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="new", nullable=False, index=True)
    classification_rank: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    review_note: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    __table_args__ = (
        CheckConstraint("status IN ('new','under_review','dismissed','escalated')", name="alert_status_valid"),
        CheckConstraint("severity IN ('low','medium','high')", name="alert_severity_valid"),
        CheckConstraint("origin IN ('automated','manual','security')", name="alert_origin_valid"),
    )


class Notification(UUIDPk, Base):
    """Notification shown in-app. ``generic_text`` is the only thing sent through push."""

    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    generic_text: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(30))
    target_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OfflineGrant(UUIDPk, Base):
    __tablename__ = "offline_grants"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SyncOperation(UUIDPk, Base):
    """Idempotency record for operations queued offline and pushed on reconnection."""

    __tablename__ = "sync_operations"

    client_op_id: Mapped[str] = mapped_column(String(80), nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    op_type: Mapped[str] = mapped_column(String(40), nullable=False)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    detail: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (UniqueConstraint("device_id", "client_op_id", name="uq_sync_op"),)


class AuditLog(Base):
    """Append-only, hash-chained audit trail.

    ``entry_hash = SHA256(prev_hash || canonical_json(entry))``. Any edit or
    deletion breaks the chain and is detected by ``verify_chain``. The
    application database role only has INSERT/SELECT on this table
    (see ``deploy/sql/least_privilege.sql``).
    """

    __tablename__ = "audit_logs"

    seq: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    actor_label: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    session_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)

    __table_args__ = (
        CheckConstraint("outcome IN ('success','failure','denied')", name="audit_outcome_valid"),
        Index("ix_audit_category_time", "category", "occurred_at"),
    )


class AuditChainHead(Base):
    """Single-row table locked during audit insertion to serialise the chain."""

    __tablename__ = "audit_chain_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), nullable=False, default=0)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)
