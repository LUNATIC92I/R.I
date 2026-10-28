"""Case (dossier) management and analytical entities.

Operational metadata (``cases``) is kept apart from sensitive content
(``document_blobs`` holds encrypted bytes only). Every analytical item carries
its epistemic status so that facts, claims and hypotheses are never confused.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, Timestamps, UUIDPk

CASE_STATUSES = ("open", "under_review", "closed", "archived", "pending_deletion")
CASE_PRIORITIES = ("low", "medium", "high", "critical")
CASE_CATEGORIES = (
    "terrorism_organised_violence",
    "organised_crime",
    "illicit_trafficking",
    "critical_infrastructure",
    "cyber_threat_public_institutions",
    "foreign_interference",
    "physical_threat_sensitive_sites",
    "security_crisis_destabilisation",
    "administrative_inquiry",
    "other",
)
STATEMENT_KINDS = ("confirmed_fact", "unverified_information", "claim", "working_hypothesis", "alternative_hypothesis")
# NATO-style source reliability (A-F) and information credibility (1-6), widely
# used in intelligence analysis; the scale can be relabelled per institution.
RELIABILITY = ("A", "B", "C", "D", "E", "F")
CREDIBILITY = (1, 2, 3, 4, 5, 6)
LOCATION_PRECISION = ("exact", "approximate", "region", "unknown")


class RetentionRule(UUIDPk, Timestamps, Base):
    __tablename__ = "retention_rules"

    code: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(300), nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    legal_basis: Mapped[str] = mapped_column(String(300), nullable=False)
    action_on_expiry: Mapped[str] = mapped_column(String(20), default="review", nullable=False)

    __table_args__ = (
        CheckConstraint("retention_days > 0", name="retention_positive"),
        CheckConstraint("action_on_expiry IN ('review','archive','delete')", name="retention_action_valid"),
    )


class Case(UUIDPk, Timestamps, Base):
    __tablename__ = "cases"

    reference: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    country_code: Mapped[str] = mapped_column(String(2), nullable=False)
    jurisdiction: Mapped[str] = mapped_column(String(200), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    service_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("services.id", ondelete="RESTRICT"), nullable=False, index=True)
    classification_rank: Mapped[int] = mapped_column(
        Integer, ForeignKey("classification_levels.rank", ondelete="RESTRICT"), nullable=False, index=True
    )
    priority: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False, index=True)
    executive_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    analysis_context: Mapped[str] = mapped_column(Text, default="", nullable=False)
    confidence_assessment: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    legal_basis: Mapped[str] = mapped_column(String(500), nullable=False)
    authorised_follow_up: Mapped[str] = mapped_column(Text, default="", nullable=False)
    review_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    retention_rule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("retention_rules.id", ondelete="RESTRICT"), nullable=False
    )
    offline_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deletion_requested_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    deletion_justification: Mapped[str | None] = mapped_column(String(500))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    members: Mapped[list[CaseMember]] = relationship(back_populates="case", cascade="all, delete-orphan")

    __mapper_args__ = {"version_id_col": version}
    __table_args__ = (
        CheckConstraint(f"status IN {CASE_STATUSES}", name="case_status_valid"),
        CheckConstraint(f"priority IN {CASE_PRIORITIES}", name="case_priority_valid"),
        CheckConstraint("confidence_assessment IN ('low','moderate','high')", name="case_confidence_valid"),
        Index("ix_cases_service_status", "service_id", "status"),
    )


class CaseMember(UUIDPk, Base):
    """Explicit need-to-know grant on a case."""

    __tablename__ = "case_members"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    access: Mapped[str] = mapped_column(String(10), default="read", nullable=False)
    granted_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    justification: Mapped[str] = mapped_column(String(300), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case: Mapped[Case] = relationship(back_populates="members")

    __table_args__ = (
        UniqueConstraint("case_id", "user_id", name="uq_case_member"),
        CheckConstraint("access IN ('read','write')", name="member_access_valid"),
    )


class CaseLink(UUIDPk, Base):
    """Documented relation between two cases."""

    __tablename__ = "case_links"

    from_case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    to_case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    rationale: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("from_case_id", "to_case_id", name="uq_case_link"),
        CheckConstraint("from_case_id <> to_case_id", name="case_link_distinct"),
    )


class Source(UUIDPk, Timestamps, Base):
    """Provenance of information. Human source identities are never stored here:
    ``protected_reference`` points to the institution's separate source registry."""

    __tablename__ = "sources"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    reliability: Mapped[str] = mapped_column(String(1), default="F", nullable=False)
    url: Mapped[str | None] = mapped_column(String(2000))
    author: Mapped[str | None] = mapped_column(String(300))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    protected_reference: Mapped[str | None] = mapped_column(String(80))
    legal_basis: Mapped[str] = mapped_column(String(300), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('open_source','institutional_system','official_report','human_protected','technical','other')",
            name="source_kind_valid",
        ),
        CheckConstraint(f"reliability IN {RELIABILITY}", name="source_reliability_valid"),
    )


class Statement(UUIDPk, Timestamps, Base):
    """An analytical assertion with explicit epistemic status."""

    __tablename__ = "statements"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    credibility: Mapped[int] = mapped_column(Integer, default=6, nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("sources.id", ondelete="SET NULL"), index=True)
    contradicts_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("statements.id", ondelete="SET NULL"))
    verified_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __mapper_args__ = {"version_id_col": version}
    __table_args__ = (
        CheckConstraint(f"kind IN {STATEMENT_KINDS}", name="statement_kind_valid"),
        CheckConstraint("credibility BETWEEN 1 AND 6", name="statement_credibility_valid"),
        # A confirmed fact must reference a source and a human verifier.
        CheckConstraint(
            "kind <> 'confirmed_fact' OR (source_id IS NOT NULL AND verified_by IS NOT NULL)",
            name="fact_requires_source_and_verifier",
        ),
    )


class Document(UUIDPk, Timestamps, Base):
    """Document metadata. Content lives encrypted in ``document_blobs``."""

    __tablename__ = "documents"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    classification_rank: Mapped[int] = mapped_column(
        Integer, ForeignKey("classification_levels.rank", ondelete="RESTRICT"), nullable=False
    )
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("sources.id", ondelete="SET NULL"))
    current_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    download_allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    versions: Mapped[list[DocumentBlob]] = relationship(
        back_populates="document", cascade="all, delete-orphan", order_by="DocumentBlob.version"
    )


class DocumentBlob(UUIDPk, Base):
    __tablename__ = "document_blobs"

    document_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(120), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(String(40), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    document: Mapped[Document] = relationship(back_populates="versions")

    __table_args__ = (UniqueConstraint("document_id", "version", name="uq_document_version"),)


class Event(UUIDPk, Timestamps, Base):
    """A dated occurrence in a case timeline, with explicit location precision."""

    __tablename__ = "events"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(60), default="other", nullable=False)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    occurred_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    date_precision: Mapped[str] = mapped_column(String(10), default="exact", nullable=False)
    location_label: Mapped[str | None] = mapped_column(String(300))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    location_precision: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    location_accuracy_m: Mapped[float | None] = mapped_column(Float)
    location_provenance: Mapped[str | None] = mapped_column(String(300))
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("sources.id", ondelete="SET NULL"))
    document_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("documents.id", ondelete="SET NULL"))
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    __table_args__ = (
        CheckConstraint(f"location_precision IN {LOCATION_PRECISION}", name="event_location_precision_valid"),
        CheckConstraint("date_precision IN ('exact','day','month','year','unknown')", name="event_date_precision_valid"),
        CheckConstraint("latitude IS NULL OR (latitude BETWEEN -90 AND 90)", name="event_lat_valid"),
        CheckConstraint("longitude IS NULL OR (longitude BETWEEN -180 AND 180)", name="event_lon_valid"),
        CheckConstraint(
            "(latitude IS NULL) = (longitude IS NULL)", name="event_coordinates_pair"
        ),
    )


class Entity(UUIDPk, Timestamps, Base):
    """An organisation, place, document reference or other node in the relation graph."""

    __tablename__ = "entities"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    label: Mapped[str] = mapped_column(String(300), nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('organisation','place','event','document','infrastructure','person','other')",
            name="entity_kind_valid",
        ),
    )


class Relation(UUIDPk, Timestamps, Base):
    """A documented relation. Without ``source_id`` or ``basis`` it cannot exist."""

    __tablename__ = "relations"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    from_entity_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    to_entity_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    relation_type: Mapped[str] = mapped_column(String(80), nullable=False)
    basis: Mapped[str] = mapped_column(String(500), nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("sources.id", ondelete="SET NULL"))
    confidence: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    is_causal_claim: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    __table_args__ = (
        CheckConstraint("confidence IN ('low','moderate','high')", name="relation_confidence_valid"),
        CheckConstraint("from_entity_id <> to_entity_id", name="relation_distinct"),
    )


class ThreatAssessment(UUIDPk, Timestamps, Base):
    __tablename__ = "threat_assessments"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    threat: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    level: Mapped[str] = mapped_column(String(30), default="signal", nullable=False)
    observed_facts: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    source_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    source_reliability: Mapped[str] = mapped_column(String(1), default="F", nullable=False)
    information_credibility: Mapped[int] = mapped_column(Integer, default=6, nullable=False)
    alternative_hypotheses: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    contradicting_elements: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    possible_consequences: Mapped[str] = mapped_column(Text, default="", nullable=False)
    uncertainty: Mapped[str] = mapped_column(String(20), default="high", nullable=False)
    recommended_verifications: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    indicators: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    analyst_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    confirmed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    last_assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "level IN ('signal','anomaly','actionable_intelligence','confirmed_threat')", name="assessment_level_valid"
        ),
        CheckConstraint("uncertainty IN ('low','moderate','high','very_high')", name="assessment_uncertainty_valid"),
        CheckConstraint("level <> 'confirmed_threat' OR confirmed_by IS NOT NULL", name="confirmed_requires_validator"),
    )


class OsintItem(UUIDPk, Timestamps, Base):
    __tablename__ = "osint_items"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(300), nullable=False)
    url: Mapped[str | None] = mapped_column(String(2000))
    normalized_url: Mapped[str | None] = mapped_column(String(2000), index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    author: Mapped[str | None] = mapped_column(String(300))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    publication_context: Mapped[str] = mapped_column(Text, default="", nullable=False)
    content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    content_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    verified_points: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    unverified_points: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    reliability: Mapped[str] = mapped_column(String(1), default="F", nullable=False)
    previous_version_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("osint_items.id", ondelete="SET NULL"))
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    __table_args__ = (CheckConstraint(f"reliability IN {RELIABILITY}", name="osint_reliability_valid"),)


class ReferenceSite(UUIDPk, Timestamps, Base):
    """Critical infrastructure declared in an authorised referential."""

    __tablename__ = "reference_sites"

    name: Mapped[str] = mapped_column(String(300), nullable=False)
    sector: Mapped[str] = mapped_column(String(60), nullable=False)
    latitude: Mapped[float] = mapped_column(Float, nullable=False)
    longitude: Mapped[float] = mapped_column(Float, nullable=False)
    location_precision: Mapped[str] = mapped_column(String(20), default="approximate", nullable=False)
    referential: Mapped[str] = mapped_column(String(200), nullable=False)
    classification_rank: Mapped[int] = mapped_column(
        Integer, ForeignKey("classification_levels.rank", ondelete="RESTRICT"), nullable=False
    )
