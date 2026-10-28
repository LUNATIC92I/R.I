"""Request/response schemas. Every input model forbids unknown fields and bounds string sizes."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.intel import (
    CASE_CATEGORIES,
    CASE_PRIORITIES,
    LOCATION_PRECISION,
    STATEMENT_KINDS,
)
from app.models.ops import INDICATOR_TYPES, REPORT_TYPES

Short = Annotated[str, Field(min_length=1, max_length=300)]
Text = Annotated[str, Field(max_length=20000)]
Reliability = Literal["A", "B", "C", "D", "E", "F"]
Confidence = Literal["low", "moderate", "high"]


class In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @model_validator(mode="after")
    def _assume_utc(self):
        """Datetimes without offset are interpreted as UTC, never as server local time."""
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, datetime) and value.tzinfo is None:
                object.__setattr__(self, name, value.replace(tzinfo=UTC))
        return self


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Authentication ---------------------------------------------------------

class DeviceIn(In):
    install_id: Annotated[str, Field(min_length=8, max_length=80, pattern=r"^[A-Za-z0-9_\-]+$")]
    platform: Literal["android", "ios", "test"]
    label: Annotated[str, Field(min_length=1, max_length=120)]
    integrity: dict[str, bool | str] | None = None


class LoginIn(In):
    username: Annotated[str, Field(min_length=1, max_length=80)]
    password: Annotated[str, Field(min_length=1, max_length=256)]
    device: DeviceIn


class OidcLoginIn(In):
    id_token: Annotated[str, Field(min_length=10, max_length=8000)]
    nonce: Annotated[str, Field(min_length=8, max_length=200)]
    device: DeviceIn


class LoginStepOut(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    enrollment_required: bool
    totp_provisioning_uri: str | None = None


class MfaIn(In):
    mfa_token: Annotated[str, Field(min_length=10, max_length=200)]
    code: Annotated[str, Field(min_length=6, max_length=6, pattern=r"^\d{6}$")]


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_at: int
    session_id: uuid.UUID


class RefreshIn(In):
    refresh_token: Annotated[str, Field(min_length=10, max_length=300)]


class StepUpIn(In):
    password: Annotated[str, Field(max_length=256)] = ""
    code: Annotated[str, Field(min_length=6, max_length=6, pattern=r"^\d{6}$")]


class RecoveryCompleteIn(In):
    username: Annotated[str, Field(min_length=1, max_length=80)]
    recovery_code: Annotated[str, Field(min_length=10, max_length=200)]
    new_password: Annotated[str, Field(min_length=12, max_length=256)]


# --- Identity ---------------------------------------------------------------

class RoleOut(Out):
    code: str
    name_fr: str
    name_en: str
    case_scope: str


class UserOut(Out):
    id: uuid.UUID
    username: str
    display_name: str
    professional_id: str
    service_id: uuid.UUID
    clearance_rank: int
    is_active: bool
    mfa_enrolled: bool
    preferred_locale: str
    roles: list[RoleOut]


class MeOut(UserOut):
    permissions: list[str] = []


class UserCreateIn(In):
    username: Annotated[str, Field(min_length=3, max_length=80, pattern=r"^[a-z0-9._\-]+$")]
    display_name: Short
    professional_id: Annotated[str, Field(min_length=2, max_length=60)]
    service_id: uuid.UUID
    clearance_rank: Annotated[int, Field(ge=0, le=100)]
    roles: Annotated[list[str], Field(min_length=1, max_length=4)]
    initial_password: Annotated[str, Field(min_length=12, max_length=256)]
    external_subject: Annotated[str, Field(max_length=255)] | None = None


class UserUpdateIn(In):
    display_name: Short | None = None
    clearance_rank: Annotated[int, Field(ge=0, le=100)] | None = None
    roles: Annotated[list[str], Field(min_length=1, max_length=4)] | None = None
    is_active: bool | None = None
    service_id: uuid.UUID | None = None


class SessionOut(Out):
    id: uuid.UUID
    device_id: uuid.UUID | None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None
    ip_address: str | None
    user_agent: str | None


class DeviceOut(Out):
    id: uuid.UUID
    user_id: uuid.UUID
    label: str
    platform: str
    status: str
    created_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None
    revoked_reason: str | None
    wipe_requested: bool
    integrity_report: dict | None


class DeviceRevokeIn(In):
    status: Literal["revoked", "lost", "stolen"]
    reason: Annotated[str, Field(min_length=3, max_length=300)]
    wipe: bool = True


class PushTokenIn(In):
    push_token: Annotated[str, Field(min_length=10, max_length=4096)]


class ServiceOut(Out):
    id: uuid.UUID
    code: str
    name: str
    parent_id: uuid.UUID | None


class ClassificationOut(Out):
    id: uuid.UUID
    code: str
    label_fr: str
    label_en: str
    rank: int
    marking: str
    export_requires_step_up: bool


class ClassificationIn(In):
    code: Annotated[str, Field(min_length=1, max_length=40, pattern=r"^[A-Z0-9_]+$")]
    label_fr: Short
    label_en: Short
    rank: Annotated[int, Field(ge=0, le=100)]
    marking: Short
    export_requires_step_up: bool = True


class RetentionOut(Out):
    id: uuid.UUID
    code: str
    description: str
    retention_days: int
    legal_basis: str
    action_on_expiry: str


class RetentionIn(In):
    code: Annotated[str, Field(min_length=1, max_length=60, pattern=r"^[A-Z0-9_]+$")]
    description: Short
    retention_days: Annotated[int, Field(gt=0, le=36500)]
    legal_basis: Short
    action_on_expiry: Literal["review", "archive", "delete"] = "review"


class RecoveryRequestIn(In):
    user_id: uuid.UUID
    identity_check_reference: Annotated[str, Field(min_length=3, max_length=200)]


# --- Cases ------------------------------------------------------------------

class CaseCreateIn(In):
    title: Short
    category: str
    country_code: Annotated[str, Field(min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")]
    jurisdiction: Short
    classification_rank: Annotated[int, Field(ge=0, le=100)]
    priority: str = "medium"
    executive_summary: Text = ""
    analysis_context: Text = ""
    legal_basis: Annotated[str, Field(min_length=3, max_length=500)]
    authorised_follow_up: Text = ""
    review_date: date
    retention_rule_code: Annotated[str, Field(min_length=1, max_length=60)]
    service_id: uuid.UUID | None = None

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in CASE_CATEGORIES:
            raise ValueError("unknown category")
        return v

    @field_validator("priority")
    @classmethod
    def _priority(cls, v: str) -> str:
        if v not in CASE_PRIORITIES:
            raise ValueError("unknown priority")
        return v


class CaseUpdateIn(In):
    version: int
    title: Short | None = None
    priority: str | None = None
    executive_summary: Text | None = None
    analysis_context: Text | None = None
    confidence_assessment: Confidence | None = None
    authorised_follow_up: Text | None = None
    review_date: date | None = None
    classification_rank: Annotated[int, Field(ge=0, le=100)] | None = None

    @field_validator("priority")
    @classmethod
    def _priority(cls, v: str | None) -> str | None:
        if v is not None and v not in CASE_PRIORITIES:
            raise ValueError("unknown priority")
        return v


class CaseSummaryOut(Out):
    id: uuid.UUID
    reference: str
    title: str
    category: str
    country_code: str
    priority: str
    status: str
    classification_rank: int
    service_id: uuid.UUID
    owner_id: uuid.UUID
    review_date: date
    created_at: datetime
    updated_at: datetime


class CaseOut(CaseSummaryOut):
    jurisdiction: str
    executive_summary: str
    analysis_context: str
    confidence_assessment: str
    legal_basis: str
    authorised_follow_up: str
    retention_rule_id: uuid.UUID
    offline_allowed: bool
    closed_at: datetime | None
    archived_at: datetime | None
    version: int


class CaseStatusIn(In):
    action: Literal["close", "reopen", "archive", "request_deletion", "approve_deletion", "submit_review"]
    justification: Annotated[str, Field(min_length=3, max_length=500)]


class MemberIn(In):
    user_id: uuid.UUID
    access: Literal["read", "write"] = "read"
    justification: Annotated[str, Field(min_length=3, max_length=300)]
    expires_at: datetime | None = None


class MemberOut(Out):
    id: uuid.UUID
    user_id: uuid.UUID
    access: str
    justification: str
    granted_by: uuid.UUID
    granted_at: datetime
    expires_at: datetime | None


class CaseLinkIn(In):
    to_case_id: uuid.UUID
    rationale: Annotated[str, Field(min_length=3, max_length=500)]


class SourceIn(In):
    kind: Literal["open_source", "institutional_system", "official_report", "human_protected", "technical", "other"]
    title: Short
    reliability: Reliability = "F"
    url: Annotated[str, Field(max_length=2000)] | None = None
    author: Short | None = None
    published_at: datetime | None = None
    collected_at: datetime | None = None
    protected_reference: Annotated[str, Field(max_length=80)] | None = None
    legal_basis: Short

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v and not v.lower().startswith(("http://", "https://")):
            raise ValueError("url must be http(s)")
        return v


class SourceOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    kind: str
    title: str
    reliability: str
    url: str | None
    author: str | None
    published_at: datetime | None
    collected_at: datetime
    protected_reference: str | None
    legal_basis: str
    created_at: datetime


class StatementIn(In):
    kind: str
    text: Annotated[str, Field(min_length=1, max_length=5000)]
    credibility: Annotated[int, Field(ge=1, le=6)] = 6
    source_id: uuid.UUID | None = None
    contradicts_id: uuid.UUID | None = None

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in STATEMENT_KINDS or v == "confirmed_fact":
            raise ValueError("kind must be a non-confirmed kind; use the verify endpoint to confirm a fact")
        return v


class StatementVerifyIn(In):
    version: int
    source_id: uuid.UUID
    credibility: Annotated[int, Field(ge=1, le=6)]


class StatementOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    kind: str
    text: str
    credibility: int
    source_id: uuid.UUID | None
    contradicts_id: uuid.UUID | None
    verified_by: uuid.UUID | None
    verified_at: datetime | None
    created_by: uuid.UUID
    created_at: datetime
    version: int


class EventIn(In):
    title: Short
    description: Text = ""
    category: Annotated[str, Field(max_length=60)] = "other"
    occurred_at: datetime | None = None
    occurred_until: datetime | None = None
    date_precision: Literal["exact", "day", "month", "year", "unknown"] = "exact"
    location_label: Short | None = None
    latitude: Annotated[float, Field(ge=-90, le=90)] | None = None
    longitude: Annotated[float, Field(ge=-180, le=180)] | None = None
    location_precision: str = "unknown"
    location_accuracy_m: Annotated[float, Field(ge=0)] | None = None
    location_provenance: Short | None = None
    source_id: uuid.UUID | None = None
    document_id: uuid.UUID | None = None

    @field_validator("location_precision")
    @classmethod
    def _precision(cls, v: str) -> str:
        if v not in LOCATION_PRECISION:
            raise ValueError("invalid location precision")
        return v


class EventOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    title: str
    description: str
    category: str
    occurred_at: datetime | None
    occurred_until: datetime | None
    date_precision: str
    location_label: str | None
    latitude: float | None
    longitude: float | None
    location_precision: str
    location_accuracy_m: float | None
    location_provenance: str | None
    source_id: uuid.UUID | None
    document_id: uuid.UUID | None
    created_at: datetime


class EntityIn(In):
    kind: Literal["organisation", "place", "event", "document", "infrastructure", "person", "other"]
    label: Short
    notes: Text = ""


class EntityOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    kind: str
    label: str
    notes: str


class RelationIn(In):
    from_entity_id: uuid.UUID
    to_entity_id: uuid.UUID
    relation_type: Annotated[str, Field(min_length=1, max_length=80)]
    basis: Annotated[str, Field(min_length=3, max_length=500)]
    source_id: uuid.UUID | None = None
    confidence: Confidence = "low"
    is_causal_claim: bool = False


class RelationOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    from_entity_id: uuid.UUID
    to_entity_id: uuid.UUID
    relation_type: str
    basis: str
    source_id: uuid.UUID | None
    confidence: str
    is_causal_claim: bool


class DocumentOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    title: str
    classification_rank: int
    source_id: uuid.UUID | None
    current_version: int
    download_allowed: bool
    created_at: datetime


class DocumentVersionOut(Out):
    version: int
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    uploaded_by: uuid.UUID
    uploaded_at: datetime


class AssessmentIn(In):
    threat: Short
    category: str
    level: Literal["signal", "anomaly", "actionable_intelligence"] = "signal"
    observed_facts: Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=100)] = []
    source_ids: Annotated[list[uuid.UUID], Field(max_length=100)] = []
    source_reliability: Reliability = "F"
    information_credibility: Annotated[int, Field(ge=1, le=6)] = 6
    alternative_hypotheses: Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=50)] = []
    contradicting_elements: Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=50)] = []
    possible_consequences: Text = ""
    uncertainty: Literal["low", "moderate", "high", "very_high"] = "high"
    recommended_verifications: Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=50)] = []
    indicators: Annotated[list[Annotated[str, Field(max_length=500)]], Field(max_length=100)] = []

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        if v not in CASE_CATEGORIES:
            raise ValueError("unknown category")
        return v


class AssessmentOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    threat: str
    category: str
    level: str
    observed_facts: list
    source_ids: list
    source_reliability: str
    information_credibility: int
    alternative_hypotheses: list
    contradicting_elements: list
    possible_consequences: str
    uncertainty: str
    recommended_verifications: list
    indicators: list
    analyst_id: uuid.UUID
    analyst_professional_id: str | None = None
    confirmed_by: uuid.UUID | None
    last_assessed_at: datetime
    disclaimer: str = (
        "Évaluation analytique à usage interne. Elle ne constitue ni une preuve ni une décision. "
        "Analytical assessment for internal use; not evidence and not a decision."
    )


class AssessmentConfirmIn(In):
    justification: Annotated[str, Field(min_length=10, max_length=2000)]


# --- OSINT ------------------------------------------------------------------

class OsintIn(In):
    source_name: Short
    url: Annotated[str, Field(max_length=2000)] | None = None
    title: Annotated[str, Field(min_length=1, max_length=500)]
    author: Short | None = None
    published_at: datetime | None = None
    event_date: datetime | None = None
    publication_context: Text = ""
    content: Annotated[str, Field(max_length=200000)] = ""
    verified_points: Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=100)] = []
    unverified_points: Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=100)] = []
    reliability: Reliability = "F"
    previous_version_id: uuid.UUID | None = None

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v and not v.lower().startswith(("http://", "https://")):
            raise ValueError("url must be http(s)")
        return v


class OsintOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    source_name: str
    url: str | None
    title: str
    author: str | None
    published_at: datetime | None
    collected_at: datetime
    event_date: datetime | None
    publication_context: str
    content_sha256: str | None
    verified_points: list
    unverified_points: list
    reliability: str
    previous_version_id: uuid.UUID | None
    created_at: datetime


# --- Cyber ------------------------------------------------------------------

class IndicatorIn(In):
    type: str
    value: Annotated[str, Field(min_length=1, max_length=2000)]
    provenance: Short
    context: Text = ""
    first_seen: datetime
    last_seen: datetime | None = None
    valid_until: datetime | None = None
    tlp: Literal["clear", "green", "amber", "amber+strict", "red"] = "amber"
    independent_source_count: Annotated[int, Field(ge=1, le=100)] = 1
    campaign: Short | None = None

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        if v not in INDICATOR_TYPES:
            raise ValueError("unknown indicator type")
        return v


class IndicatorVerdictIn(In):
    verdict: Literal["suspicious", "malicious_confirmed", "benign", "false_positive", "unassessed"]
    justification: Annotated[str, Field(min_length=10, max_length=2000)]


class IndicatorOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID
    type: str
    value: str
    provenance: str
    context: str
    first_seen: datetime
    last_seen: datetime
    valid_until: datetime | None
    tlp: str
    verdict: str
    verdict_justification: str | None
    independent_source_count: int
    campaign: str | None
    enrichment: dict
    freshness: str | None = None


class StixImportIn(In):
    bundle: dict
    provenance: Short


class SiemEventIn(In):
    external_id: Annotated[str, Field(min_length=1, max_length=200)]
    observed_at: datetime
    sensor: Short
    observable_type: str
    observable_value: Annotated[str, Field(min_length=1, max_length=2000)]
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    raw: dict = {}

    @field_validator("observable_type")
    @classmethod
    def _type(cls, v: str) -> str:
        if v not in INDICATOR_TYPES:
            raise ValueError("unknown observable type")
        return v


class SiemBatchIn(In):
    events: Annotated[list[SiemEventIn], Field(min_length=1, max_length=500)]


class ServiceAccountIn(In):
    name: Annotated[str, Field(min_length=3, max_length=120)]
    scopes: list[Literal["siem:ingest"]]
    service_id: uuid.UUID


# --- Reports ----------------------------------------------------------------

class ReportIn(In):
    report_type: str
    title: Short
    classification_rank: Annotated[int, Field(ge=0, le=100)] | None = None
    dissemination: Short = "Diffusion restreinte / Restricted distribution"
    summary: Text = ""
    analysis: Text = ""
    uncertainties: Text = ""
    recommendations: Text = ""
    source_ids: Annotated[list[uuid.UUID], Field(max_length=200)] = []
    statement_ids: Annotated[list[uuid.UUID], Field(max_length=500)] = []
    prefill_from_case: bool = True

    @field_validator("report_type")
    @classmethod
    def _type(cls, v: str) -> str:
        if v not in REPORT_TYPES:
            raise ValueError("unknown report type")
        return v


class ReportUpdateIn(In):
    version: int
    title: Short | None = None
    summary: Text | None = None
    analysis: Text | None = None
    uncertainties: Text | None = None
    recommendations: Text | None = None
    dissemination: Short | None = None
    source_ids: Annotated[list[uuid.UUID], Field(max_length=200)] | None = None
    statement_ids: Annotated[list[uuid.UUID], Field(max_length=500)] | None = None


class ReportDecisionIn(In):
    decision: Literal["approved", "rejected"]
    comment: Annotated[str, Field(max_length=2000)] = ""


class ReportOut(Out):
    id: uuid.UUID
    reference: str
    case_id: uuid.UUID
    report_type: str
    title: str
    classification_rank: int
    dissemination: str
    summary: str
    analysis: str
    uncertainties: str
    recommendations: str
    source_ids: list
    statement_ids: list
    status: str
    author_id: uuid.UUID
    content_sha256: str | None
    created_at: datetime
    updated_at: datetime
    version: int


# --- Alerts, notifications --------------------------------------------------

class AlertOut(Out):
    id: uuid.UUID
    case_id: uuid.UUID | None
    kind: str
    title: str
    detail: str
    origin: str
    severity: str
    status: str
    created_at: datetime
    reviewed_by: uuid.UUID | None
    review_note: str | None
    evidence: dict
    notice: str = (
        "Une alerte est un signal à vérifier, jamais une preuve. "
        "An alert is a signal to verify, never proof."
    )


class AlertReviewIn(In):
    status: Literal["under_review", "dismissed", "escalated"]
    note: Annotated[str, Field(min_length=3, max_length=2000)]


class NotificationOut(Out):
    id: uuid.UUID
    generic_text: str
    category: str
    target_type: str | None
    target_id: uuid.UUID | None
    created_at: datetime
    read_at: datetime | None


# --- Assistant --------------------------------------------------------------

class AssistantIn(In):
    task: Literal["summarize", "extract_dates", "contradictions", "verification_questions", "draft_report", "gaps"]
    document_id: uuid.UUID | None = None
    text: Annotated[str, Field(max_length=50000)] | None = None


# --- Offline sync -----------------------------------------------------------

class SyncOpIn(In):
    client_op_id: Annotated[str, Field(min_length=8, max_length=80)]
    op_type: Literal["add_statement", "add_event", "update_case_summary"]
    case_id: uuid.UUID
    base_version: int | None = None
    payload: dict
    queued_at: datetime


class SyncPushIn(In):
    operations: Annotated[list[SyncOpIn], Field(min_length=1, max_length=200)]


class SiteIn(In):
    name: Short
    sector: Annotated[str, Field(min_length=1, max_length=60)]
    latitude: Annotated[float, Field(ge=-90, le=90)]
    longitude: Annotated[float, Field(ge=-180, le=180)]
    location_precision: Literal["exact", "approximate", "region"] = "approximate"
    referential: Short
    classification_rank: Annotated[int, Field(ge=0, le=100)] = 0
