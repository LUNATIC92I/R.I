"""Indicators of compromise: validation, freshness, verdict rules, STIX import, SIEM correlation."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.threat_intel import provider_from_settings
from app.core.context import ctx
from app.core.errors import bad_request, conflict
from app.core.security import ensure_aware, utcnow
from app.models import Alert, Case, Indicator, SecurityEvent, ServiceAccount
from app.schemas import api as s
from app.services import audit

STALE_AFTER = timedelta(days=90)
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")


def normalize(ioc_type: str, value: str) -> str:
    v = value.strip()
    if ioc_type == "ipv4":
        ip = ipaddress.ip_address(v)
        if ip.version != 4:
            raise ValueError("not ipv4")
        return str(ip)
    if ioc_type == "ipv6":
        ip = ipaddress.ip_address(v)
        if ip.version != 6:
            raise ValueError("not ipv6")
        return str(ip)
    if ioc_type == "domain":
        v = v.lower().rstrip(".").replace("[.]", ".")
        if not _DOMAIN.match(v):
            raise ValueError("invalid domain")
        return v
    if ioc_type == "url":
        v = v.replace("hxxp", "http").replace("[.]", ".")
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("invalid url")
        return v
    if ioc_type in _HEX:
        v = v.lower()
        if len(v) != _HEX[ioc_type] or not re.fullmatch(r"[0-9a-f]+", v):
            raise ValueError(f"invalid {ioc_type}")
        return v
    if ioc_type == "email":
        if not _EMAIL.match(v):
            raise ValueError("invalid email")
        return v.lower()
    raise ValueError("unknown type")


def value_hash(ioc_type: str, normalized: str) -> str:
    return hashlib.sha256(f"{ioc_type}:{normalized}".encode()).hexdigest()


def freshness(ind: Indicator, now: datetime | None = None) -> str:
    now = now or utcnow()
    valid_until = ensure_aware(ind.valid_until)
    if valid_until and valid_until <= now:
        return "expired"
    if ensure_aware(ind.last_seen) < now - STALE_AFTER:
        return "stale"
    return "active"


def ip_context(ioc_type: str, value: str) -> dict:
    """Factual network context. An IP address never designates a person or a precise location."""
    if ioc_type not in {"ipv4", "ipv6"}:
        return {}
    ip = ipaddress.ip_address(value)
    return {
        "is_private": ip.is_private,
        "is_reserved": ip.is_reserved,
        "is_global": ip.is_global,
        "location_note": "Une adresse IP ne permet pas de localiser précisément une personne ; "
                         "elle peut être partagée, dynamique, relayée (VPN, NAT, proxy).",
    }


def create_indicator(db: Session, principal, case: Case, data: s.IndicatorIn) -> Indicator:
    try:
        value = normalize(data.type, data.value)
    except ValueError as exc:
        raise bad_request("invalid_indicator", str(exc)) from None
    last_seen = data.last_seen or data.first_seen
    if last_seen < data.first_seen:
        raise bad_request("last_seen_before_first_seen")
    vh = value_hash(data.type, value)
    if db.scalar(select(Indicator.id).where(Indicator.case_id == case.id, Indicator.value_hash == vh)):
        raise conflict("indicator_exists")
    ind = Indicator(
        case_id=case.id, type=data.type, value=value, value_hash=vh, provenance=data.provenance,
        context=data.context, first_seen=data.first_seen, last_seen=last_seen, valid_until=data.valid_until,
        tlp=data.tlp, independent_source_count=data.independent_source_count, campaign=data.campaign,
        enrichment={"network": ip_context(data.type, value)}, created_by=principal.id,
    )
    db.add(ind)
    db.flush()
    audit.record(db, principal.audit, "indicator.create", "cyber", "success", "indicator", ind.id,
                 {"case_id": str(case.id), "type": data.type}, commit=False)
    db.commit()
    return ind


def set_verdict(db: Session, principal, ind: Indicator, verdict: str, justification: str) -> Indicator:
    if verdict == "malicious_confirmed":
        corroborated = ind.independent_source_count >= 2 or db.scalar(
            select(SecurityEvent.id).where(SecurityEvent.observable_hash == ind.value_hash).limit(1)
        )
        if not corroborated:
            raise bad_request("isolated_signal",
                              "A malicious verdict requires at least two independent sources or an observed event")
        if freshness(ind) != "active":
            raise bad_request("stale_indicator",
                              "Old reputation alone cannot justify a malicious verdict; refresh the observation first")
    ind.verdict = verdict
    ind.verdict_justification = justification
    ind.verdict_by = principal.id
    audit.record(db, principal.audit, "indicator.verdict", "cyber", "success", "indicator", ind.id,
                 {"verdict": verdict}, commit=False)
    db.commit()
    return ind


def enrich(db: Session, principal, ind: Indicator) -> Indicator:
    result = provider_from_settings(ctx().settings).lookup(ind.type, ind.value)
    ind.enrichment = {**ind.enrichment, result["provider"]: {**result, "at": utcnow().isoformat()}}
    audit.record(db, principal.audit, "indicator.enrich", "cyber", "success", "indicator", ind.id,
                 {"provider": result["provider"], "status": result["status"]}, commit=False)
    db.commit()
    return ind


_STIX_PATTERN = re.compile(
    r"\[(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file):(value|hashes\.'?(SHA-256|SHA-1|MD5)'?)\s*=\s*'([^']+)'\]"
)
_STIX_TYPES = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain", "url": "url", "email-addr": "email"}
_STIX_HASH = {"SHA-256": "sha256", "SHA-1": "sha1", "MD5": "md5"}


def import_stix(db: Session, principal, case: Case, bundle: dict, provenance: str) -> dict:
    """Import simple STIX 2.1 indicator patterns. Complex patterns are reported, not guessed."""
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise bad_request("invalid_stix_bundle")
    created, skipped = 0, []
    for obj in bundle["objects"][:2000]:
        if obj.get("type") != "indicator" or obj.get("pattern_type", "stix") != "stix":
            continue
        match = _STIX_PATTERN.fullmatch(str(obj.get("pattern", "")).strip())
        if not match:
            skipped.append({"id": obj.get("id"), "reason": "unsupported_pattern"})
            continue
        obj_type, _, hash_name, raw = match.groups()
        ioc_type = _STIX_HASH.get(hash_name or "", "") if obj_type == "file" else _STIX_TYPES[obj_type]
        try:
            value = normalize(ioc_type, raw)
        except ValueError:
            skipped.append({"id": obj.get("id"), "reason": "invalid_value"})
            continue
        vh = value_hash(ioc_type, value)
        if db.scalar(select(Indicator.id).where(Indicator.case_id == case.id, Indicator.value_hash == vh)):
            skipped.append({"id": obj.get("id"), "reason": "duplicate"})
            continue
        first = _parse_ts(obj.get("valid_from") or obj.get("created")) or utcnow()
        db.add(Indicator(
            case_id=case.id, type=ioc_type, value=value, value_hash=vh, provenance=provenance[:300],
            context=str(obj.get("description", ""))[:5000], first_seen=first,
            last_seen=_parse_ts(obj.get("modified")) or first, valid_until=_parse_ts(obj.get("valid_until")),
            enrichment={"stix_id": obj.get("id"), "network": ip_context(ioc_type, value)}, created_by=principal.id,
        ))
        created += 1
    audit.record(db, principal.audit, "indicator.import_stix", "cyber", "success", "case", case.id,
                 {"created": created, "skipped": len(skipped)}, commit=False)
    db.commit()
    return {"created": created, "skipped": skipped[:100]}


def _parse_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def ingest_siem(db: Session, account: ServiceAccount, events: list[s.SiemEventIn], actx) -> dict:
    """Store SIEM events and raise alerts when an observable matches a case indicator.

    Each alert is attached to the matching case, so it is only visible to people
    with need-to-know on that case. The SIEM learns nothing about the match.
    """
    stored, matched = 0, 0
    for ev in events:
        try:
            value = normalize(ev.observable_type, ev.observable_value)
        except ValueError:
            continue
        if db.scalar(select(SecurityEvent.id).where(SecurityEvent.service_account_id == account.id,
                                                    SecurityEvent.external_id == ev.external_id)):
            continue
        vh = value_hash(ev.observable_type, value)
        db.add(SecurityEvent(
            service_account_id=account.id, external_id=ev.external_id, observed_at=ev.observed_at,
            received_at=utcnow(), sensor=ev.sensor, observable_type=ev.observable_type, observable_hash=vh,
            observable_value=value, severity=ev.severity, raw=ev.raw,
        ))
        stored += 1
        for ind in db.scalars(select(Indicator).where(Indicator.value_hash == vh)).all():
            case = db.get(Case, ind.case_id)
            ind.last_seen = max(ensure_aware(ind.last_seen), ev.observed_at)
            matched += 1
            db.add(Alert(
                case_id=case.id, service_id=case.service_id, kind="ioc_match", origin="automated",
                severity="medium" if ev.severity in {"high", "critical"} else "low",
                classification_rank=case.classification_rank,
                title="Correspondance d'indicateur technique à vérifier",
                detail="Un événement de sécurité institutionnel correspond à un indicateur du dossier. "
                       "Signal technique : vérification humaine requise.",
                evidence={"indicator_id": str(ind.id), "sensor": ev.sensor, "observed_at": ev.observed_at.isoformat()},
            ))
    audit.record(db, actx, "siem.ingest", "integration", "success", "service_account", account.id,
                 {"received": len(events), "stored": stored, "matched": matched}, commit=False)
    db.commit()
    return {"received": len(events), "stored": stored}
