"""Open-source information: provenance, duplicate detection and version comparison.

Content is entered by the analyst from public, lawfully accessible resources.
This module deliberately contains no crawler, no account access and no
mechanism to bypass technical protections.
"""

from __future__ import annotations

import difflib
import re
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import sha256_hex
from app.core.errors import bad_request
from app.core.security import utcnow
from app.models import Case, OsintItem
from app.schemas import api as s
from app.services import audit

_TRACKING_PARAMS = re.compile(r"^(utm_|fbclid|gclid|mc_|ref$|ref_src)")
NEAR_DUPLICATE_THRESHOLD = 0.8


def normalize_url(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower().removeprefix("www.")
    query = urlencode(sorted((k, v) for k, v in parse_qsl(parts.query) if not _TRACKING_PARAMS.match(k)))
    path = parts.path.rstrip("/") or "/"
    return urlunsplit(("https", host, path, query, ""))


def _normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    return re.sub(r"\W+", " ", text).strip()


def shingles(text: str, size: int = 4) -> set[str]:
    words = _normalize_text(text).split()
    if len(words) < size:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + size]) for i in range(len(words) - size + 1)}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def find_duplicates(db: Session, case: Case, url: str | None, content: str, exclude_id=None) -> list[dict]:
    """Exact (same URL or same hash) and near duplicates within the same case only."""
    norm = normalize_url(url)
    digest = sha256_hex(content.encode()) if content else None
    items = db.scalars(select(OsintItem).where(OsintItem.case_id == case.id)).all()
    target = shingles(content) if content else set()
    found = []
    for item in items:
        if item.id == exclude_id:
            continue
        if norm and item.normalized_url == norm:
            found.append({"id": item.id, "match": "same_url", "score": 1.0})
        elif digest and item.content_sha256 == digest:
            found.append({"id": item.id, "match": "same_content", "score": 1.0})
        elif target:
            score = jaccard(target, shingles(item.content))
            if score >= NEAR_DUPLICATE_THRESHOLD:
                found.append({"id": item.id, "match": "near_duplicate", "score": round(score, 3)})
    return found


def create_item(db: Session, principal, case: Case, data: s.OsintIn) -> tuple[OsintItem, list[dict]]:
    if data.previous_version_id:
        prev = db.get(OsintItem, data.previous_version_id)
        if prev is None or prev.case_id != case.id:
            raise bad_request("previous_version_not_in_case")
    duplicates = find_duplicates(db, case, data.url, data.content)
    item = OsintItem(
        case_id=case.id, created_by=principal.id, collected_at=utcnow(),
        normalized_url=normalize_url(data.url),
        content_sha256=sha256_hex(data.content.encode()) if data.content else None,
        **data.model_dump(),
    )
    db.add(item)
    db.flush()
    audit.record(db, principal.audit, "osint.create", "case_content", "success", "osint", item.id,
                 {"case_id": str(case.id), "duplicates": len(duplicates)}, commit=False)
    db.commit()
    return item, duplicates


def compare_versions(old: OsintItem, new: OsintItem) -> dict:
    diff = list(difflib.unified_diff(old.content.splitlines(), new.content.splitlines(),
                                     fromfile=str(old.id), tofile=str(new.id), lineterm="", n=1))
    ratio = difflib.SequenceMatcher(None, old.content, new.content).ratio()
    return {
        "similarity": round(ratio, 3),
        "hash_changed": old.content_sha256 != new.content_sha256,
        "title_changed": old.title != new.title,
        "published_at_changed": old.published_at != new.published_at,
        "diff": diff[:500],
    }


def cluster_publications(items: list[OsintItem]) -> list[list]:
    """Group publications that likely describe the same story (shared shingles)."""
    groups: list[list[OsintItem]] = []
    for item in items:
        sh = shingles(item.title + " " + item.content)
        for group in groups:
            if jaccard(sh, shingles(group[0].title + " " + group[0].content)) >= 0.3:
                group.append(item)
                break
        else:
            groups.append([item])
    return [[i.id for i in g] for g in groups if len(g) > 1]
