"""Analytical assistant.

The default engine is local and deterministic: extractive summaries, date
extraction, contradiction listing, verification questions and draft outlines.
Every output item cites the identifier of the authorised material it comes
from, and nothing is invented: when material is missing, the assistant says so.

An optional institutional language model can be plugged in through
:class:`InstitutionalLlm`. It is refused for any material classified above
``AIC_LLM_MAX_CLASSIFICATION_RANK`` and is never called with data from a
case the user cannot read.
"""

from __future__ import annotations

import re
from collections import Counter

import httpx

from app.core.config import Settings
from app.core.errors import ApiError
from app.models import Case
from app.services import correlation

LIMITS_NOTICE = (
    "Aide analytique automatisée : résultats indicatifs, à vérifier par l'analyste. "
    "Aucune conclusion produite ici ne justifie une mesure coercitive. "
    "Automated analytical aid: indicative output to be checked by the analyst."
)

_MONTHS_FR = "janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre"
_MONTHS_EN = "january|february|march|april|may|june|july|august|september|october|november|december"
_DATE_PATTERNS = [
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"), "iso"),
    (re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b"), "dmy_slash"),
    (re.compile(rf"\b(\d{{1,2}})(?:er)?\s+({_MONTHS_FR})\s+(\d{{4}})\b", re.I), "fr_text"),
    (re.compile(rf"\b({_MONTHS_EN})\s+(\d{{1,2}}),?\s+(\d{{4}})\b", re.I), "en_text"),
]
_STOPWORDS = set(
    "le la les de des du un une et en à au aux pour par sur dans est sont a été que qui ne pas plus "
    "the of and to in is was for on with that by as at be are this from it an or".split()
)


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p.strip() for p in parts if len(p.strip()) > 20]


def summarize(text: str, max_sentences: int = 5) -> list[dict]:
    sentences = split_sentences(text)
    if not sentences:
        return []
    words = [w for w in re.findall(r"\w+", text.lower()) if w not in _STOPWORDS and len(w) > 2]
    freq = Counter(words)
    scored = []
    for idx, sentence in enumerate(sentences):
        tokens = [w for w in re.findall(r"\w+", sentence.lower()) if w in freq]
        score = sum(freq[w] for w in tokens) / (len(tokens) + 1)
        scored.append((score, idx, sentence))
    top = sorted(sorted(scored, reverse=True)[:max_sentences], key=lambda t: t[1])
    return [{"sentence_index": idx, "text": sentence} for _, idx, sentence in top]


def extract_dates(text: str) -> list[dict]:
    found = []
    for pattern, kind in _DATE_PATTERNS:
        for m in pattern.finditer(text):
            start = max(0, m.start() - 80)
            found.append({"match": m.group(0), "format": kind, "offset": m.start(),
                          "context": text[start:m.end() + 80].replace("\n", " ")})
    return sorted(found, key=lambda d: d["offset"])


def verification_questions(statements, assessments) -> list[dict]:
    questions = []
    for st in statements:
        if st.kind == "unverified_information":
            questions.append({"about": str(st.id), "question":
                              "Quelle source indépendante permettrait de confirmer ou d'infirmer cet élément ?"})
        if st.kind == "claim":
            questions.append({"about": str(st.id), "question":
                              "Qui est l'auteur de cette déclaration, quel est son accès à l'information et son intérêt ?"})
        if st.kind == "working_hypothesis":
            questions.append({"about": str(st.id), "question":
                              "Quels faits observables infirmeraient cette hypothèse ? Ont-ils été recherchés ?"})
        if st.source_id is None and st.kind != "working_hypothesis":
            questions.append({"about": str(st.id), "question": "D'où provient cet élément ? Aucune source n'est rattachée."})
    for a in assessments:
        if not a.alternative_hypotheses:
            questions.append({"about": str(a.id), "question":
                              "Quelles explications alternatives (y compris non malveillantes) ont été considérées ?"})
    return questions


def draft_outline(case: Case, statements, sources) -> dict:
    by_kind: dict[str, list] = {}
    for st in statements:
        by_kind.setdefault(st.kind, []).append({"id": str(st.id), "text": st.text,
                                                 "source_id": str(st.source_id) if st.source_id else None})
    missing = []
    if not by_kind.get("confirmed_fact"):
        missing.append("Aucun fait confirmé : le projet ne peut présenter que des éléments à vérifier.")
    if not sources:
        missing.append("Aucune source enregistrée.")
    return {
        "title": f"Projet de note : {case.title}",
        "facts": by_kind.get("confirmed_fact", []),
        "unverified": by_kind.get("unverified_information", []) + by_kind.get("claim", []),
        "hypotheses": by_kind.get("working_hypothesis", []) + by_kind.get("alternative_hypothesis", []),
        "sources": [{"id": str(src.id), "title": src.title, "reliability": src.reliability} for src in sources],
        "missing": missing,
        "status": "draft_for_human_review",
    }


def run(db, case: Case, task: str, statements, sources, assessments, text: str | None, text_ref: str | None) -> dict:
    result: dict = {"task": task, "case_id": str(case.id), "notice": LIMITS_NOTICE, "engine": "local"}
    if task in {"summarize", "extract_dates"}:
        if not text:
            result["items"] = []
            result["missing"] = ["Aucun texte autorisé fourni."]
            return result
        items = summarize(text) if task == "summarize" else extract_dates(text)
        for item in items:
            item["source_ref"] = text_ref
        result["items"] = items
    elif task == "contradictions":
        result["items"] = correlation.contradictions(db, {case.id})
    elif task == "gaps":
        result["items"] = correlation.gaps(db, case.id)
    elif task == "verification_questions":
        result["items"] = verification_questions(statements, assessments)
    elif task == "draft_report":
        result["draft"] = draft_outline(case, statements, sources)
    return result


class InstitutionalLlm:
    """Connector to a model hosted in the institution's own infrastructure."""

    def __init__(self, settings: Settings):
        if not settings.llm_endpoint:
            raise ApiError(503, "llm_not_configured")
        self.endpoint = settings.llm_endpoint
        self.max_rank = settings.llm_max_classification_rank

    def summarize(self, text: str, classification_rank: int) -> str:
        if classification_rank > self.max_rank:
            raise ApiError(403, "classification_not_allowed_for_llm")
        resp = httpx.post(self.endpoint, json={"task": "summarize", "text": text}, timeout=30)
        resp.raise_for_status()
        return str(resp.json().get("summary", ""))
