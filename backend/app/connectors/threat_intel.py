"""Threat-intelligence enrichment connectors.

API keys are read from server-side configuration only and never returned to
clients. The MISP connector targets the standard ``/attributes/restSearch``
endpoint; it is implemented but untested against a live instance here.
"""

from __future__ import annotations

from typing import Protocol

import httpx

from app.core.config import Settings


class EnrichmentProvider(Protocol):
    name: str

    def lookup(self, ioc_type: str, value: str) -> dict: ...


class DisabledProvider:
    name = "disabled"

    def lookup(self, ioc_type: str, value: str) -> dict:
        return {"provider": self.name, "status": "not_configured"}


class MispProvider:
    name = "misp"

    def __init__(self, url: str, api_key: str, timeout: float = 10.0):
        if not url.startswith("https://"):
            raise ValueError("MISP URL must use HTTPS")
        self._url = url.rstrip("/")
        self._headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
        self._timeout = timeout

    def lookup(self, ioc_type: str, value: str) -> dict:
        try:
            resp = httpx.post(f"{self._url}/attributes/restSearch", headers=self._headers,
                              json={"value": value, "limit": 20}, timeout=self._timeout)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return {"provider": self.name, "status": "error", "error": type(exc).__name__}
        attrs = resp.json().get("response", {}).get("Attribute", [])
        return {
            "provider": self.name,
            "status": "ok",
            "matches": len(attrs),
            "events": sorted({str(a.get("event_id")) for a in attrs})[:20],
            "note": "Enrichissement externe : à recouper, ne vaut pas verdict.",
        }


def provider_from_settings(settings: Settings) -> EnrichmentProvider:
    if settings.misp_url and settings.misp_api_key:
        return MispProvider(settings.misp_url, settings.misp_api_key)
    return DisabledProvider()
