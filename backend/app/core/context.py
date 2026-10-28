"""Process-wide objects built at start-up from the validated settings."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings
from app.core.crypto import Cipher, LocalKeyProvider


@dataclass
class AppContext:
    settings: Settings
    cipher: Cipher


_ctx: AppContext | None = None


def build_context(settings: Settings) -> AppContext:
    global _ctx
    provider = LocalKeyProvider(settings.master_key)
    _ctx = AppContext(settings=settings, cipher=Cipher(provider, settings.master_key))
    return _ctx


def ctx() -> AppContext:
    if _ctx is None:
        raise RuntimeError("Application context not initialised")
    return _ctx
