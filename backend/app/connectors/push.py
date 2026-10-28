"""Push notification connector.

Only the generic text of a notification ever leaves the backend; push
payloads never contain case titles, names, coordinates or identifiers.
FCM/APNs delivery requires institutional credentials kept server side and is
not implemented here: :class:`LoggingPushGateway` records that a push would
have been sent. Implement :class:`PushGateway` for the real provider.
"""

from __future__ import annotations

import logging
from typing import Protocol

log = logging.getLogger("aic.push")


class PushGateway(Protocol):
    def send(self, device_token: str, generic_text: str) -> None: ...


class LoggingPushGateway:
    sent: list[str]

    def __init__(self) -> None:
        self.sent = []

    def send(self, device_token: str, generic_text: str) -> None:
        self.sent.append(generic_text)
        log.info("push queued (provider not configured)")


gateway: PushGateway = LoggingPushGateway()
