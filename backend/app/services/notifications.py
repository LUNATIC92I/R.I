"""In-app notifications with generic, non-revealing texts."""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors import push
from app.core.context import ctx
from app.core.security import utcnow
from app.models import Device, Notification

GENERIC_TEXTS = {
    "case_activity": "Nouvelle activité dans votre espace de travail",
    "report_validation": "Un élément attend votre validation",
    "report_decision": "Une décision a été enregistrée",
    "alert": "Un nouvel élément requiert une vérification",
    "security": "Information de sécurité sur votre compte",
    "access_granted": "Vos accès ont été mis à jour",
}


def notify(db: Session, user_ids: Iterable[uuid.UUID], category: str,
           target_type: str | None = None, target_id: uuid.UUID | None = None) -> None:
    text = GENERIC_TEXTS[category]
    for user_id in set(user_ids):
        db.add(Notification(user_id=user_id, generic_text=text, category=category,
                            target_type=target_type, target_id=target_id, created_at=utcnow()))
        devices = db.scalars(select(Device).where(Device.user_id == user_id, Device.status == "active",
                                                  Device.push_token_enc.is_not(None))).all()
        for device in devices:
            push.gateway.send(ctx().cipher.decrypt_field(device.push_token_enc), text)
