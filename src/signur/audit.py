import uuid
from typing import Any

from sqlalchemy.orm import Session

from signur.models import AuditEvent, User


def record_event(
    session: Session,
    *,
    actor: User | None,
    action: str,
    entity_type: str,
    entity_id: uuid.UUID | str,
    request_id: str,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        actor_user_id=actor.id if actor else None,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        request_id=request_id,
        details=details or {},
    )
    session.add(event)
    return event
