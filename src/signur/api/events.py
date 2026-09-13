import asyncio
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from signur.auth import DbSession, connection_still_authenticated, resolve_connection_user
from signur.config import Settings, get_settings
from signur.errors import ApiError
from signur.models import Document, SignatureJob, UserRole
from signur.origins import origin_is_trusted

router = APIRouter(tags=["events"])


def _access_revoked(role: UserRole) -> bool:
    return role is UserRole.NO_ACCESS


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _snapshot(session: DbSession, user_id: uuid.UUID, role: UserRole) -> dict[str, object]:
    document_filter = [] if role is UserRole.ADMIN else [Document.owner_user_id == user_id]
    documents = session.execute(
        select(Document.id, Document.state, Document.version, Document.completed_at)
        .where(*document_filter)
        .order_by(Document.id)
    ).all()
    jobs = session.execute(
        select(
            SignatureJob.id,
            SignatureJob.document_id,
            SignatureJob.status,
            SignatureJob.error_code,
            SignatureJob.error_message,
            SignatureJob.started_at,
            SignatureJob.completed_at,
        )
        .join(SignatureJob.document)
        .where(*document_filter)
        .order_by(SignatureJob.created_at.desc(), SignatureJob.id)
        .limit(200)
    ).all()
    payload: dict[str, object] = {
        "type": "snapshot",
        "documents": [
            {
                "id": str(item.id),
                "state": item.state.value,
                "version": item.version,
                "completed_at": _iso(item.completed_at),
            }
            for item in documents
        ],
        "jobs": [
            {
                "id": str(item.id),
                "document_id": str(item.document_id),
                "status": item.status.value,
                "error_code": item.error_code,
                "error_message": item.error_message,
                "started_at": _iso(item.started_at),
                "completed_at": _iso(item.completed_at),
            }
            for item in jobs
        ],
    }
    session.rollback()
    return payload


@router.websocket("/events")
async def events(
    websocket: WebSocket,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    client_ip = websocket.client.host if websocket.client else ""
    if settings.trusted_gateway_ips and client_ip not in settings.trusted_gateway_ips:
        await websocket.close(code=4403, reason="Gateway non autorizzato.")
        return
    origin = websocket.headers.get("origin", "")
    if not origin_is_trusted(origin, websocket.headers.get("host", ""), settings):
        await websocket.close(code=4403, reason="Origine non consentita.")
        return
    try:
        user = resolve_connection_user(websocket, session, settings, str(uuid.uuid4()))
        if _access_revoked(user.role):
            raise ApiError(403, "access_pending", "Account in attesa di autorizzazione.")
    except ApiError as exc:
        await websocket.close(code=4401 if exc.status_code == 401 else 4403, reason=exc.message)
        return

    await websocket.accept()
    previous: dict[str, object] | None = None
    heartbeat = 0
    try:
        while True:
            session.refresh(user)
            if not connection_still_authenticated(websocket, session, settings, user):
                await websocket.close(code=4401, reason="Sessione non più valida.")
                return
            if _access_revoked(user.role):
                await websocket.close(code=4403, reason="Accesso revocato.")
                return
            snapshot = _snapshot(session, user.id, user.role)
            heartbeat += 1
            if snapshot != previous or heartbeat >= 20:
                await websocket.send_json(snapshot)
                previous = snapshot
                heartbeat = 0
            await asyncio.sleep(1)
    except (WebSocketDisconnect, RuntimeError):
        return
