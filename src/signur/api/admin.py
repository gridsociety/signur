import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select

from signur.audit import record_event
from signur.auth import LOCAL_AUTHORITY, AdminUser, DbSession, find_local_user
from signur.config import Settings, get_settings
from signur.errors import ApiError
from signur.models import (
    BootstrapState,
    Document,
    SignatureJob,
    SignatureJobStatus,
    User,
    UserRole,
)
from signur.passwords import hash_password
from signur.schemas import (
    AdminPasswordReset,
    DocumentDetail,
    DocumentOwnerUpdate,
    RoleUpdate,
    UserCreate,
    UserList,
    UserUpdate,
    UserView,
)
from signur.sessions import revoke_user_sessions

router = APIRouter(prefix="/admin", tags=["administration"])


@router.get("/users", response_model=UserList)
def list_users(
    _admin: AdminUser,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    search: Annotated[str | None, Query(max_length=255)] = None,
    role: Annotated[list[UserRole] | None, Query()] = None,
) -> UserList:
    filters: list[Any] = []
    if role:
        filters.append(User.role.in_(role))
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                User.display_name.ilike(pattern),
                User.external_id.ilike(pattern),
                User.email.ilike(pattern),
            )
        )
    total = session.scalar(select(func.count(User.id)).where(*filters)) or 0
    users = session.scalars(
        select(User)
        .where(*filters)
        .order_by(User.first_seen_at, User.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return UserList(
        items=[UserView.model_validate(user) for user in users],
        total=total,
        limit=limit,
        offset=offset,
    )


SettingsDep = Annotated[Settings, Depends(get_settings)]


def _require_local_auth(settings: Settings) -> None:
    if not settings.local_auth:
        raise ApiError(
            409,
            "local_auth_disabled",
            "Gli account sono gestiti dal provider di identità esterno.",
        )


@router.post("/users", response_model=UserView, status_code=201)
def create_user(
    request: Request,
    body: UserCreate,
    admin: AdminUser,
    session: DbSession,
    settings: SettingsDep,
) -> UserView:
    _require_local_auth(settings)
    username = body.username.strip()
    if find_local_user(session, username) is not None:
        raise ApiError(409, "username_taken", "Questo nome utente è già in uso.")
    user = User(
        id=uuid.uuid4(),
        identity_authority=LOCAL_AUTHORITY,
        external_id=username,
        display_name=body.display_name.strip(),
        email=body.email,
        role=body.role,
        password_hash=hash_password(body.password),
    )
    session.add(user)
    session.flush()
    record_event(
        session,
        actor=admin,
        action="user.created",
        entity_type="user",
        entity_id=user.id,
        request_id=request.state.request_id,
        details={"initial_role": body.role.value, "created_by_admin": True},
    )
    session.commit()
    return UserView.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserView)
def update_user(
    request: Request,
    user_id: uuid.UUID,
    body: UserUpdate,
    admin: AdminUser,
    session: DbSession,
) -> UserView:
    target = session.scalar(select(User).where(User.id == user_id).with_for_update())
    if target is None:
        raise ApiError(404, "user_not_found", "Utente non trovato.")

    changes: dict[str, str] = {}
    if body.username is not None:
        username = body.username.strip()
        if target.identity_authority != LOCAL_AUTHORITY:
            raise ApiError(
                409,
                "username_not_editable",
                "Il nome utente di questo account è gestito dal provider di identità.",
            )
        clash = find_local_user(session, username)
        if clash is not None and clash.id != target.id:
            raise ApiError(409, "username_taken", "Questo nome utente è già in uso.")
        if username != target.external_id:
            changes["username"] = username
            target.external_id = username
    if body.display_name is not None:
        display_name = body.display_name.strip()
        if display_name != target.display_name:
            changes["display_name"] = display_name
            target.display_name = display_name
    if body.email is not None:
        email = body.email.strip() or None
        if email != target.email:
            changes["email"] = email or ""
            target.email = email

    if not changes:
        return UserView.model_validate(target)
    record_event(
        session,
        actor=admin,
        action="user.updated",
        entity_type="user",
        entity_id=target.id,
        request_id=request.state.request_id,
        details={"changed": sorted(changes)},
    )
    session.commit()
    return UserView.model_validate(target)


@router.put("/users/{user_id}/password", response_model=UserView)
def reset_password(
    request: Request,
    user_id: uuid.UUID,
    body: AdminPasswordReset,
    admin: AdminUser,
    session: DbSession,
    settings: SettingsDep,
) -> UserView:
    _require_local_auth(settings)
    target = session.scalar(select(User).where(User.id == user_id))
    if target is None or target.identity_authority != LOCAL_AUTHORITY:
        raise ApiError(404, "user_not_found", "Utente non trovato.")
    target.password_hash = hash_password(body.new_password)
    revoke_user_sessions(session, target)
    record_event(
        session,
        actor=admin,
        action="user.password_reset",
        entity_type="user",
        entity_id=target.id,
        request_id=request.state.request_id,
        details={},
    )
    session.commit()
    return UserView.model_validate(target)


@router.patch("/users/{user_id}/role", response_model=UserView)
def update_role(
    request: Request,
    user_id: uuid.UUID,
    update: RoleUpdate,
    admin: AdminUser,
    session: DbSession,
) -> UserView:
    session.scalar(select(BootstrapState).where(BootstrapState.id == 1).with_for_update())
    target = session.scalar(select(User).where(User.id == user_id).with_for_update())
    if target is None:
        raise ApiError(404, "user_not_found", "Utente non trovato.")
    if (
        target.id == admin.id
        and target.role is UserRole.ADMIN
        and update.role is not UserRole.ADMIN
    ):
        raise ApiError(
            409, "self_demotion_forbidden", "Non puoi revocare il tuo ruolo amministratore."
        )
    if target.role is update.role:
        return UserView.model_validate(target)
    if target.role is UserRole.ADMIN and update.role is not UserRole.ADMIN:
        admins = session.scalars(
            select(User).where(User.role == UserRole.ADMIN).with_for_update()
        ).all()
        if len(admins) <= 1:
            raise ApiError(409, "last_admin", "Deve rimanere almeno un amministratore.")
    previous = target.role
    target.role = update.role
    record_event(
        session,
        actor=admin,
        action="user.role_changed",
        entity_type="user",
        entity_id=target.id,
        request_id=request.state.request_id,
        details={"from": previous.value, "to": update.role.value},
    )
    session.commit()
    return UserView.model_validate(target)


@router.patch("/documents/{document_id}/owner", response_model=DocumentDetail)
def update_document_owner(
    request: Request,
    document_id: uuid.UUID,
    update: DocumentOwnerUpdate,
    admin: AdminUser,
    session: DbSession,
) -> DocumentDetail:
    document = session.scalar(select(Document).where(Document.id == document_id).with_for_update())
    if document is None:
        raise ApiError(404, "document_not_found", "Documento non trovato.")
    new_owner = session.scalar(
        select(User).where(User.id == update.owner_user_id).with_for_update()
    )
    if new_owner is None:
        raise ApiError(404, "user_not_found", "Utente non trovato.")
    if new_owner.role is UserRole.NO_ACCESS:
        raise ApiError(
            422,
            "owner_ineligible",
            "Il proprietario deve essere un utente abilitato o un amministratore.",
        )
    if document.owner_user_id == new_owner.id:
        return DocumentDetail.model_validate(document)
    active_job = session.scalar(
        select(SignatureJob.id).where(
            SignatureJob.document_id == document.id,
            SignatureJob.status.in_((SignatureJobStatus.QUEUED, SignatureJobStatus.RUNNING)),
        )
    )
    if active_job is not None:
        raise ApiError(
            409,
            "signature_in_progress",
            "Il proprietario non può cambiare durante un tentativo di firma.",
        )
    previous_owner_id = document.owner_user_id
    document.owner = new_owner
    document.version += 1
    record_event(
        session,
        actor=admin,
        action="document.owner_changed",
        entity_type="document",
        entity_id=document.id,
        request_id=request.state.request_id,
        details={
            "from_user_id": str(previous_owner_id),
            "to_user_id": str(new_owner.id),
        },
    )
    session.commit()
    return DocumentDetail.model_validate(document)
