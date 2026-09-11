import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.requests import HTTPConnection

from signur.audit import record_event
from signur.config import Settings, get_settings
from signur.database import get_session
from signur.errors import ApiError
from signur.models import BootstrapState, User, UserRole
from signur.sessions import resolve_session


@dataclass(frozen=True)
class ForwardIdentity:
    external_id: str
    username: str
    display_name: str
    email: str | None


def _header(connection: HTTPConnection, name: str) -> str:
    return connection.headers.get(name, "").strip()


def read_forward_identity(connection: HTTPConnection, settings: Settings) -> ForwardIdentity:
    expected = settings.forward_auth_shared_secret.get_secret_value()
    supplied = _header(connection, settings.identity_secret_header)
    if expected and not hmac.compare_digest(supplied, expected):
        raise ApiError(401, "authentication_required", "Autenticazione richiesta.")

    external_id = _header(connection, settings.identity_uid_header)
    username = _header(connection, settings.identity_username_header)
    display_name = _header(connection, settings.identity_name_header) or username
    email = _header(connection, settings.identity_email_header) or None
    if not external_id or len(external_id) > 255 or any(ord(char) < 32 for char in external_id):
        raise ApiError(401, "invalid_identity", "Identità inoltrata non valida.")
    if not display_name:
        display_name = external_id
    return ForwardIdentity(external_id, username, display_name[:255], email)


def resolve_user(
    session: Session,
    identity: ForwardIdentity,
    settings: Settings,
    request_id: str,
) -> User:
    authority = settings.identity_authority
    existing = session.scalar(
        select(User).where(
            User.identity_authority == authority,
            User.external_id == identity.external_id,
        )
    )
    if existing:
        existing.display_name = identity.display_name
        existing.email = identity.email
        existing.last_seen_at = datetime.now(UTC)
        session.commit()
        return existing

    bootstrap = session.scalar(
        select(BootstrapState).where(BootstrapState.id == 1).with_for_update()
    )
    if bootstrap is None:
        raise RuntimeError("bootstrap_state row is missing; run database migrations")

    existing = session.scalar(
        select(User).where(
            User.identity_authority == authority,
            User.external_id == identity.external_id,
        )
    )
    if existing:
        existing.last_seen_at = datetime.now(UTC)
        session.commit()
        return existing

    role = UserRole.NO_ACCESS if bootstrap.completed else UserRole.ADMIN
    user = User(
        id=uuid.uuid4(),
        identity_authority=authority,
        external_id=identity.external_id,
        display_name=identity.display_name,
        email=identity.email,
        role=role,
    )
    session.add(user)
    session.flush()
    if not bootstrap.completed:
        bootstrap.completed = True
        bootstrap.initial_admin_user_id = user.id
    record_event(
        session,
        actor=user,
        action="user.created",
        entity_type="user",
        entity_id=user.id,
        request_id=request_id,
        details={"initial_role": role.value},
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        found = session.scalar(
            select(User).where(
                User.identity_authority == authority,
                User.external_id == identity.external_id,
            )
        )
        if found is None:
            raise
        return found
    return user


LOCAL_AUTHORITY = "local"
BOOTSTRAP_USERNAME = "admin"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def is_loopback_request(connection: HTTPConnection) -> bool:
    host = connection.client.host if connection.client else ""
    return host in LOOPBACK_HOSTS


def find_local_user(session: Session, username: str) -> User | None:
    return session.scalar(
        select(User).where(
            User.identity_authority == LOCAL_AUTHORITY,
            func.lower(User.external_id) == username.strip().lower(),
        )
    )


def ensure_bootstrap_admin(session: Session, settings: Settings) -> User:
    """Create the passwordless ``admin`` account the first time the app starts."""
    existing = find_local_user(session, BOOTSTRAP_USERNAME)
    if existing is not None:
        return existing
    user = User(
        id=uuid.uuid4(),
        identity_authority=LOCAL_AUTHORITY,
        external_id=BOOTSTRAP_USERNAME,
        display_name="Amministratore",
        email=None,
        role=UserRole.ADMIN,
        password_hash=None,
    )
    session.add(user)
    session.flush()
    bootstrap = session.scalar(select(BootstrapState).where(BootstrapState.id == 1))
    if bootstrap is not None and not bootstrap.completed:
        bootstrap.completed = True
        bootstrap.initial_admin_user_id = user.id
    session.commit()
    return user


def resolve_local_user(connection: HTTPConnection, session: Session, settings: Settings) -> User:
    token = connection.cookies.get(settings.session_cookie_name, "")
    user = resolve_session(session, token)
    if user is not None:
        return user

    # First run convenience: the untouched ``admin`` account has no password yet,
    # so it signs in by itself, but only for someone already on this machine.
    candidate = find_local_user(session, BOOTSTRAP_USERNAME)
    if (
        candidate is not None
        and not candidate.password_hash
        and is_loopback_request(connection)
    ):
        return candidate

    raise ApiError(401, "authentication_required", "Autenticazione richiesta.")


def resolve_connection_user(
    connection: HTTPConnection, session: Session, settings: Settings, request_id: str
) -> User:
    """Identify the caller of an HTTP request or a WebSocket, per auth mode."""
    if settings.local_auth:
        return resolve_local_user(connection, session, settings)
    identity = read_forward_identity(connection, settings)
    return resolve_user(session, identity, settings, request_id)


def get_current_user(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    return resolve_connection_user(request, session, settings, request.state.request_id)


CurrentUser = Annotated[User, Depends(get_current_user)]
DbSession = Annotated[Session, Depends(get_session)]


def require_access(user: CurrentUser) -> User:
    if user.role is UserRole.NO_ACCESS:
        raise ApiError(
            403,
            "access_pending",
            "Il tuo account è in attesa di autorizzazione. Contatta un amministratore.",
        )
    return user


AccessUser = Annotated[User, Depends(require_access)]


def require_admin(user: CurrentUser) -> User:
    if user.role is UserRole.NO_ACCESS:
        raise ApiError(
            403,
            "access_pending",
            "Il tuo account è in attesa di autorizzazione. Contatta un amministratore.",
        )
    if user.role is not UserRole.ADMIN:
        raise ApiError(403, "admin_required", "Operazione riservata agli amministratori.")
    return user


AdminUser = Annotated[User, Depends(require_admin)]
