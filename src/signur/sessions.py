"""Server-side sessions for the local authentication mode.

The cookie carries an opaque random token; only its hash is stored, so reading
the database does not yield usable credentials. Sessions can be revoked at any
time, which is what a password change relies on.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from signur.config import Settings
from signur.models import User, UserSession

TOKEN_BYTES = 32


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(
    session: Session, user: User, settings: Settings, *, persistent: bool = False
) -> str:
    """Issue a session token. Persistent sessions are meant for CLI logins."""
    lifetime = (
        timedelta(days=settings.persistent_session_days)
        if persistent
        else timedelta(hours=settings.session_lifetime_hours)
    )
    token = secrets.token_urlsafe(TOKEN_BYTES)
    session.add(
        UserSession(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=datetime.now(UTC) + lifetime,
        )
    )
    return token


def resolve_session(session: Session, token: str) -> User | None:
    if not token:
        return None
    record = session.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    if record is None:
        return None
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(UTC):
        session.delete(record)
        session.commit()
        return None
    record.last_seen_at = datetime.now(UTC)
    session.commit()
    return record.user


def revoke_token(session: Session, token: str) -> None:
    if token:
        session.execute(delete(UserSession).where(UserSession.token_hash == hash_token(token)))
        session.commit()


def revoke_user_sessions(session: Session, user: User) -> None:
    session.execute(delete(UserSession).where(UserSession.user_id == user.id))


def session_is_live(session: Session, token: str) -> bool:
    """Whether a session is still usable, without recording that it was used.

    A connection that stays open asks this over and over, so it must not write
    anything; resolving the session outright would rewrite its last use every
    time.
    """
    if not token:
        return False
    expires_at = session.scalar(
        select(UserSession.expires_at).where(UserSession.token_hash == hash_token(token))
    )
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at > datetime.now(UTC)
