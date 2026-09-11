from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from signur.audit import record_event
from signur.auth import CurrentUser, DbSession, find_local_user, is_loopback_request
from signur.config import Settings, get_settings
from signur.errors import ApiError
from signur.models import UserRole
from signur.passwords import hash_password, verify_password
from signur.schemas import AuthStatus, LoginRequest, LoginResult, PasswordChange, UserView
from signur.sessions import create_session, revoke_token, revoke_user_sessions

router = APIRouter(prefix="/auth", tags=["authentication"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


def _require_local_auth(settings: Settings) -> None:
    if not settings.local_auth:
        raise ApiError(
            409,
            "local_auth_disabled",
            "L'autenticazione locale non è attiva su questo server.",
        )


def _set_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=int(settings.session_lifetime_hours * 3600),
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )


@router.get("/status", response_model=AuthStatus)
def auth_status(request: Request, session: DbSession, settings: SettingsDep) -> AuthStatus:
    if not settings.local_auth:
        return AuthStatus(auth_mode=settings.auth_mode, authenticated=True, password_set=True)
    from signur.auth import BOOTSTRAP_USERNAME, resolve_local_user

    admin = find_local_user(session, BOOTSTRAP_USERNAME)
    password_set = bool(admin.password_hash) if admin else True
    try:
        user = resolve_local_user(request, session, settings)
    except ApiError:
        return AuthStatus(
            auth_mode=settings.auth_mode, authenticated=False, password_set=password_set
        )
    return AuthStatus(
        auth_mode=settings.auth_mode,
        authenticated=True,
        password_set=password_set,
        user=UserView.model_validate(user),
    )


@router.post("/login", response_model=LoginResult)
def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    session: DbSession,
    settings: SettingsDep,
) -> LoginResult:
    _require_local_auth(settings)
    user = find_local_user(session, body.username)
    invalid = ApiError(401, "invalid_credentials", "Nome utente o password non validi.")
    if user is None:
        raise invalid
    if user.password_hash:
        if not verify_password(body.password, user.password_hash):
            raise invalid
    else:
        # An account without a password exists only until someone sets one, and
        # it must never be reachable from another machine.
        if body.password or not is_loopback_request(request):
            raise invalid
    if user.role is UserRole.NO_ACCESS:
        raise ApiError(
            403,
            "access_pending",
            "Il tuo account è in attesa di autorizzazione. Contatta un amministratore.",
        )
    token = create_session(session, user, settings, persistent=body.persistent)
    record_event(
        session,
        actor=user,
        action="user.logged_in",
        entity_type="user",
        entity_id=user.id,
        request_id=request.state.request_id,
        details={"persistent": body.persistent},
    )
    session.commit()
    _set_cookie(response, token, settings)
    result = LoginResult.model_validate(user)
    if body.persistent:
        result.session_token = token
    return result


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, session: DbSession, settings: SettingsDep) -> None:
    revoke_token(session, request.cookies.get(settings.session_cookie_name, ""))
    response.delete_cookie(settings.session_cookie_name, path="/")


@router.post("/password", response_model=UserView)
def change_password(
    request: Request,
    response: Response,
    body: PasswordChange,
    user: CurrentUser,
    session: DbSession,
    settings: SettingsDep,
) -> UserView:
    _require_local_auth(settings)
    if user.identity_authority != "local":
        raise ApiError(
            409, "not_a_local_account", "Questo account non usa l'autenticazione locale."
        )
    if user.password_hash and not verify_password(body.current_password, user.password_hash):
        raise ApiError(403, "invalid_credentials", "La password attuale non è corretta.")
    user.password_hash = hash_password(body.new_password)
    # A password change invalidates every session, including the one in use.
    revoke_user_sessions(session, user)
    token = create_session(session, user, settings)
    record_event(
        session,
        actor=user,
        action="user.password_changed",
        entity_type="user",
        entity_id=user.id,
        request_id=request.state.request_id,
        details={},
    )
    session.commit()
    _set_cookie(response, token, settings)
    return UserView.model_validate(user)
