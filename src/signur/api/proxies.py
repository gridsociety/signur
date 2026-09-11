import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from signur.audit import record_event
from signur.auth import AccessUser, AdminUser, DbSession
from signur.config import Settings, get_settings
from signur.errors import ApiError
from signur.local_pkcs11 import (
    LocalPkcs11Error,
    LocalPkcs11SigningClient,
    discover_certificates,
    known_library_paths,
)
from signur.models import CertificateBackend, SigningProxy
from signur.proxy_security import validate_proxy_url
from signur.schemas import (
    KnownPkcs11LibrariesView,
    LocalPkcs11CertificateList,
    LocalPkcs11CertificateView,
    LocalPkcs11DiscoverRequest,
    LocalPkcs11LibraryStatusView,
    SigningIdentityView,
    SigningProxyAdminList,
    SigningProxyAdminView,
    SigningProxyCreate,
    SigningProxyPublicList,
    SigningProxyPublicView,
    SigningProxyUpdate,
)
from signur.secret_box import SecretBoxError, seal_pin
from signur.signing_proxy import (
    ProxySigningError,
    SigningClient,
    SigningIdentity,
    SigningProxyClient,
)

router = APIRouter(tags=["signing proxies"])


def _identity_view(identity: SigningIdentity) -> SigningIdentityView:
    return SigningIdentityView(
        display_name=identity.display_name,
        subject=identity.subject,
        issuer=identity.issuer,
        serial_number=identity.serial_number,
        not_valid_before=identity.certificate.not_valid_before_utc,
        not_valid_after=identity.certificate.not_valid_after_utc,
        certificate_sha256=identity.certificate_sha256,
    )


def _check(proxy: SigningProxy, settings: Settings) -> SigningProxyPublicView:
    client: SigningClient
    if proxy.backend is CertificateBackend.LOCAL:
        if not (
            proxy.pkcs11_library_path
            and proxy.pkcs11_token_label
            and proxy.pkcs11_certificate_label
        ):
            return SigningProxyPublicView(
                id=proxy.id,
                name=proxy.name,
                version=proxy.version,
                backend=proxy.backend,
                requires_pin=not proxy.pin_saved,
                available=False,
            )
        client = LocalPkcs11SigningClient(
            proxy.pkcs11_library_path,
            proxy.pkcs11_token_label,
            proxy.pkcs11_certificate_label,
            None,
        )
    else:
        if proxy.base_url is None:
            raise ApiError(
                500, "invalid_certificate_config", "Configurazione certificato non valida."
            )
        validate_proxy_url(proxy.base_url)
        client = SigningProxyClient(proxy.base_url, settings.signing_proxy_timeout_seconds)
    try:
        identity = client.get_identity()
    except ProxySigningError:
        return SigningProxyPublicView(
            id=proxy.id,
            name=proxy.name,
            version=proxy.version,
            backend=proxy.backend,
            requires_pin=proxy.backend is CertificateBackend.LOCAL and not proxy.pin_saved,
            available=False,
        )
    finally:
        client.close()
    return SigningProxyPublicView(
        id=proxy.id,
        name=proxy.name,
        version=proxy.version,
        backend=proxy.backend,
        requires_pin=proxy.backend is CertificateBackend.LOCAL and not proxy.pin_saved,
        available=True,
        identity=_identity_view(identity),
    )


@router.get("/signing-proxies", response_model=SigningProxyPublicList)
def list_available_proxies(
    _user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SigningProxyPublicList:
    proxies = session.scalars(
        select(SigningProxy)
        .where(SigningProxy.active.is_(True))
        .order_by(SigningProxy.name, SigningProxy.id)
    ).all()
    items = [_check(proxy, settings) for proxy in proxies]
    return SigningProxyPublicList(items=items, total=len(items))


@router.get("/admin/signing-proxies", response_model=SigningProxyAdminList)
def list_admin_proxies(_admin: AdminUser, session: DbSession) -> SigningProxyAdminList:
    proxies = session.scalars(
        select(SigningProxy).order_by(SigningProxy.name, SigningProxy.id)
    ).all()
    return SigningProxyAdminList(
        items=[SigningProxyAdminView.model_validate(proxy) for proxy in proxies],
        total=len(proxies),
    )


@router.post("/admin/signing-proxies", response_model=SigningProxyAdminView, status_code=201)
def create_proxy(
    request: Request,
    body: SigningProxyCreate,
    admin: AdminUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SigningProxyAdminView:
    name = body.name.strip()
    if not name:
        raise ApiError(422, "invalid_proxy_name", "Il nome del proxy è vuoto.")
    values: dict[str, object] = {"name": name, "backend": body.backend}
    if body.backend is CertificateBackend.PKCS11_WEB_PROXY:
        if body.base_url is None:
            raise ApiError(422, "proxy_url_required", "L'URL del PKCS11 Web Proxy è obbligatorio.")
        values["base_url"] = validate_proxy_url(body.base_url)
    else:
        if not (
            body.pkcs11_library_path and body.pkcs11_token_label and body.pkcs11_certificate_label
        ):
            raise ApiError(422, "pkcs11_selection_required", "Seleziona un certificato PKCS#11.")
        try:
            discovered = discover_certificates(body.pkcs11_library_path)
        except LocalPkcs11Error as exc:
            raise ApiError(422, "pkcs11_discovery_failed", str(exc)) from exc
        selected = [
            item
            for item in discovered
            if item.token_label == body.pkcs11_token_label
            and item.certificate_label == body.pkcs11_certificate_label
        ]
        if len(selected) != 1:
            raise ApiError(422, "pkcs11_certificate_unavailable", "Certificato non disponibile.")
        values.update(
            pkcs11_library_path=body.pkcs11_library_path,
            pkcs11_token_label=body.pkcs11_token_label,
            pkcs11_certificate_label=body.pkcs11_certificate_label,
        )
        if body.save_pin:
            if body.pin is None:
                raise ApiError(422, "pin_required", "Inserisci il PIN da salvare.")
            try:
                values["saved_pin_ciphertext"] = seal_pin(
                    body.pin.get_secret_value(), settings.pin_encryption_key
                )
            except SecretBoxError as exc:
                raise ApiError(503, "pin_encryption_unavailable", str(exc)) from exc
    proxy = SigningProxy(active=True, version=1, created_by=admin, **values)
    session.add(proxy)
    record_event(
        session,
        actor=admin,
        action="signing_proxy.created",
        entity_type="signing_proxy",
        entity_id=proxy.id,
        request_id=request.state.request_id,
        details={
            "name": proxy.name,
            "backend": proxy.backend.value,
            "base_url": proxy.base_url,
            "pkcs11_library_path": proxy.pkcs11_library_path,
            "pkcs11_token_label": proxy.pkcs11_token_label,
            "pkcs11_certificate_label": proxy.pkcs11_certificate_label,
            "pin_saved": proxy.pin_saved,
        },
    )
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise ApiError(409, "signing_proxy_exists", "Nome o URL del proxy già presente.") from exc
    return SigningProxyAdminView.model_validate(proxy)


@router.patch("/admin/signing-proxies/{proxy_id}", response_model=SigningProxyAdminView)
def update_proxy(
    request: Request,
    proxy_id: uuid.UUID,
    body: SigningProxyUpdate,
    admin: AdminUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SigningProxyAdminView:
    proxy = session.scalar(
        select(SigningProxy).where(SigningProxy.id == proxy_id).with_for_update()
    )
    if proxy is None:
        raise ApiError(404, "signing_proxy_not_found", "Proxy di firma non trovato.")
    changes = body.model_dump(exclude_none=True, exclude={"pin", "saved_pin_action"})
    if not changes and body.saved_pin_action == "keep":
        raise ApiError(422, "empty_update", "Non è stata specificata alcuna modifica.")
    if "name" in changes:
        changes["name"] = changes["name"].strip()
        if not changes["name"]:
            raise ApiError(422, "invalid_proxy_name", "Il nome del proxy è vuoto.")
    if "base_url" in changes:
        if proxy.backend is not CertificateBackend.PKCS11_WEB_PROXY:
            raise ApiError(422, "certificate_backend_mismatch", "Questa configurazione è locale.")
        changes["base_url"] = validate_proxy_url(changes["base_url"])
    local_fields = {
        "pkcs11_library_path",
        "pkcs11_token_label",
        "pkcs11_certificate_label",
    }
    if local_fields.intersection(changes) and proxy.backend is not CertificateBackend.LOCAL:
        raise ApiError(422, "certificate_backend_mismatch", "Questa configurazione usa un proxy.")
    if local_fields.intersection(changes):
        library_path = str(changes.get("pkcs11_library_path", proxy.pkcs11_library_path))
        token_label = str(changes.get("pkcs11_token_label", proxy.pkcs11_token_label))
        certificate_label = str(
            changes.get("pkcs11_certificate_label", proxy.pkcs11_certificate_label)
        )
        try:
            discovered = discover_certificates(library_path)
        except LocalPkcs11Error as exc:
            raise ApiError(422, "pkcs11_discovery_failed", str(exc)) from exc
        if (
            sum(
                item.token_label == token_label and item.certificate_label == certificate_label
                for item in discovered
            )
            != 1
        ):
            raise ApiError(
                422,
                "pkcs11_certificate_unavailable",
                "Certificato non disponibile.",
            )
    pin_before = proxy.pin_saved
    if body.saved_pin_action == "replace":
        if proxy.backend is not CertificateBackend.LOCAL or body.pin is None:
            raise ApiError(422, "pin_required", "Inserisci il nuovo PIN.")
        try:
            proxy.saved_pin_ciphertext = seal_pin(
                body.pin.get_secret_value(), settings.pin_encryption_key
            )
        except SecretBoxError as exc:
            raise ApiError(503, "pin_encryption_unavailable", str(exc)) from exc
    elif body.saved_pin_action == "remove":
        proxy.saved_pin_ciphertext = None
    before = {field: getattr(proxy, field) for field in changes}
    for field, value in changes.items():
        setattr(proxy, field, value)
    proxy.version += 1
    record_event(
        session,
        actor=admin,
        action="signing_proxy.updated",
        entity_type="signing_proxy",
        entity_id=proxy.id,
        request_id=request.state.request_id,
        details={
            "before": {**before, "pin_saved": pin_before},
            "after": {**changes, "pin_saved": proxy.pin_saved},
            "version": proxy.version,
        },
    )
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise ApiError(409, "signing_proxy_exists", "Nome o URL del proxy già presente.") from exc
    return SigningProxyAdminView.model_validate(proxy)


@router.post("/admin/signing-proxies/{proxy_id}/check", response_model=SigningProxyPublicView)
def check_proxy(
    proxy_id: uuid.UUID,
    _admin: AdminUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SigningProxyPublicView:
    proxy = session.get(SigningProxy, proxy_id)
    if proxy is None:
        raise ApiError(404, "signing_proxy_not_found", "Proxy di firma non trovato.")
    return _check(proxy, settings)


@router.post(
    "/admin/signing-proxies/local/discover",
    response_model=LocalPkcs11CertificateList,
)
def discover_local_certificates(
    body: LocalPkcs11DiscoverRequest,
    _admin: AdminUser,
) -> LocalPkcs11CertificateList:
    try:
        discovered = discover_certificates(body.library_path)
    except LocalPkcs11Error as exc:
        raise ApiError(422, "pkcs11_discovery_failed", str(exc)) from exc
    items = [
        LocalPkcs11CertificateView(
            token_label=item.token_label,
            certificate_label=item.certificate_label,
            identity=_identity_view(item.identity),
        )
        for item in discovered
    ]
    return LocalPkcs11CertificateList(items=items, total=len(items))


@router.get(
    "/admin/signing-proxies/local/libraries",
    response_model=KnownPkcs11LibrariesView,
)
def list_known_local_libraries(
    _admin: AdminUser, settings: Annotated[Settings, Depends(get_settings)]
) -> KnownPkcs11LibrariesView:
    return KnownPkcs11LibrariesView(
        items=known_library_paths(),
        pin_encryption_enabled=settings.pin_encryption_enabled,
    )


@router.post(
    "/admin/signing-proxies/local/library-status",
    response_model=LocalPkcs11LibraryStatusView,
)
def local_library_status(
    body: LocalPkcs11DiscoverRequest,
    _admin: AdminUser,
) -> LocalPkcs11LibraryStatusView:
    path = Path(body.library_path).expanduser()
    return LocalPkcs11LibraryStatusView(exists=path.is_absolute() and path.is_file())
