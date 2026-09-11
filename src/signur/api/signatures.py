import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from signur.auth import AccessUser, DbSession
from signur.config import Settings, get_settings
from signur.errors import ApiError
from signur.models import (
    CadesStrategy,
    CertificateBackend,
    Document,
    GraphicSignature,
    GraphicSignatureVersion,
    InputFormat,
    SignatureJob,
    SignatureMode,
    SigningProxy,
    UserRole,
    XadesPackaging,
)
from signur.schemas import SignatureCreate, SignatureJobView, SigningIdentityView
from signur.secret_box import SecretBoxError, seal_pin
from signur.signature_service import PlacementSpec, enqueue_signature
from signur.signing_proxy import ProxySigningError, SigningProxyClient

router = APIRouter(tags=["signatures"])


def _visible_job(session: DbSession, job_id: uuid.UUID, user: AccessUser) -> SignatureJob:
    filters = [SignatureJob.id == job_id]
    if user.role is not UserRole.ADMIN:
        filters.append(Document.owner_user_id == user.id)
    job = session.scalar(
        select(SignatureJob)
        .join(SignatureJob.document)
        .options(joinedload(SignatureJob.document))
        .where(*filters)
    )
    if job is None:
        raise ApiError(404, "signature_job_not_found", "Tentativo di firma non trovato.")
    return job


@router.get("/signing-identity", response_model=SigningIdentityView)
def get_signing_identity(
    _user: AccessUser, settings: Annotated[Settings, Depends(get_settings)]
) -> SigningIdentityView:
    client = SigningProxyClient(settings.signing_proxy_url, settings.signing_proxy_timeout_seconds)
    try:
        identity = client.get_identity()
    except ProxySigningError as exc:
        raise ApiError(
            503,
            "signing_identity_unavailable",
            "I dati del firmatario non sono disponibili.",
        ) from exc
    finally:
        client.close()
    return SigningIdentityView(
        display_name=identity.display_name,
        subject=identity.subject,
        issuer=identity.issuer,
        serial_number=identity.serial_number,
        not_valid_before=identity.certificate.not_valid_before_utc,
        not_valid_after=identity.certificate.not_valid_after_utc,
        certificate_sha256=identity.certificate_sha256,
    )


@router.post(
    "/documents/{document_id}/signatures", response_model=SignatureJobView, status_code=202
)
def create_signature(
    request: Request,
    document_id: uuid.UUID,
    body: SignatureCreate,
    user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SignatureJobView:
    filters = [Document.id == document_id]
    if user.role is not UserRole.ADMIN:
        filters.append(Document.owner_user_id == user.id)
    document = session.scalar(select(Document).where(*filters))
    if document is None:
        raise ApiError(404, "document_not_found", "Documento non trovato.")
    if body.mode.value not in document.capabilities:
        raise ApiError(
            422,
            "signature_mode_unavailable",
            "La modalità richiesta non è disponibile per questo documento.",
        )
    is_cms = document.input_format is InputFormat.CMS_ATTACHED
    if (is_cms and body.cades_strategy is CadesStrategy.NEW) or (
        not is_cms and body.cades_strategy in {CadesStrategy.NESTED, CadesStrategy.PARALLEL}
    ):
        raise ApiError(
            422,
            "cades_strategy_unavailable",
            "La strategia CAdES richiesta non è disponibile per questo documento.",
        )
    xades_packaging = None
    if body.mode is SignatureMode.XADES:
        xades_packaging = body.xades_packaging or XadesPackaging.ENVELOPED
    cades_strategy = None
    if body.mode is SignatureMode.CADES:
        cades_strategy = body.cades_strategy or (
            CadesStrategy.NESTED if is_cms else CadesStrategy.NEW
        )
    version_ids = {placement.graphic_signature_version_id for placement in body.placements}
    versions = session.scalars(
        select(GraphicSignatureVersion)
        .join(GraphicSignatureVersion.graphic_signature)
        .where(
            GraphicSignatureVersion.id.in_(version_ids),
            GraphicSignature.active.is_(True),
        )
    ).all()
    versions_by_id = {version.id: version for version in versions}
    if len(versions_by_id) != len(version_ids):
        raise ApiError(
            422,
            "graphic_version_unavailable",
            "Una firma grafica richiesta non è disponibile.",
        )
    placements = [
        PlacementSpec(
            version=versions_by_id[item.graphic_signature_version_id],
            page=item.page,
            x=item.x,
            y=item.y,
            width=item.width,
            height=item.height,
            layer_order=item.order,
        )
        for item in body.placements
    ]
    signing_proxy = None
    signing_pin_ciphertext = None
    if body.mode is not SignatureMode.GRAPHIC:
        proxy_query = select(SigningProxy).where(SigningProxy.active.is_(True))
        if body.signing_proxy_id is not None:
            proxy_query = proxy_query.where(SigningProxy.id == body.signing_proxy_id)
        signing_proxy = session.scalar(
            proxy_query.order_by(SigningProxy.sort_order, SigningProxy.name, SigningProxy.id)
        )
        if body.signing_proxy_id is not None and signing_proxy is None:
            raise ApiError(422, "signing_proxy_unavailable", "Proxy di firma non disponibile.")
        if signing_proxy is not None and signing_proxy.backend is CertificateBackend.LOCAL:
            if body.pin is None and not signing_proxy.pin_saved:
                raise ApiError(422, "pin_required", "Inserisci il PIN della smart card.")
            if body.pin is not None:
                try:
                    signing_pin_ciphertext = seal_pin(
                        body.pin.get_secret_value(), settings.pin_encryption_key
                    )
                except SecretBoxError as exc:
                    raise ApiError(503, "pin_encryption_unavailable", str(exc)) from exc
        elif body.pin is not None:
            raise ApiError(422, "pin_not_allowed", "Il PIN non è previsto per questo certificato.")
    job = enqueue_signature(
        session,
        document=document,
        operator=user,
        mode=body.mode,
        cades_strategy=cades_strategy,
        xades_packaging=xades_packaging,
        request_id=request.state.request_id,
        placements=placements,
        signing_proxy=signing_proxy,
        signing_pin_ciphertext=signing_pin_ciphertext,
    )
    return SignatureJobView.model_validate(job)


@router.get("/signature-jobs/{job_id}", response_model=SignatureJobView)
def get_signature_job(job_id: uuid.UUID, user: AccessUser, session: DbSession) -> SignatureJobView:
    return SignatureJobView.model_validate(_visible_job(session, job_id, user))
