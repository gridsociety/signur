import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload, selectinload

from signur.audit import record_event
from signur.cades import CadesError, build_cades_b_b, build_cades_parallel_b_b
from signur.config import Settings
from signur.errors import ApiError
from signur.graphics_pdf import GraphicPdfError, GraphicPlacement, apply_graphics
from signur.local_pkcs11 import LocalPkcs11SigningClient, LocalPkcs11SigningError
from signur.models import (
    Blob,
    BlobState,
    CadesStrategy,
    CertificateBackend,
    Document,
    DocumentState,
    GraphicSignatureVersion,
    Placement,
    SignatureJob,
    SignatureJobStatus,
    SignatureMode,
    SignedArtifact,
    SigningProxy,
    User,
    UserRole,
    XadesPackaging,
)
from signur.pades import PadesError, build_pades_b_b, verify_pades_b_b
from signur.proxy_security import validate_proxy_url
from signur.secret_box import SecretBoxError, unseal_pin
from signur.signing_proxy import (
    ProxySigningError,
    SigningClient,
    SigningIdentity,
    SigningProxyClient,
)
from signur.storage import LocalBlobStorage
from signur.xades import XadesError, build_xades_b_b, verify_xades_b_b

ACTIVE_JOB_STATUSES = (SignatureJobStatus.QUEUED, SignatureJobStatus.RUNNING)


@dataclass(frozen=True)
class PlacementSpec:
    version: GraphicSignatureVersion
    page: int
    x: float
    y: float
    width: float
    height: float
    layer_order: int


def enqueue_signature(
    session: Session,
    *,
    document: Document,
    operator: User,
    mode: SignatureMode,
    request_id: str,
    cades_strategy: CadesStrategy | None = None,
    xades_packaging: XadesPackaging | None = None,
    placements: list[PlacementSpec] | None = None,
    signing_proxy: SigningProxy | None = None,
    signing_pin_ciphertext: bytes | None = None,
) -> SignatureJob:
    locked_document = session.scalar(
        select(Document).where(Document.id == document.id).with_for_update()
    )
    if locked_document is None:
        raise ApiError(404, "document_not_found", "Documento non trovato.")
    if locked_document.state is DocumentState.SIGNED:
        raise ApiError(409, "document_finalized", "Il documento è già firmato.")
    active_job = session.scalar(
        select(SignatureJob.id).where(
            SignatureJob.document_id == locked_document.id,
            SignatureJob.status.in_(ACTIVE_JOB_STATUSES),
        )
    )
    if active_job is not None:
        raise ApiError(409, "signature_in_progress", "Esiste già un tentativo di firma attivo.")

    last_attempt = session.scalar(
        select(func.max(SignatureJob.attempt_number)).where(
            SignatureJob.document_id == locked_document.id
        )
    )
    job = SignatureJob(
        document_id=locked_document.id,
        operator_user_id=operator.id,
        attempt_number=(last_attempt or 0) + 1,
        mode=mode,
        cades_strategy=cades_strategy,
        xades_packaging=xades_packaging,
        status=SignatureJobStatus.QUEUED,
        document_version=locked_document.version,
        document_sha256=locked_document.sha256,
        request_id=request_id,
        signing_proxy=signing_proxy,
        signing_proxy_name=signing_proxy.name if signing_proxy is not None else None,
        signing_pin_ciphertext=signing_pin_ciphertext,
    )
    session.add(job)
    session.flush()
    for item in placements or []:
        session.add(
            Placement(
                job=job,
                graphic_signature_version=item.version,
                page=item.page,
                x=item.x,
                y=item.y,
                width=item.width,
                height=item.height,
                layer_order=item.layer_order,
            )
        )
    record_event(
        session,
        actor=operator,
        action="signature.queued",
        entity_type="signature_job",
        entity_id=job.id,
        request_id=request_id,
        details={
            "document_id": str(locked_document.id),
            "attempt_number": job.attempt_number,
            "mode": mode.value,
            "cades_strategy": cades_strategy.value if cades_strategy is not None else None,
            "xades_packaging": xades_packaging.value if xades_packaging is not None else None,
        },
    )
    session.commit()
    session.refresh(job)
    return job


def claim_next_signature(session: Session) -> uuid.UUID | None:
    job = session.scalar(
        select(SignatureJob)
        .where(SignatureJob.status == SignatureJobStatus.QUEUED)
        .order_by(SignatureJob.created_at, SignatureJob.id)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        session.rollback()
        return None
    job.status = SignatureJobStatus.RUNNING
    job.started_at = datetime.now(UTC)
    record_event(
        session,
        actor=job.operator,
        action="signature.started",
        entity_type="signature_job",
        entity_id=job.id,
        request_id=job.request_id,
        details={"document_id": str(job.document_id), "attempt_number": job.attempt_number},
    )
    session.commit()
    return job.id


def _failure_details(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, LocalPkcs11SigningError):
        return exc.code, exc.user_message
    if isinstance(exc, ProxySigningError):
        return "proxy_signing_failed", "Il servizio di firma non ha completato l'operazione."
    if isinstance(exc, CadesError):
        return "cades_generation_failed", "Il file firmato non ha superato la verifica."
    if isinstance(exc, PadesError):
        return "pades_generation_failed", "Il PDF firmato non ha superato la verifica."
    if isinstance(exc, XadesError):
        return "xades_generation_failed", "L'XML firmato non ha superato la verifica."
    if isinstance(exc, GraphicPdfError):
        return "graphic_generation_failed", "Il PDF grafico non ha superato la verifica."
    if isinstance(exc, OSError):
        return "storage_failed", "Il risultato non può essere salvato."
    return "signing_failed", "Firma non riuscita."


def _load_placement(storage: LocalBlobStorage, placement: Placement) -> GraphicPlacement:
    """Read the catalogue image a placement points at."""
    version = placement.graphic_signature_version
    png = storage.path_for(version.blob.storage_key).read_bytes()
    if len(png) != version.blob.size_bytes:
        raise OSError("graphic size mismatch")
    return GraphicPlacement(
        page=placement.page,
        x=placement.x,
        y=placement.y,
        width=placement.width,
        height=placement.height,
        layer_order=placement.layer_order,
        png=png,
    )


def _acquire_signing_identity(
    session: Session,
    job: SignatureJob,
    settings: Settings,
    client: SigningClient | None,
) -> tuple[SigningClient, SigningIdentity, bool]:
    """Open the card, read the identity and freeze it on the job."""
    signing_client: SigningClient
    if client is not None:
        signing_client = client
    elif job.signing_proxy is not None and job.signing_proxy.backend is CertificateBackend.LOCAL:
        proxy = job.signing_proxy
        if not (
            proxy.pkcs11_library_path
            and proxy.pkcs11_token_label
            and proxy.pkcs11_certificate_label
        ):
            raise ProxySigningError("La configurazione PKCS#11 locale è incompleta.")
        ciphertext = job.signing_pin_ciphertext or proxy.saved_pin_ciphertext
        if ciphertext is None:
            raise LocalPkcs11SigningError(
                "pkcs11_pin_required",
                "Il PIN della smart card è richiesto.",
            )
        try:
            pin = unseal_pin(ciphertext, settings.pin_encryption_key)
        except SecretBoxError as exc:
            raise LocalPkcs11SigningError(
                "pkcs11_configuration_failed",
                "Il PIN salvato non è utilizzabile: chiedi a un amministratore di sostituirlo.",
            ) from exc
        signing_client = LocalPkcs11SigningClient(
            proxy.pkcs11_library_path,
            proxy.pkcs11_token_label,
            proxy.pkcs11_certificate_label,
            pin,
        )
    else:
        proxy_url = (
            validate_proxy_url(job.signing_proxy.base_url)
            if job.signing_proxy is not None and job.signing_proxy.base_url is not None
            else settings.signing_proxy_url
        )
        signing_client = SigningProxyClient(proxy_url, settings.signing_proxy_timeout_seconds)
    own_client = client is None
    identity = signing_client.get_identity()
    identity_job = session.scalar(
        select(SignatureJob).where(SignatureJob.id == job.id).with_for_update()
    )
    if identity_job is None or identity_job.status is not SignatureJobStatus.RUNNING:
        raise CadesError("Il tentativo non è più attivo.")
    identity_job.signing_identity_sha256 = identity.certificate_sha256
    identity_job.signing_certificate_der = identity.certificate_der
    identity_job.signing_display_name = identity.display_name
    identity_job.signing_subject = identity.subject
    identity_job.signing_issuer = identity.issuer
    identity_job.signing_serial_number = identity.serial_number
    identity_job.signing_key_bits = identity.key_bits
    identity_job.signing_not_valid_before = identity.certificate.not_valid_before_utc
    identity_job.signing_not_valid_after = identity.certificate.not_valid_after_utc
    identity_job.signing_pin_ciphertext = None
    session.commit()
    return signing_client, identity, own_client


def process_claimed_signature(
    session: Session,
    settings: Settings,
    job_id: uuid.UUID,
    client: SigningClient | None = None,
) -> bool:
    job = session.scalar(
        select(SignatureJob)
        .options(
            joinedload(SignatureJob.document).joinedload(Document.original_blob),
            joinedload(SignatureJob.operator),
            joinedload(SignatureJob.signing_proxy),
            selectinload(SignatureJob.placements)
            .joinedload(Placement.graphic_signature_version)
            .joinedload(GraphicSignatureVersion.blob),
        )
        .where(SignatureJob.id == job_id)
    )
    if job is None or job.status is not SignatureJobStatus.RUNNING:
        return False

    storage = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes)
    signing_client: SigningClient | None = None
    own_client = False
    stored_key: str | None = None
    try:
        original_path = storage.path_for(job.document.original_blob.storage_key)
        original = original_path.read_bytes()
        if len(original) != job.document.original_blob.size_bytes:
            raise OSError("original size mismatch")
        if job.operator.role is UserRole.NO_ACCESS or (
            job.document.owner_user_id != job.operator.id
            and job.operator.role is not UserRole.ADMIN
        ):
            raise ApiError(403, "access_revoked", "L'operatore non è più autorizzato.")

        identity: SigningIdentity | None = None
        if job.mode in {SignatureMode.CADES, SignatureMode.PADES, SignatureMode.XADES}:
            card, identity, own_client = _acquire_signing_identity(session, job, settings, client)
            signing_client = card
            if job.mode is SignatureMode.CADES:
                if job.cades_strategy is CadesStrategy.PARALLEL:
                    result = build_cades_parallel_b_b(original, card, identity)
                else:
                    result = build_cades_b_b(original, card, identity)
                media_type = "application/pkcs7-mime"
                if job.cades_strategy is CadesStrategy.PARALLEL:
                    name = job.document.original_name
                    stem = name[:-4] if name.lower().endswith(".p7m") else name
                    filename = f"{stem}-firmato.p7m"
                else:
                    filename = f"{job.document.original_name}.p7m"
            elif job.mode is SignatureMode.PADES:
                placement = _load_placement(storage, job.placements[0]) if job.placements else None
                result = build_pades_b_b(original, card, identity, placement)
                verify_pades_b_b(result, original)
                media_type = "application/pdf"
                stem = job.document.original_name.removesuffix(".pdf")
                filename = f"{stem}-firmato.pdf"
            else:
                packaging = job.xades_packaging or XadesPackaging.ENVELOPED
                result = build_xades_b_b(original, card, identity, packaging)
                verify_xades_b_b(result, original, packaging, identity)
                media_type = "application/xml"
                stem = job.document.original_name.removesuffix(".xml")
                filename = f"{stem}-firmato.xml"
        elif job.mode is SignatureMode.GRAPHIC:
            result = apply_graphics(
                original, [_load_placement(storage, item) for item in job.placements]
            )
            media_type = "application/pdf"
            stem = job.document.original_name.removesuffix(".pdf")
            filename = f"{stem}-firmato.pdf"
        else:
            raise ApiError(501, "signature_mode_not_implemented", "Modalità non implementata.")
        stored = storage.store_bytes(result)
        stored_key = stored.key

        current_job = session.scalar(
            select(SignatureJob).where(SignatureJob.id == job_id).with_for_update()
        )
        current_document = session.scalar(
            select(Document).where(Document.id == job.document_id).with_for_update()
        )
        if (
            current_job is None
            or current_document is None
            or current_job.status is not SignatureJobStatus.RUNNING
            or current_document.state is DocumentState.SIGNED
            or current_document.sha256 != current_job.document_sha256
        ):
            raise CadesError("Lo stato del documento è cambiato durante la firma.")

        blob = Blob(
            storage_key=stored.key,
            kind="signed_result",
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            state=BlobState.STORED,
        )
        artifact = SignedArtifact(
            document=current_document,
            job=current_job,
            blob=blob,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type=media_type,
            filename=filename,
        )
        current_job.status = SignatureJobStatus.COMPLETED
        current_job.completed_at = datetime.now(UTC)
        current_document.state = DocumentState.SIGNED
        current_document.completed_at = current_job.completed_at
        current_document.version += 1
        session.add(artifact)
        record_event(
            session,
            actor=current_job.operator,
            action="signature.completed",
            entity_type="signature_job",
            entity_id=current_job.id,
            request_id=current_job.request_id,
            details={
                "document_id": str(current_document.id),
                "artifact_sha256": stored.sha256,
                "cades_strategy": (
                    current_job.cades_strategy.value
                    if current_job.cades_strategy is not None
                    else None
                ),
                "signing_identity_sha256": (
                    identity.certificate_sha256 if identity is not None else None
                ),
                "mode": current_job.mode.value,
            },
        )
        session.commit()
        stored_key = None
        return True
    except Exception as exc:
        session.rollback()
        if stored_key is not None:
            storage.delete(stored_key)
        current_job = session.scalar(
            select(SignatureJob).where(SignatureJob.id == job_id).with_for_update()
        )
        if current_job is not None and current_job.status is SignatureJobStatus.RUNNING:
            current_document = session.scalar(
                select(Document).where(Document.id == current_job.document_id).with_for_update()
            )
            error_code, error_message = _failure_details(exc)
            current_job.status = SignatureJobStatus.FAILED
            current_job.error_code = error_code
            current_job.error_message = error_message
            current_job.signing_pin_ciphertext = None
            current_job.completed_at = datetime.now(UTC)
            if current_document is not None and current_document.state is not DocumentState.SIGNED:
                current_document.state = DocumentState.SIGNING_FAILED
                current_document.version += 1
            record_event(
                session,
                actor=current_job.operator,
                action="signature.failed",
                entity_type="signature_job",
                entity_id=current_job.id,
                request_id=current_job.request_id,
                details={"document_id": str(current_job.document_id), "error_code": error_code},
            )
            session.commit()
        return False
    finally:
        if own_client and signing_client is not None:
            signing_client.close()
