import re
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, joinedload

from signur.audit import record_event
from signur.auth import AccessUser, DbSession
from signur.cms_content import CmsContentError, extract_nested_content
from signur.config import Settings, get_settings
from signur.detection import detect_content
from signur.errors import ApiError
from signur.models import (
    Blob,
    BlobState,
    Document,
    DocumentState,
    InputFormat,
    PdfaStatus,
    SignatureJob,
    SignatureJobStatus,
    SignedArtifact,
    UserRole,
)
from signur.pdfa import PdfaReport, check_pdfa
from signur.schemas import DocumentDetail, DocumentList, DocumentView
from signur.storage import LocalBlobStorage

router = APIRouter(prefix="/documents", tags=["documents"])


def _check_pdfa(input_format: InputFormat, path: Path) -> PdfaReport:
    """Check the uploaded PDF, or the PDF reached through the CMS layers."""
    if input_format is InputFormat.PDF:
        return check_pdfa(path.read_bytes())
    if input_format is InputFormat.CMS_ATTACHED:
        try:
            return check_pdfa(extract_nested_content(path.read_bytes()).content)
        except CmsContentError:
            return PdfaReport(PdfaStatus.INDETERMINATE, ["unreadable_cms"])
    return PdfaReport(PdfaStatus.NOT_APPLICABLE)


def _visible_document_query(user_id: uuid.UUID, is_admin: bool) -> Select[tuple[Document]]:
    statement = select(Document).options(
        joinedload(Document.owner),
        joinedload(Document.uploaded_by),
        joinedload(Document.original_blob),
        joinedload(Document.signed_artifact).joinedload(SignedArtifact.job),
    )
    return statement if is_admin else statement.where(Document.owner_user_id == user_id)


def _get_visible_document(session: Session, document_id: uuid.UUID, user: AccessUser) -> Document:
    document = session.scalar(
        _visible_document_query(user.id, user.role is UserRole.ADMIN).where(
            Document.id == document_id
        )
    )
    if document is None:
        raise ApiError(404, "document_not_found", "Documento non trovato.")
    return document


def _safe_filename(filename: str | None) -> str:
    name = Path((filename or "documento").replace("\x00", "")).name.strip()
    name = re.sub(r"[\r\n]", "", name)
    return name[:512] or "documento"


@router.get("", response_model=DocumentList)
def list_documents(
    user: AccessUser,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    search: Annotated[str | None, Query(max_length=255)] = None,
    owner: Annotated[list[uuid.UUID] | None, Query()] = None,
) -> DocumentList:
    filters: list[Any] = [] if user.role is UserRole.ADMIN else [Document.owner_user_id == user.id]
    if owner:
        # Everyone else already sees only their own documents, so asking for
        # somebody else's is an administrative act.
        if user.role is not UserRole.ADMIN:
            raise ApiError(403, "admin_required", "Solo un amministratore può filtrare per autore.")
        filters.append(Document.owner_user_id.in_(owner))
    if search and search.strip():
        filters.append(Document.original_name.ilike(f"%{search.strip()}%"))
    total = session.scalar(select(func.count(Document.id)).where(*filters)) or 0
    items = session.scalars(
        select(Document)
        .options(
            joinedload(Document.owner),
            joinedload(Document.uploaded_by),
            joinedload(Document.signed_artifact).joinedload(SignedArtifact.job),
        )
        .where(*filters)
        .order_by(Document.created_at.desc(), Document.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return DocumentList(
        items=[DocumentDetail.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=DocumentView, status_code=201)
async def upload_document(
    request: Request,
    user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
    file: Annotated[UploadFile, File()],
) -> DocumentView:
    storage = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes)
    stored = await storage.store_upload(file)
    detection = detect_content(stored.prefix, file.content_type, stored.path)
    pdfa = _check_pdfa(detection.input_format, stored.path)
    blob = Blob(
        storage_key=stored.key,
        kind="original",
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        state=BlobState.STORED,
    )
    document = Document(
        owner_user_id=user.id,
        uploaded_by_user_id=user.id,
        original_name=_safe_filename(file.filename),
        input_format=detection.input_format,
        detected_media_type=detection.media_type,
        original_blob=blob,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        state=DocumentState.TO_SIGN,
        analysis_status=detection.analysis_status,
        capabilities=detection.capabilities,
        analysis_warnings=detection.warnings,
        pdfa_status=pdfa.status,
        pdfa_declared_part=pdfa.declared_part,
        pdfa_violations=pdfa.violations,
    )
    session.add(document)
    session.flush()
    record_event(
        session,
        actor=user,
        action="document.uploaded",
        entity_type="document",
        entity_id=document.id,
        request_id=request.state.request_id,
        details={
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "input_format": detection.input_format.value,
        },
    )
    try:
        session.commit()
    except Exception:
        session.rollback()
        storage.delete(stored.key)
        raise
    session.refresh(document)
    return DocumentView.model_validate(document)


@router.get("/{document_id}", response_model=DocumentDetail)
def get_document(document_id: uuid.UUID, user: AccessUser, session: DbSession) -> DocumentDetail:
    return DocumentDetail.model_validate(_get_visible_document(session, document_id, user))


@router.get("/{document_id}/original", response_class=FileResponse)
def download_original(
    request: Request,
    document_id: uuid.UUID,
    user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    document = _get_visible_document(session, document_id, user)
    path = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes).path_for(
        document.original_blob.storage_key
    )
    if not path.is_file():
        raise ApiError(409, "original_unavailable", "Il file originale non è disponibile.")
    record_event(
        session,
        actor=user,
        action="document.original_downloaded",
        entity_type="document",
        entity_id=document.id,
        request_id=request.state.request_id,
        details={"sha256": document.sha256, "size_bytes": document.size_bytes},
    )
    session.commit()
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=document.original_name,
        content_disposition_type="attachment",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.get("/{document_id}/preview", response_class=Response)
def preview_pdf(
    document_id: uuid.UUID,
    user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    document = _get_visible_document(session, document_id, user)
    path = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes).path_for(
        document.original_blob.storage_key
    )
    if not path.is_file():
        raise ApiError(409, "original_unavailable", "Il file originale non è disponibile.")
    if document.input_format in {InputFormat.CMS_ATTACHED, InputFormat.OPAQUE}:
        try:
            embedded = extract_nested_content(path.read_bytes()).content
        except (CmsContentError, OSError) as exc:
            if document.input_format is InputFormat.OPAQUE:
                raise ApiError(
                    422, "preview_unavailable", "Il documento non contiene un PDF visualizzabile."
                ) from exc
            raise ApiError(
                422, "preview_unavailable", "Il contenuto del P7M non è visualizzabile."
            ) from exc
        if not embedded.startswith(b"%PDF-"):
            raise ApiError(422, "preview_unavailable", "Il P7M non contiene un PDF visualizzabile.")
        return Response(
            content=embedded,
            media_type="application/pdf",
            headers={"Content-Disposition": "inline", "X-Content-Type-Options": "nosniff"},
        )
    if document.input_format is not InputFormat.PDF:
        raise ApiError(422, "preview_unavailable", "L'anteprima è disponibile soltanto per i PDF.")
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=_safe_filename(document.original_name),
        content_disposition_type="inline",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.get("/{document_id}/result", response_class=FileResponse)
def download_result(
    request: Request,
    document_id: uuid.UUID,
    user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    filters = [Document.id == document_id]
    if user.role is not UserRole.ADMIN:
        filters.append(Document.owner_user_id == user.id)
    artifact = session.scalar(
        select(SignedArtifact)
        .join(SignedArtifact.document)
        .options(joinedload(SignedArtifact.blob))
        .where(*filters)
    )
    if artifact is None:
        document_exists = session.scalar(select(Document.id).where(*filters))
        if document_exists is None:
            raise ApiError(404, "document_not_found", "Documento non trovato.")
        raise ApiError(409, "result_unavailable", "Il documento non è ancora firmato.")
    path = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes).path_for(
        artifact.blob.storage_key
    )
    if not path.is_file():
        raise ApiError(409, "result_unavailable", "Il risultato firmato non è disponibile.")
    record_event(
        session,
        actor=user,
        action="document.result_downloaded",
        entity_type="document",
        entity_id=document_id,
        request_id=request.state.request_id,
        details={"sha256": artifact.sha256, "size_bytes": artifact.size_bytes},
    )
    session.commit()
    return FileResponse(
        path,
        media_type=artifact.media_type,
        filename=artifact.filename,
        content_disposition_type="attachment",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.delete("/{document_id}", status_code=204)
def delete_document(
    request: Request,
    document_id: uuid.UUID,
    user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    filters = [Document.id == document_id]
    if user.role is not UserRole.ADMIN:
        filters.append(Document.owner_user_id == user.id)
    document = session.scalar(
        select(Document)
        .options(joinedload(Document.original_blob))
        .where(*filters)
        .with_for_update(of=Document)
    )
    if document is None:
        raise ApiError(404, "document_not_found", "Documento non trovato.")
    if document.state is DocumentState.SIGNED:
        raise ApiError(409, "document_finalized", "Un documento firmato non può essere eliminato.")
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
            "Il documento non può essere eliminato durante un tentativo di firma.",
        )
    blob = document.original_blob
    storage_key = blob.storage_key
    blob.state = BlobState.DELETED
    session.delete(document)
    record_event(
        session,
        actor=user,
        action="document.deleted",
        entity_type="document",
        entity_id=document.id,
        request_id=request.state.request_id,
        details={"owner_user_id": str(document.owner_user_id), "sha256": document.sha256},
    )
    session.commit()
    LocalBlobStorage(settings.storage_root, settings.max_upload_bytes).delete(storage_key)
