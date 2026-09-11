import io
import logging
import uuid
import warnings
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse
from PIL import Image, UnidentifiedImageError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from signur.audit import record_event
from signur.auth import AccessUser, AdminUser, DbSession
from signur.config import Settings, get_settings
from signur.errors import ApiError
from signur.models import (
    Blob,
    BlobState,
    Document,
    GraphicSignature,
    GraphicSignatureVersion,
    Placement,
    SignatureJob,
    UserRole,
)
from signur.schemas import GraphicSignatureList, GraphicSignatureUpdate, GraphicSignatureView
from signur.storage import LocalBlobStorage

router = APIRouter(tags=["graphic signatures"])
logger = logging.getLogger(__name__)


def _view(graphic: GraphicSignature) -> GraphicSignatureView:
    return GraphicSignatureView.model_validate(graphic)


async def _read_png(upload: UploadFile, settings: Settings) -> tuple[bytes, int, int]:
    try:
        data = await upload.read(settings.max_graphic_bytes + 1)
    finally:
        await upload.close()
    if len(data) > settings.max_graphic_bytes:
        raise ApiError(413, "graphic_too_large", "L'immagine supera il limite consentito.")
    if not data:
        raise ApiError(422, "empty_graphic", "L'immagine è vuota.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "PNG" or getattr(image, "n_frames", 1) != 1:
                    raise ApiError(422, "invalid_graphic", "È richiesto un singolo PNG statico.")
                width, height = image.size
                if max(width, height) > settings.max_graphic_dimension:
                    raise ApiError(
                        422,
                        "graphic_dimensions_exceeded",
                        "Le dimensioni dell'immagine superano il limite consentito.",
                    )
                image.load()
                alpha_min, alpha_max = image.convert("RGBA").getchannel("A").getextrema()
                if alpha_min == 255:
                    raise ApiError(
                        422, "graphic_without_transparency", "Il PNG non contiene trasparenza."
                    )
                if alpha_max == 0:
                    raise ApiError(422, "graphic_invisible", "Il PNG è completamente trasparente.")
    except ApiError:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, Image.DecompressionBombWarning) as exc:
        raise ApiError(
            422, "invalid_graphic", "Il PNG non è valido o non è decodificabile."
        ) from exc
    return data, width, height


def _new_version(
    session: DbSession,
    graphic: GraphicSignature,
    data: bytes,
    width: int,
    height: int,
    admin: AdminUser,
    settings: Settings,
) -> tuple[GraphicSignatureVersion, str]:
    storage = LocalBlobStorage(settings.storage_root, settings.max_graphic_bytes)
    stored = storage.store_bytes(data)
    blob = Blob(
        storage_key=stored.key,
        kind="graphic_signature",
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        state=BlobState.STORED,
    )
    version = GraphicSignatureVersion(
        graphic_signature=graphic,
        version_number=graphic.current_version_number or 1,
        blob=blob,
        sha256=stored.sha256,
        width_pixels=width,
        height_pixels=height,
        created_by=admin,
    )
    session.add(version)
    return version, stored.key


@router.get("/graphic-signatures", response_model=GraphicSignatureList)
def list_graphics(_user: AccessUser, session: DbSession) -> GraphicSignatureList:
    graphics = session.scalars(
        select(GraphicSignature)
        .options(selectinload(GraphicSignature.versions))
        .where(GraphicSignature.active.is_(True))
        .order_by(GraphicSignature.name, GraphicSignature.id)
    ).all()
    return GraphicSignatureList(items=[_view(graphic) for graphic in graphics], total=len(graphics))


@router.get("/admin/graphic-signatures", response_model=GraphicSignatureList)
def list_admin_graphics(_admin: AdminUser, session: DbSession) -> GraphicSignatureList:
    graphics = session.scalars(
        select(GraphicSignature)
        .options(selectinload(GraphicSignature.versions))
        .order_by(GraphicSignature.name, GraphicSignature.id)
    ).all()
    return GraphicSignatureList(items=[_view(graphic) for graphic in graphics], total=len(graphics))


@router.get(
    "/graphic-signatures/{graphic_id}/versions/{version_number}/image",
    response_class=FileResponse,
)
def download_graphic(
    request: Request,
    graphic_id: uuid.UUID,
    version_number: int,
    user: AccessUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    version = session.scalar(
        select(GraphicSignatureVersion)
        .join(GraphicSignatureVersion.graphic_signature)
        .options(
            selectinload(GraphicSignatureVersion.blob),
            selectinload(GraphicSignatureVersion.graphic_signature),
        )
        .where(
            GraphicSignatureVersion.graphic_signature_id == graphic_id,
            GraphicSignatureVersion.version_number == version_number,
        )
    )
    if version is None:
        raise ApiError(404, "graphic_version_not_found", "Versione grafica non trovata.")
    visible = user.role is UserRole.ADMIN or version.graphic_signature.active
    if not visible:
        filters = [Placement.graphic_signature_version_id == version.id]
        if user.role is not UserRole.ADMIN:
            filters.append(Document.owner_user_id == user.id)
        visible = (
            session.scalar(
                select(Placement.id)
                .join(Placement.job)
                .join(SignatureJob.document)
                .where(*filters)
                .limit(1)
            )
            is not None
        )
    if not visible:
        raise ApiError(404, "graphic_version_not_found", "Versione grafica non trovata.")
    path = LocalBlobStorage(settings.storage_root, settings.max_graphic_bytes).path_for(
        version.blob.storage_key
    )
    if not path.is_file():
        raise ApiError(409, "graphic_unavailable", "L'immagine non è disponibile.")
    record_event(
        session,
        actor=user,
        action="graphic_signature.version_downloaded",
        entity_type="graphic_signature_version",
        entity_id=version.id,
        request_id=request.state.request_id,
        details={
            "graphic_signature_id": str(graphic_id),
            "version": version.version_number,
            "sha256": version.sha256,
        },
    )
    session.commit()
    return FileResponse(
        path,
        media_type="image/png",
        filename=f"{version.graphic_signature.name}-v{version.version_number}.png",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.post("/admin/graphic-signatures", response_model=GraphicSignatureView, status_code=201)
async def create_graphic(
    request: Request,
    admin: AdminUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
    name: Annotated[str, Form(min_length=1, max_length=255)],
    image: Annotated[UploadFile, File()],
    description: Annotated[str, Form(max_length=1000)] = "",
) -> GraphicSignatureView:
    data, width, height = await _read_png(image, settings)
    graphic = GraphicSignature(
        name=name.strip(), description=description, active=True, created_by=admin
    )
    session.add(graphic)
    version, storage_key = _new_version(session, graphic, data, width, height, admin, settings)
    record_event(
        session,
        actor=admin,
        action="graphic_signature.created",
        entity_type="graphic_signature",
        entity_id=graphic.id,
        request_id=request.state.request_id,
        details={"version_id": str(version.id), "sha256": version.sha256},
    )
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        LocalBlobStorage(settings.storage_root, settings.max_graphic_bytes).delete(storage_key)
        logger.warning("Graphic signature creation conflicted", exc_info=exc)
        raise ApiError(
            409, "graphic_name_exists", "Esiste già una firma grafica con questo nome."
        ) from exc
    session.refresh(graphic)
    return _view(graphic)


@router.patch("/admin/graphic-signatures/{graphic_id}", response_model=GraphicSignatureView)
def update_graphic(
    request: Request,
    graphic_id: uuid.UUID,
    update: GraphicSignatureUpdate,
    admin: AdminUser,
    session: DbSession,
) -> GraphicSignatureView:
    graphic = session.scalar(
        select(GraphicSignature)
        .options(selectinload(GraphicSignature.versions))
        .where(GraphicSignature.id == graphic_id)
        .with_for_update()
    )
    if graphic is None:
        raise ApiError(404, "graphic_not_found", "Firma grafica non trovata.")
    changes = update.model_dump(exclude_none=True)
    if not changes:
        raise ApiError(422, "empty_update", "Non è stata specificata alcuna modifica.")
    before = {field: getattr(graphic, field) for field in changes}
    for field, value in changes.items():
        setattr(graphic, field, value.strip() if isinstance(value, str) else value)
    record_event(
        session,
        actor=admin,
        action="graphic_signature.updated",
        entity_type="graphic_signature",
        entity_id=graphic.id,
        request_id=request.state.request_id,
        details={"before": before, "after": changes},
    )
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise ApiError(
            409, "graphic_name_exists", "Esiste già una firma grafica con questo nome."
        ) from exc
    return _view(graphic)


@router.post(
    "/admin/graphic-signatures/{graphic_id}/versions",
    response_model=GraphicSignatureView,
    status_code=201,
)
async def upload_graphic_version(
    request: Request,
    graphic_id: uuid.UUID,
    admin: AdminUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
    image: Annotated[UploadFile, File()],
) -> GraphicSignatureView:
    data, width, height = await _read_png(image, settings)
    graphic = session.scalar(
        select(GraphicSignature)
        .options(selectinload(GraphicSignature.versions))
        .where(GraphicSignature.id == graphic_id)
        .with_for_update()
    )
    if graphic is None:
        raise ApiError(404, "graphic_not_found", "Firma grafica non trovata.")
    graphic.current_version_number += 1
    version, storage_key = _new_version(session, graphic, data, width, height, admin, settings)
    record_event(
        session,
        actor=admin,
        action="graphic_signature.version_created",
        entity_type="graphic_signature",
        entity_id=graphic.id,
        request_id=request.state.request_id,
        details={"version": version.version_number, "sha256": version.sha256},
    )
    try:
        session.commit()
    except Exception:
        session.rollback()
        LocalBlobStorage(settings.storage_root, settings.max_graphic_bytes).delete(storage_key)
        raise
    return _view(graphic)


@router.delete("/admin/graphic-signatures/{graphic_id}/versions/{version_number}", status_code=204)
def delete_graphic_version(
    request: Request,
    graphic_id: uuid.UUID,
    version_number: int,
    admin: AdminUser,
    session: DbSession,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    version = session.scalar(
        select(GraphicSignatureVersion)
        .join(GraphicSignatureVersion.graphic_signature)
        .options(
            selectinload(GraphicSignatureVersion.blob),
            selectinload(GraphicSignatureVersion.graphic_signature),
        )
        .where(
            GraphicSignatureVersion.graphic_signature_id == graphic_id,
            GraphicSignatureVersion.version_number == version_number,
        )
        .with_for_update()
    )
    if version is None:
        raise ApiError(404, "graphic_version_not_found", "Versione grafica non trovata.")
    if version.version_number == version.graphic_signature.current_version_number:
        raise ApiError(
            409, "current_graphic_version", "La versione corrente non può essere eliminata."
        )
    if session.scalar(
        select(func.count(Placement.id)).where(Placement.graphic_signature_version_id == version.id)
    ):
        raise ApiError(409, "graphic_version_referenced", "La versione è usata da un documento.")
    storage_key = version.blob.storage_key
    version.blob.state = BlobState.DELETED
    record_event(
        session,
        actor=admin,
        action="graphic_signature.version_deleted",
        entity_type="graphic_signature",
        entity_id=graphic_id,
        request_id=request.state.request_id,
        details={"version": version_number, "sha256": version.sha256},
    )
    session.delete(version)
    session.commit()
    LocalBlobStorage(settings.storage_root, settings.max_graphic_bytes).delete(storage_key)
