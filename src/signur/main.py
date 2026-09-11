import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from signur.api import admin, auth, documents, events, graphics, me, proxies, signatures
from signur.config import get_settings
from signur.errors import ApiError, ErrorBody, ErrorResponse, api_error_handler
from signur.migrate import upgrade_to_head
from signur.schemas import HealthView

logger = logging.getLogger(__name__)
STATIC_ROOT = __file__.replace("main.py", "static")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.validate_security()
    settings.storage_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not settings.pin_encryption_enabled:
        logger.warning(
            "SIGNUR_PIN_ENCRYPTION_KEY is not set: smart card PINs are stored "
            "unencrypted. See the README for how to enable encryption."
        )
    if settings.auto_migrate:
        upgrade_to_head(settings)
    if settings.local_auth:
        from signur.auth import ensure_bootstrap_admin
        from signur.database import SessionLocal

        with SessionLocal() as session:
            ensure_bootstrap_admin(session, settings)
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="Signur", version="0.1.0", lifespan=lifespan)
    app.add_exception_handler(ApiError, api_error_handler)  # type: ignore[arg-type]

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = str(uuid.uuid4())
        settings = get_settings()
        client_ip = request.client.host if request.client else ""
        if settings.trusted_gateway_ips and client_ip not in settings.trusted_gateway_ips:
            response = api_error_handler(
                request,
                ApiError(403, "gateway_forbidden", "Gateway non autorizzato."),
            )
        elif request.method not in {"GET", "HEAD", "OPTIONS"} and settings.allowed_origins:
            origin = request.headers.get("origin", "").rstrip("/")
            if origin not in settings.allowed_origins:
                response = api_error_handler(
                    request,
                    ApiError(403, "origin_forbidden", "Origine della richiesta non consentita."),
                )
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        body = ErrorResponse(
            error=ErrorBody(
                code="validation_error",
                message="La richiesta non è valida.",
                request_id=request.state.request_id,
                details=exc.errors(),
            )
        )
        return JSONResponse(status_code=422, content=jsonable_encoder(body))

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled request error", extra={"request_id": request.state.request_id})
        body = ErrorResponse(
            error=ErrorBody(
                code="internal_error",
                message="Errore interno. Riprova o comunica l'identificativo della richiesta.",
                request_id=request.state.request_id,
            )
        )
        return JSONResponse(status_code=500, content=jsonable_encoder(body))

    @app.get("/healthz", response_model=HealthView, include_in_schema=False)
    def health() -> HealthView:
        return HealthView(status="ok")

    @app.get("/", include_in_schema=False, response_class=FileResponse)
    def home() -> FileResponse:
        return FileResponse(f"{STATIC_ROOT}/index.html", media_type="text/html; charset=utf-8")

    app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")

    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(me.router, prefix="/api/v1")
    app.include_router(documents.router, prefix="/api/v1")
    app.include_router(signatures.router, prefix="/api/v1")
    app.include_router(events.router, prefix="/api/v1")
    app.include_router(graphics.router, prefix="/api/v1")
    app.include_router(proxies.router, prefix="/api/v1")
    app.include_router(admin.router, prefix="/api/v1")
    return app


app = create_app()


def run() -> None:
    settings = get_settings()
    host = settings.bind_host
    port = settings.bind_port
    print(f"Signur: http://{host}:{port}")
    uvicorn.run("signur.main:app", host=host, port=port, proxy_headers=False)
