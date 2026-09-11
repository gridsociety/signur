from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str
    details: Any | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class ApiError(Exception):
    def __init__(
        self, status_code: int, code: str, message: str, details: Any | None = None
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    body = ErrorResponse(
        error=ErrorBody(
            code=exc.code,
            message=exc.message,
            request_id=request_id,
            details=exc.details,
        )
    )
    return JSONResponse(status_code=exc.status_code, content=body.model_dump(exclude_none=True))
