from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class APIError(BaseModel):
    error: str
    detail: str
    code: str


class AppError(Exception):
    def __init__(self, message: str, code: str = "app_error", status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


async def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=APIError(error=exc.message, detail=exc.message, code=exc.code).model_dump(),
    )


async def http_error_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content=APIError(error=detail, detail=detail, code="http_error").model_dump(),
    )


async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=APIError(
            error="Internal server error",
            detail="An unexpected error occurred. Details were logged server-side.",
            code="internal_error",
        ).model_dump(),
    )
