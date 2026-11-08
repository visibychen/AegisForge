import secrets
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.artifacts import install_artifact_routes
from app.api.repairs import install_repair_routes
from app.api.scans import install_scan_routes
from app.core.config import Settings
from app.core.errors import DomainError
from app.schemas.contracts import CapabilitiesResponse, ErrorResponse, HealthResponse


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    application = FastAPI(title="AegisForge API", version=__version__)
    application.state.settings = settings
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
        expose_headers=["X-Request-ID"],
    )

    @application.middleware("http")
    async def request_identity(request: Request, call_next):
        request.state.request_id = str(uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    def error_response(request: Request, status: int, code: str, message: str, headers=None):
        return JSONResponse(
            status_code=status,
            content={
                "request_id": request.state.request_id,
                "error": {"code": code, "message": message},
            },
            headers=headers,
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exception: StarletteHTTPException):
        if isinstance(exception.detail, dict):
            code = exception.detail["code"]
            message = exception.detail["message"]
        else:
            code, message = "HTTP_ERROR", "请求的资源或方法不可用。"
        return error_response(request, exception.status_code, code, message, exception.headers)

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _exception: RequestValidationError):
        # Do not echo submitted content, secrets, or validation input back to the client.
        return error_response(request, 422, "INVALID_REQUEST", "请求参数格式不正确。")

    @application.exception_handler(DomainError)
    async def domain_error(request: Request, exception: DomainError):
        return error_response(request, exception.status, exception.code, exception.message)

    @application.exception_handler(Exception)
    async def unexpected_error(request: Request, _exception: Exception):
        return error_response(
            request,
            500,
            "INTERNAL_ERROR",
            "服务发生内部错误。",
            headers={"X-Request-ID": request.state.request_id, "Cache-Control": "no-store"},
        )

    bearer = HTTPBearer(auto_error=False)

    def require_token(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> None:
        token = settings.api_token.get_secret_value()
        if not token:
            raise HTTPException(
                503, detail={"code": "SERVICE_NOT_CONFIGURED", "message": "服务尚未配置访问令牌。"}
            )
        if credentials is None or not secrets.compare_digest(
            credentials.credentials.encode("utf-8"), token.encode("utf-8")
        ):
            raise HTTPException(
                401,
                detail={"code": "UNAUTHORIZED", "message": "访问令牌无效或缺失。"},
                headers={"WWW-Authenticate": "Bearer"},
            )

    @application.get("/health", response_model=HealthResponse, tags=["system"])
    def health(request: Request):
        return HealthResponse(request_id=request.state.request_id)

    @application.get(
        "/api/v1/capabilities",
        response_model=CapabilitiesResponse,
        dependencies=[Depends(require_token)],
        responses={401: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
        tags=["system"],
    )
    def capabilities(request: Request):
        return CapabilitiesResponse(
            request_id=request.state.request_id,
            version=__version__,
            max_file_bytes=settings.max_file_bytes,
            max_files=settings.max_files,
            max_total_bytes=settings.max_total_bytes,
            model_mode=settings.model_mode,
            model_aliases=settings.model_aliases,
        )

    install_artifact_routes(application, require_token)
    install_scan_routes(application, require_token)
    install_repair_routes(application, require_token)
    return application


app = create_app()
