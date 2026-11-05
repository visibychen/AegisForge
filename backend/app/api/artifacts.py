from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.database import build_engine
from app.core.errors import DomainError
from app.models import Artifact
from app.services.artifacts import preview, store_artifact


def install_artifact_routes(application, require_token):
    def database(request: Request):
        if not hasattr(request.app.state, "engine"):
            request.app.state.engine = build_engine(request.app.state.settings)
        with Session(request.app.state.engine) as session:
            yield session

    application.state.database_dependency = database

    @application.post("/api/v1/artifacts", status_code=201, dependencies=[Depends(require_token)])
    async def upload(
        request: Request,
        filename: str,
        input_type: Literal["source", "http"],
        session: Annotated[Session, Depends(database)],
    ):
        settings = request.app.state.settings
        declared = request.headers.get("content-length", "")
        if declared and (not declared.isascii() or not declared.isdecimal()):
            raise DomainError("INVALID_LENGTH", "Content-Length 格式无效。", 400)
        if declared and (len(declared) > 10 or int(declared) > settings.max_file_bytes):
            raise DomainError("FILE_SIZE", "超过单文件大小限制。", 413)
        body = bytearray()
        async for part in request.stream():
            if len(body) + len(part) > settings.max_file_bytes:
                raise DomainError("FILE_SIZE", "超过单文件大小限制。", 413)
            body.extend(part)
        # Parsing, redaction and rules are CPU-bound; keep them off the event loop.
        payload = await run_in_threadpool(
            store_artifact, session, settings, filename, input_type, bytes(body)
        )
        return {"request_id": request.state.request_id, "artifact": payload}

    @application.get("/api/v1/artifacts/{artifact_id}", dependencies=[Depends(require_token)])
    def read(artifact_id: UUID, request: Request, session: Annotated[Session, Depends(database)]):
        artifact = session.get(Artifact, str(artifact_id))
        if artifact is None:
            raise DomainError("ARTIFACT_NOT_FOUND", "输入快照不存在。", 404)
        return {
            "request_id": request.state.request_id,
            "artifact": preview(request.app.state.settings, artifact),
        }
