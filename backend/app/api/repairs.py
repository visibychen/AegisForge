import json
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.errors import DomainError
from app.models import Artifact, Job, Repair
from app.services.artifacts import load_artifact
from app.services.queue import transaction, utcnow
from app.services.receipts import canonical
from app.services.repairs import create_repair, repair_view, require_repair


class RepairRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: UUID
    source_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    model_alias: str = Field(pattern="^(fake|deepseek)$")


def install_repair_routes(app, require_token):
    database = app.state.database_dependency
    auth = [Depends(require_token)]

    @app.post("/api/v1/repairs", status_code=202, dependencies=auth)
    async def create(request: Request):
        body = bytearray()
        async for part in request.stream():
            body.extend(part)
            if len(body) > 4096:
                raise DomainError("REQUEST_SIZE", "修复请求过大。", 413)
        try:
            data = RepairRequest.model_validate_json(body)
            key = str(UUID(request.headers.get("idempotency-key", "")))
        except (ValidationError, ValueError):
            raise DomainError("INVALID_REQUEST", "修复请求或幂等键格式不正确。", 422) from None
        repair_id = await run_in_threadpool(
            create_repair,
            app.state.engine,
            app.state.settings,
            str(data.finding_id),
            data.source_sha256,
            data.model_alias,
            key,
        )
        with Session(app.state.engine) as session:
            return {"repair": repair_view(session, require_repair(session, repair_id))}

    @app.get("/api/v1/repairs", dependencies=auth)
    def history(scan_id: UUID, session: Annotated[Session, Depends(database)]):
        rows = session.scalars(
            select(Repair)
            .where(Repair.scan_id == str(scan_id))
            .order_by(Repair.created_at.desc())
            .limit(20)
        )
        return {"repairs": [repair_view(session, r) for r in rows]}

    @app.get("/api/v1/repairs/{repair_id}", dependencies=auth)
    def detail(repair_id: UUID, session: Annotated[Session, Depends(database)]):
        return {"repair": repair_view(session, require_repair(session, str(repair_id)))}

    @app.post("/api/v1/repairs/{repair_id}/cancel", dependencies=auth)
    def cancel(repair_id: UUID):
        with transaction(app.state.engine) as session:
            item = require_repair(session, str(repair_id))
            if item.status in {"queued", "running"}:
                item.cancel_requested = True
                if item.status == "queued":
                    item.status, session.get(Job, item.job_id).status = "cancelled", "cancelled"
                    item.finished_at = utcnow()
            else:
                # Candidate already exists: this cancels a pending/running dynamic validation.
                dynamic = json.loads(item.dynamic_json)
                if dynamic.get("status") == "pending":
                    item.dynamic_requested = False
                    item.dynamic_json = canonical({**dynamic, "status": "cancelled"})
                elif dynamic.get("status") == "running":
                    item.dynamic_json = canonical({**dynamic, "cancel_requested": True})
            return {"repair": repair_view(session, item)}

    @app.get("/api/v1/repairs/{repair_id}/download", dependencies=auth)
    def download(
        repair_id: UUID, session: Annotated[Session, Depends(database)], format: str = "diff"
    ):
        item = require_repair(session, str(repair_id))
        if item.candidate_id is None or item.status != "candidate":
            raise DomainError("CANDIDATE_NOT_READY", "候选尚未生成或已失效。", 409)
        if format not in {"diff", "source"}:
            raise DomainError("INVALID_REQUEST", "下载格式不支持。", 422)
        content = (
            item.diff
            if format == "diff"
            else load_artifact(app.state.settings, session.get(Artifact, item.candidate_id)).content
        )
        return PlainTextResponse(
            content,
            headers={
                "Content-Disposition": 'attachment; filename="'
                + ("repair.patch" if format == "diff" else "candidate.py")
                + '"'
            },
        )

    @app.post("/api/v1/repairs/{repair_id}/validate", status_code=202, dependencies=auth)
    def validate(repair_id: UUID):
        from app.validation.registry import match_case

        with transaction(app.state.engine) as session:
            item = require_repair(session, str(repair_id))
            if item.status != "candidate":
                raise DomainError("CANDIDATE_NOT_READY", "候选尚未生成。", 409)
            match_case(item.source_sha256)
            if json.loads(item.dynamic_json).get("status") in {"pending", "running"}:
                raise DomainError("VALIDATION_IN_PROGRESS", "受控动态验证正在进行。", 409)
            item.dynamic_requested = True
            item.dynamic_json = canonical(
                {"status": "pending", "requested_at": utcnow().isoformat()}
            )
            return {"repair": repair_view(session, item)}
