import json
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Query, Request
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.errors import DomainError
from app.models import FindingRecord, ModelCall, ScanTask
from app.schemas.contracts import ScanCreate
from app.services.scans import change_scan, create_scan, require_scan, scan_view


def inline_schema(model):
    schema = model.model_json_schema()
    definitions = schema.pop("$defs", {})

    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                return visit(definitions[value["$ref"].split("/")[-1]])
            return {key: visit(item) for key, item in value.items()}
        return [visit(item) for item in value] if isinstance(value, list) else value

    return visit(schema)


def install_scan_routes(application, require_token):
    database = application.state.database_dependency
    auth = [Depends(require_token)]

    @application.post(
        "/api/v1/scans",
        status_code=202,
        dependencies=auth,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": inline_schema(ScanCreate)}},
            }
        },
    )
    async def create(request: Request, session: Annotated[Session, Depends(database)]):
        body = bytearray()
        async for part in request.stream():
            if len(body) + len(part) > 8192:
                raise DomainError("REQUEST_SIZE", "创建任务的请求过大。", 413)
            body.extend(part)
        try:
            data = ScanCreate.model_validate_json(body)
            key = request.headers.get("idempotency-key")
            if key is not None:
                key = str(UUID(key))
        except (ValidationError, ValueError):
            raise DomainError("INVALID_REQUEST", "任务请求或幂等键格式不正确。") from None
        scan_id = await run_in_threadpool(
            create_scan, request.app.state.engine, request.app.state.settings, data, key
        )
        scan = require_scan(session, scan_id)
        settings = request.app.state.settings
        return {"request_id": request.state.request_id, "scan": scan_view(session, scan, settings)}

    @application.get("/api/v1/scans", dependencies=auth)
    def history(
        request: Request,
        session: Annotated[Session, Depends(database)],
        limit: Annotated[int, Query(ge=1, le=50)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        scans = session.scalars(
            select(ScanTask)
            .order_by(ScanTask.created_at.desc(), ScanTask.id)
            .offset(offset)
            .limit(limit)
        ).all()
        total = session.scalar(select(func.count()).select_from(ScanTask))
        return {
            "request_id": request.state.request_id,
            "total": total,
            "scans": [scan_view(session, scan, request.app.state.settings) for scan in scans],
        }

    @application.get("/api/v1/scans/{scan_id}", dependencies=auth)
    def detail(scan_id: UUID, request: Request, session: Annotated[Session, Depends(database)]):
        return {
            "request_id": request.state.request_id,
            "scan": scan_view(
                session, require_scan(session, str(scan_id)), request.app.state.settings
            ),
        }

    @application.get("/api/v1/scans/{scan_id}/findings", dependencies=auth)
    def findings(
        scan_id: UUID,
        request: Request,
        session: Annotated[Session, Depends(database)],
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        attempt: Annotated[int | None, Query(ge=0, le=2)] = None,
    ):
        scan = require_scan(session, str(scan_id))
        chosen = scan.retries if attempt is None else attempt
        scope = (FindingRecord.scan_id == str(scan_id), FindingRecord.attempt == chosen)
        rows = session.scalars(
            select(FindingRecord)
            .where(*scope)
            .order_by(FindingRecord.position, FindingRecord.id)
            .offset(offset)
            .limit(limit)
        ).all()
        total = session.scalar(select(func.count()).select_from(FindingRecord).where(*scope))
        items = []
        for row in rows:
            payload = json.loads(row.payload)
            items.append(
                {
                    "id": row.id,
                    **payload["finding"],
                    "contributors": payload["contributors"],
                    "severity_disagreement": payload["severity_disagreement"],
                    "severity_policy": payload.get("severity_policy"),
                }
            )
        return {
            "request_id": request.state.request_id,
            "attempt": chosen,
            "total": total,
            "findings": items,
        }

    @application.post("/api/v1/scans/{scan_id}/cancel", dependencies=auth)
    def cancel(scan_id: UUID, request: Request, session: Annotated[Session, Depends(database)]):
        settings = request.app.state.settings
        change_scan(request.app.state.engine, settings, str(scan_id), "cancel")
        return {
            "request_id": request.state.request_id,
            "scan": scan_view(session, require_scan(session, str(scan_id)), settings),
        }

    @application.post("/api/v1/scans/{scan_id}/retry", status_code=202, dependencies=auth)
    def retry(scan_id: UUID, request: Request, session: Annotated[Session, Depends(database)]):
        settings = request.app.state.settings
        change_scan(request.app.state.engine, settings, str(scan_id), "retry")
        return {
            "request_id": request.state.request_id,
            "scan": scan_view(session, require_scan(session, str(scan_id)), settings),
        }

    @application.get("/api/v1/scans/{scan_id}/calls", dependencies=auth)
    def calls(scan_id: UUID, request: Request, session: Annotated[Session, Depends(database)]):
        require_scan(session, str(scan_id))
        rows = session.scalars(
            select(ModelCall)
            .where(ModelCall.scan_id == str(scan_id))
            .order_by(ModelCall.created_at)
        ).all()
        return {
            "request_id": request.state.request_id,
            "calls": [
                {
                    "id": row.id,
                    "model": row.model,
                    "status": row.status,
                    "duration_ms": row.duration_ms,
                    "input_chars": row.input_chars,
                    "output_bytes": row.output_bytes,
                    "input_tokens": row.input_tokens,
                    "output_tokens": row.output_tokens,
                    "failure_category": row.failure_category,
                }
                for row in rows
            ],
        }
