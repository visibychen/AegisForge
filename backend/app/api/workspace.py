"""Workspace API: overview, lightweight history, logical removal and source-free reports.

Removal only takes a scan out of history. Budget/audit rows and shared input snapshots are kept
(an input stays previewable by its id through the artifact endpoint); nothing is erased.
"""

import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.models import Repair
from app.services.queue import transaction, utcnow
from app.services.reports import build_report, render_markdown
from app.services.scans import require_scan
from app.services.workspace import history_page, overview


def install_workspace_routes(app, require_token):
    database = app.state.database_dependency
    auth = [Depends(require_token), Depends(database)]  # also makes sure app.state.engine exists

    @app.get("/api/v1/workspace", dependencies=auth)
    def summary(session: Annotated[Session, Depends(database)]):
        return overview(session)

    @app.get("/api/v1/workspace/history", dependencies=auth)
    def history(
        session: Annotated[Session, Depends(database)],
        status: Literal[
            "all", "queued", "running", "completed", "partial", "failed", "cancelled"
        ] = "all",
        q: Annotated[str, Query(max_length=64)] = "",
        cwe: Literal["CWE-79", "CWE-89", "CWE-78"] | None = None,
        severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=50)] = 10,
    ):
        return history_page(
            session, status=status, q=q, cwe=cwe, severity=severity, offset=offset, limit=limit
        )

    @app.post("/api/v1/workspace/{scan_id}/delete", dependencies=auth)
    def delete(scan_id: UUID):
        with transaction(app.state.engine) as session:
            scan = require_scan(session, str(scan_id))
            repairs = session.scalars(select(Repair).where(Repair.scan_id == scan.id)).all()
            if scan.status in {"queued", "running"} or any(
                r.status in {"queued", "running"}
                or r.dynamic_requested
                or json.loads(r.dynamic_json).get("status") in {"pending", "running"}
                for r in repairs
            ):
                raise DomainError("TASK_ACTIVE", "请先取消检测、修复或动态验证，再移出历史。", 409)
            scan.deleted_at = utcnow()
        return {
            "deleted": True,
            "scan_id": str(scan_id),
            "retained": "仅移出历史并停止访问其任务、发现与修复；调用预算审计保留，输入快照仍可"
            "按其编号预览，这不是文件擦除。",
        }

    @app.get("/api/v1/workspace/{scan_id}/report", dependencies=auth)
    def report(
        scan_id: UUID,
        session: Annotated[Session, Depends(database)],
        format: Literal["json", "markdown"] = "json",
    ):
        session.execute(sql_text("BEGIN"))  # explicit SQLite read snapshot, before the first SELECT
        scan = require_scan(session, str(scan_id))
        data = build_report(session, scan)
        extension = "json" if format == "json" else "md"
        text = (
            json.dumps(data, ensure_ascii=False, indent=2)
            if format == "json"
            else render_markdown(data)
        )
        return Response(
            text,
            media_type="application/json" if format == "json" else "text/markdown",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="aegisforge-report-{str(scan_id)[:8]}.{extension}"'
                ),
                "Cache-Control": "no-store",
            },
        )
