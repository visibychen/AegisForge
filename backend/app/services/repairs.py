import asyncio
import contextlib
import json
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.llm.deepseek import DeepSeekProvider
from app.llm.repair import REPAIR_PROMPT_VERSION, RepairProvider
from app.models import Artifact, FindingRecord, Job, ModelCall, Repair, ScanTask
from app.parsers.inputs import parse_input
from app.rules.detector import detect
from app.schemas.contracts import AnalysisRequest
from app.services.artifacts import load_artifact, store_artifact
from app.services.patches import Edit, RepairWire, apply_edits
from app.services.queue import Lease, capacity, model_usage, transaction, utcnow, with_db_retry
from app.services.receipts import canonical, digest


def require_repair(session, repair_id):
    item = session.get(Repair, repair_id)
    if item is None:
        raise DomainError("REPAIR_NOT_FOUND", "候选修复不存在。", 404)
    return item


def finding_anchor(scan, artifact, finding):
    return digest(
        {
            "source": artifact.sha256,
            "finding": json.loads(finding.payload),
            "plan": json.loads(scan.plan_json).get("plan_digest"),
            "attempt": finding.attempt,
        }
    )


def repair_source(settings, artifact):
    if artifact.input_type != "source":
        raise DomainError("source_required", "HTTP 请求缺少源码，无法生成源码补丁。", 422)
    parsed = load_artifact(settings, artifact)
    if len(parsed.chunks) != 1 or len(parsed.content) > 12000:
        raise DomainError("REPAIR_INPUT_BUDGET", "首版修复仅接受单块源码。", 422)
    if "[REDACTED]" in parsed.content:
        raise DomainError("REPAIR_SENSITIVE_SOURCE", "请先移除源码凭据再申请自动修复。", 422)
    return parsed


def create_repair(engine, settings, finding_id, sha256, alias, key):
    if alias not in settings.model_aliases:
        raise DomainError("MODEL_NOT_AVAILABLE", "所选模型未配置。", 422)
    with transaction(engine) as session:
        prior = session.scalar(select(Job).where(Job.idempotency_key == "repair:" + key))
        if prior:
            item = session.scalar(select(Repair).where(Repair.job_id == prior.id))
            if (item.finding_id, item.source_sha256, item.model_alias) != (
                finding_id,
                sha256,
                alias,
            ):
                raise DomainError("IDEMPOTENCY_CONFLICT", "幂等键与先前请求不一致。", 409)
            return item.id
        finding = session.get(FindingRecord, finding_id)
        if finding is None:
            raise DomainError("FINDING_NOT_FOUND", "发现不存在。", 404)
        scan, artifact = (
            session.get(ScanTask, finding.scan_id),
            session.get(Artifact, finding.artifact_id),
        )
        repair_source(settings, artifact)
        if (
            artifact.sha256 != sha256
            or finding.attempt != scan.retries
            or scan.status not in {"completed", "partial"}
        ):
            raise DomainError("REPAIR_STALE", "发现或源快照已变化，请重新检测。", 409)
        capacity(session, settings)
        job = Job(id=str(uuid4()), scan_id=scan.id, kind="repair", idempotency_key="repair:" + key)
        item = Repair(
            id=str(uuid4()),
            scan_id=scan.id,
            finding_id=finding.id,
            source_id=artifact.id,
            job_id=job.id,
            source_sha256=sha256,
            anchor=finding_anchor(scan, artifact, finding),
            model_alias=alias,
            model_name=settings.deepseek_model,
        )
        session.add(job)
        session.flush()
        session.add(item)
        return item.id


def repair_view(session, item):
    calls = session.scalars(select(ModelCall).where(ModelCall.job_id == item.job_id)).all()
    checks, dynamic = json.loads(item.checks_json), json.loads(item.dynamic_json)
    verdict = "unverified"
    if item.status == "failed" or checks.get("target_remaining") or checks.get("new_findings"):
        verdict = "failed"
    if dynamic.get("status") == "error":
        verdict = "error"
    elif dynamic.get("status") == "failed":
        verdict = "failed"
    elif (
        dynamic.get("status") == "passed"
        and checks.get("llm_complete")
        and checks.get("static_passed")
    ):
        verdict = "passed"
    return {
        "id": item.id,
        "scan_id": item.scan_id,
        "finding_id": item.finding_id,
        "source_id": item.source_id,
        "source_sha256": item.source_sha256,
        "anchor": item.anchor,
        "candidate_id": item.candidate_id,
        "model_alias": item.model_alias,
        "model": item.model_name,
        "status": item.status,
        "error_code": item.error_code,
        "diff": item.diff,
        "checks": checks,
        "dynamic": dynamic,
        "dynamic_requested": item.dynamic_requested,
        "validation_status": verdict,
        "call_count": len(calls),
        "prompt_version": REPAIR_PROMPT_VERSION,
        "calls": [
            {
                "status": c.status,
                "duration_ms": c.duration_ms,
                "input_tokens": c.input_tokens,
                "output_tokens": c.output_tokens,
                "prompt_version": c.prompt_version,
            }
            for c in calls
        ],
    }


def claim_repair(engine, settings):
    at = utcnow()
    with transaction(engine) as session:
        for job in session.scalars(
            select(Job).where(Job.kind == "repair", Job.status == "running", Job.lease_until <= at)
        ):
            item = session.scalar(select(Repair).where(Repair.job_id == job.id))
            job.lease_token = None
            if item.cancel_requested or job.attempts >= 3:
                job.status = item.status = "cancelled" if item.cancel_requested else "failed"
                item.error_code = None if item.cancel_requested else "LEASE_EXHAUSTED"
            else:
                job.status, item.status = "queued", "queued"
        job = session.scalar(
            select(Job)
            .where(Job.kind == "repair", Job.status == "queued")
            .order_by(Job.created_at)
            .limit(1)
        )
        if job is None:
            return None
        item = session.scalar(select(Repair).where(Repair.job_id == job.id))
        job.status, item.status, job.lease_token = "running", "running", str(uuid4())
        job.attempts += 1
        job.lease_until = at + timedelta(seconds=settings.lease_seconds)
        item.started_at = item.started_at or at
        return Lease(job.id, job.scan_id, job.lease_token)


def active_repair(session, lease, allow_cancel=False):
    job = session.get(Job, lease.job_id)
    item = session.scalar(select(Repair).where(Repair.job_id == lease.job_id))
    if job.status != "running" or job.lease_token != lease.token or job.lease_until <= utcnow():
        raise DomainError("LEASE_LOST", "修复租约失效。", 409)
    if item.cancel_requested and not allow_cancel:
        raise DomainError("TASK_CANCELLED", "修复已取消。", 409)
    return job, item


class RepairLedger:
    def __init__(self, engine, settings, lease, version):
        self.engine, self.settings, self.lease, self.version = engine, settings, lease, version

    def reserve(self, chars):
        with transaction(self.engine) as session:
            active_repair(session, self.lease)
            scan_used, daily = model_usage(session, self.settings, self.lease.scan_id)
            used = session.scalar(
                select(func.count())
                .select_from(ModelCall)
                .where(ModelCall.job_id == self.lease.job_id)
            )
            if (
                used >= 8
                or scan_used >= self.settings.max_model_calls
                or daily >= self.settings.daily_model_calls
            ):
                raise DomainError("MODEL_CALL_BUDGET", "修复或服务器模型预算已耗尽。", 409)
            call = ModelCall(
                scan_id=self.lease.scan_id,
                job_id=self.lease.job_id,
                model=self.settings.deepseek_model,
                prompt_version=self.version,
                input_chars=chars,
            )
            session.add(call)
            session.flush()
            return call.id

    def finish(self, call_id, status, duration, size, usage, category=None):
        with transaction(self.engine) as session:
            call = session.get(ModelCall, call_id)
            call.status, call.duration_ms, call.output_bytes, call.failure_category = (
                status,
                duration,
                size,
                category,
            )
            call.input_tokens, call.output_tokens = (
                usage.get("prompt_tokens"),
                usage.get("completion_tokens"),
            )


async def execute_repair(engine, settings, lease, factory=None):
    try:
        with Session(engine) as session:
            _, item = active_repair(session, lease)
            scan, source, finding = (
                session.get(ScanTask, item.scan_id),
                session.get(Artifact, item.source_id),
                session.get(FindingRecord, item.finding_id),
            )
            parsed = repair_source(settings, source)
            if (
                item.anchor != finding_anchor(scan, source, finding)
                or finding.attempt != scan.retries
            ):
                raise DomainError("REPAIR_STALE", "发现锚点已变化，请重新检测。", 409)
            if item.model_name != settings.deepseek_model:
                raise DomainError("ANALYSIS_CONFIG_CHANGED", "修复模型配置已变化。", 409)
            target = json.loads(finding.payload)["finding"]
            remaining = settings.task_timeout_seconds - (utcnow() - item.started_at).total_seconds()
            simulated = item.model_alias == "fake"
        if remaining <= 0:
            raise TimeoutError
        async with asyncio.timeout(remaining):
            req = AnalysisRequest(
                artifact_id=source.id,
                input_type="source",
                content=parsed.content,
                start_line=1,
                end_line=len(parsed.content.splitlines()),
            )
            ledger = RepairLedger(engine, settings, lease, REPAIR_PROMPT_VERSION)
            provider = (
                factory(settings, ledger)
                if factory
                else RepairProvider(settings, ledger.reserve, ledger.finish)
            )
            if simulated:
                wire = RepairWire(
                    schema_version="repair-1.0",
                    edits=[
                        Edit(
                            start_line=1,
                            end_line=len(parsed.content.splitlines()),
                            old_text=parsed.content,
                            new_text=parsed.content,
                        )
                    ],
                    explanation="模拟流程，未生成真实修复。",
                )
            else:
                wire = await provider.generate(
                    req, {k: target[k] for k in ("cwe", "location", "evidence")}
                )
            candidate, diff = apply_edits(parsed.content, wire.edits)
            after = parse_input("source", candidate)
            before_rules, after_rules = (
                detect(UUID(source.id), "source", parsed),
                detect(UUID(source.id), "source", after),
            )
            target_remaining = any(f.cwe == target["cwe"] for f in after_rules.findings)
            before_cwes = {f.cwe for f in before_rules.findings}
            checks = {
                "syntax": "passed",
                "patch": "passed",
                "mode": "fake" if simulated else "real",
                "target_remaining": target_remaining,
                "llm_complete": False,
                "before": [f.model_dump(mode="json") for f in before_rules.findings],
                "after_rules": [f.model_dump(mode="json") for f in after_rules.findings],
                "new_findings": [
                    f.model_dump(mode="json")
                    for f in after_rules.findings
                    if f.cwe not in before_cwes
                ],
                "explanation": wire.explanation,
            }
            if not simulated:
                ledger.version = "analysis-1.1"
                reviewer = (
                    factory(settings, ledger)
                    if factory
                    else DeepSeekProvider(settings, ledger.reserve, ledger.finish)
                )
                reviewed = await reviewer.analyze(
                    req.model_copy(
                        update={"content": candidate, "end_line": len(candidate.splitlines())}
                    )
                )
                checks["llm_complete"] = reviewed.analysis_complete and reviewed.mode == "real"
                checks["after_llm"] = [f.model_dump(mode="json") for f in reviewed.findings]
                checks["target_remaining"] |= any(f.cwe == target["cwe"] for f in reviewed.findings)
                checks["new_findings"].extend(
                    f.model_dump(mode="json") for f in reviewed.findings if f.cwe not in before_cwes
                )
            checks["static_passed"] = (
                not checks["target_remaining"]
                and not checks["new_findings"]
                and checks["llm_complete"]
            )
        with transaction(engine) as session:
            job, item = active_repair(session, lease)
            # Recheck anchor immediately before publishing the immutable candidate.
            if item.anchor != finding_anchor(
                session.get(ScanTask, item.scan_id),
                session.get(Artifact, item.source_id),
                session.get(FindingRecord, item.finding_id),
            ):
                raise DomainError("REPAIR_STALE", "发现锚点已变化。", 409)
            candidate_preview = store_artifact(
                session, settings, "candidate.py", "source", candidate.encode(), commit=False
            )
            item.candidate_id, item.diff = candidate_preview["id"], diff
            item.edits_json, item.checks_json = (
                canonical(wire.model_dump(mode="json")["edits"]),
                canonical(checks),
            )
            item.status, item.finished_at, job.status = "candidate", utcnow(), "completed"
            job.lease_token, job.lease_until = None, None
    except Exception as error:
        if isinstance(error, DomainError) and error.code == "LEASE_LOST":
            return
        with contextlib.suppress(Exception), transaction(engine) as session:
            job, item = active_repair(session, lease, allow_cancel=True)
            item.status = "cancelled" if item.cancel_requested else "failed"
            item.error_code = (
                None
                if item.cancel_requested
                else error.code
                if isinstance(error, DomainError)
                else "TASK_TIMEOUT"
                if isinstance(error, TimeoutError)
                else "REPAIR_INTERNAL"
            )
            item.finished_at, job.status, job.lease_token, job.lease_until = (
                utcnow(),
                item.status,
                None,
                None,
            )


async def run_repair_once(engine, settings, factory=None):
    lease = with_db_retry(claim_repair, engine, settings)
    if lease is None:
        return False
    work = asyncio.create_task(execute_repair(engine, settings, lease, factory))

    async def pulse():
        while not work.done():
            await asyncio.sleep(1)
            with transaction(engine) as session:
                job, item = active_repair(session, lease, allow_cancel=True)
                if item.cancel_requested:
                    work.cancel()
                    return
                job.lease_until = utcnow() + timedelta(seconds=settings.lease_seconds)

    monitor = asyncio.create_task(pulse())
    try:
        await work
    except asyncio.CancelledError:
        if asyncio.current_task().cancelling():
            raise
        with contextlib.suppress(Exception), transaction(engine) as session:
            job, item = active_repair(session, lease, allow_cancel=True)
            if item.cancel_requested:
                item.status, job.status, job.lease_token = "cancelled", "cancelled", None
    finally:
        monitor.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await monitor
    return True
