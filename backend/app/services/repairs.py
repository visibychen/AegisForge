import asyncio
import contextlib
import hashlib
import json
import time
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.llm.deepseek import DeepSeekProvider
from app.llm.prompts import PROMPT_VERSION
from app.llm.repair import REPAIR_PROMPT_VERSION, RepairProvider
from app.models import Artifact, FindingRecord, Job, ModelCall, Repair, ScanTask
from app.parsers.inputs import parse_input
from app.rules.detector import detect
from app.schemas.contracts import AnalysisRequest
from app.services.artifacts import load_artifact, store_artifact
from app.services.patch_review import (
    PatchScopeError,
    build_gates,
    build_line_map,
    finding_delta,
    locations,
    review_structure,
    summarize,
    verdict_for,
)
from app.services.patches import Edit, RepairWire, apply_edits
from app.services.queue import (
    Lease,
    capacity,
    model_usage,
    transaction,
    utcnow,
    with_db_retry,
)
from app.services.receipts import canonical, digest
from app.services.repair_contract import capture_contract, seal_contract
from app.validation.registry import dynamic_binding

MAX_REPAIRS_PER_FINDING = 3
MAX_CALLS_PER_REPAIR = 8
MIN_CALLS_PER_REPAIR = 2  # one generation plus one model recheck
PASS_THROUGH = {"LEASE_LOST", "TASK_CANCELLED"}


def require_repair(session, repair_id):
    """Single choke point: a repair of a removed (logically deleted) scan does not exist."""
    item = session.get(Repair, repair_id)
    scan = session.get(ScanTask, item.scan_id) if item is not None else None
    if item is None or scan is None or scan.deleted_at is not None:
        raise DomainError("REPAIR_NOT_FOUND", "候选修复不存在或其检测任务已移出历史。", 404)
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


def ensure_fresh(item, scan, artifact, finding):
    """The repair is only meaningful for the exact finding, snapshot and *current* analysis."""
    if (
        scan is None
        or scan.deleted_at is not None
        or artifact is None
        or finding is None
        or scan.status not in {"completed", "partial"}
        or finding.attempt != scan.retries
        or artifact.sha256 != item.source_sha256
        or item.anchor != finding_anchor(scan, artifact, finding)
    ):
        raise DomainError("REPAIR_STALE", "发现、源快照或父检测任务已变化，请重新检测。", 409)


def repair_source(settings, artifact):
    if artifact.input_type != "source":
        raise DomainError("source_required", "HTTP 请求缺少源码，无法生成源码补丁。", 422)
    parsed = load_artifact(settings, artifact)
    if len(parsed.chunks) != 1 or len(parsed.content) > 12000:
        raise DomainError("REPAIR_INPUT_BUDGET", "首版修复仅接受单块源码。", 422)
    if "[REDACTED]" in parsed.content:
        raise DomainError("REPAIR_SENSITIVE_SOURCE", "请先移除源码凭据再申请自动修复。", 422)
    return parsed


def baseline_for(session, scan, artifact, attempt=None) -> list[tuple]:
    """Findings reported for this snapshot by the parent analysis (rules and model alike)."""
    rows = session.scalars(
        select(FindingRecord).where(
            FindingRecord.scan_id == scan.id,
            FindingRecord.attempt == (scan.retries if attempt is None else attempt),
            FindingRecord.artifact_id == artifact.id,
        )
    )
    baseline = []
    for row in rows:
        finding = json.loads(row.payload)["finding"]
        baseline.extend(locations([finding], "parent:" + "+".join(finding.get("sources", []))))
    return baseline


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
            # Reusing a key must never resurrect a repair of a removed scan.
            require_repair(session, item.id)
            return item.id
        finding = session.get(FindingRecord, finding_id)
        scan = session.get(ScanTask, finding.scan_id) if finding is not None else None
        if finding is None or scan is None or scan.deleted_at is not None:
            raise DomainError("FINDING_NOT_FOUND", "发现不存在或其检测任务已移出历史。", 404)
        artifact = session.get(Artifact, finding.artifact_id)
        repair_source(settings, artifact)
        if (
            artifact.sha256 != sha256
            or finding.attempt != scan.retries
            or scan.status not in {"completed", "partial"}
        ):
            raise DomainError("REPAIR_STALE", "发现或源快照已变化，请重新检测。", 409)
        existing = session.scalars(select(Repair).where(Repair.finding_id == finding.id)).all()
        running = next((r for r in existing if r.status in {"queued", "running"}), None)
        if running is not None:
            if (running.source_sha256, running.model_alias) == (sha256, alias):
                return running.id  # one live candidate per finding; do not pay twice
            raise DomainError("REPAIR_IN_PROGRESS", "该发现已有进行中的修复。", 409)
        if len(existing) >= MAX_REPAIRS_PER_FINDING:
            raise DomainError("REPAIR_LIMIT", "同一发现最多生成 3 个候选修复。", 409)
        if alias != "fake":
            scan_used, daily_used = model_usage(session, settings, scan.id)
            if settings.max_model_calls - scan_used < MIN_CALLS_PER_REPAIR:
                raise DomainError(
                    "REPAIR_BUDGET", "本任务剩余模型调用预算不足以完成修复与复检。", 409
                )
            if settings.daily_model_calls - daily_used < MIN_CALLS_PER_REPAIR:
                raise DomainError("MODEL_DAILY_BUDGET", "今日服务器模型调用次数不足。", 429)
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


def evaluate_repair(session, item):
    """(checks, dynamic record, gate ledger, verdict) shared by detail views and aggregates."""
    checks, dynamic = json.loads(item.checks_json), json.loads(item.dynamic_json)
    candidate = session.get(Artifact, item.candidate_id) if item.candidate_id else None
    binding = dynamic_binding(item.source_sha256, dynamic, candidate.sha256 if candidate else None)
    gates = build_gates(checks, dynamic, binding)
    return checks, dynamic, gates, verdict_for(item.status, item.error_code, checks, gates)


def repair_view(session, item):
    calls = session.scalars(select(ModelCall).where(ModelCall.job_id == item.job_id)).all()
    checks, dynamic, gates, verdict = evaluate_repair(session, item)
    finding = session.get(FindingRecord, item.finding_id)
    scan = session.get(ScanTask, item.scan_id)
    return {
        "finding_attempt": finding.attempt if finding else None,
        "archived": finding is None or scan is None or finding.attempt != scan.retries,
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
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "diff": item.diff,
        "checks": checks,
        "impact": checks.get("impact"),
        "gates": gates,
        "simulated": checks.get("mode") == "fake",
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
            for call in session.scalars(
                select(ModelCall).where(ModelCall.job_id == job.id, ModelCall.status == "started")
            ):
                call.status = "interrupted"
            job.lease_token, job.lease_until = None, None
            if item.cancel_requested or job.attempts >= 3:
                job.status = item.status = "cancelled" if item.cancel_requested else "failed"
                item.error_code = None if item.cancel_requested else "LEASE_EXHAUSTED"
                item.finished_at = at
            else:
                job.status, item.status = "queued", "queued"
        session.flush()
        while True:
            job = session.scalar(
                select(Job)
                .where(Job.kind == "repair", Job.status == "queued")
                .order_by(Job.created_at, Job.id)
                .limit(1)
            )
            if job is None:
                return None
            item = session.scalar(select(Repair).where(Repair.job_id == job.id))
            scan = session.get(ScanTask, item.scan_id)
            if scan is not None and scan.deleted_at is None:
                break
            # Defence in depth: a queued repair of a removed scan is never executed or paid for.
            job.status = item.status = "cancelled"
            item.error_code, item.finished_at = "SCAN_REMOVED", at
            session.flush()
        job.status, item.status, job.lease_token = "running", "running", str(uuid4())
        job.attempts += 1
        job.heartbeat_at = at
        job.lease_until = at + timedelta(seconds=settings.lease_seconds)
        # Anchored at the first start, like scans: elapsed time includes recovery pauses so a
        # crash loop cannot extend the total time limit.
        item.started_at = item.started_at or at
        return Lease(job.id, job.scan_id, job.lease_token)


def active_repair(session, lease, allow_cancel=False):
    job = session.get(Job, lease.job_id)
    item = session.scalar(select(Repair).where(Repair.job_id == lease.job_id))
    if (
        job is None
        or item is None
        or job.status != "running"
        or job.lease_token != lease.token
        or job.lease_until is None
        or job.lease_until <= utcnow()
    ):
        raise DomainError("LEASE_LOST", "修复租约失效。", 409)
    if item.cancel_requested and not allow_cancel:
        raise DomainError("TASK_CANCELLED", "修复已取消。", 409)
    return job, item


def heartbeat_repair(engine, settings, lease) -> bool:
    with transaction(engine) as session:
        job, item = active_repair(session, lease, allow_cancel=True)
        job.heartbeat_at = utcnow()
        job.lease_until = job.heartbeat_at + timedelta(seconds=settings.lease_seconds)
        return item.cancel_requested


class RepairLedger:
    def __init__(self, engine, settings, lease, version):
        self.engine, self.settings, self.lease, self.version = engine, settings, lease, version

    def reserve(self, chars):
        return with_db_retry(self._reserve, chars)

    def _reserve(self, chars):
        with transaction(self.engine) as session:
            active_repair(session, self.lease)
            scan_used, daily = model_usage(session, self.settings, self.lease.scan_id)
            used = session.scalar(
                select(func.count())
                .select_from(ModelCall)
                .where(ModelCall.job_id == self.lease.job_id)
            )
            if (
                used >= MAX_CALLS_PER_REPAIR
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
        with_db_retry(self._finish, call_id, status, duration, size, usage, category)

    def _finish(self, call_id, status, duration, size, usage, category):
        with transaction(self.engine) as session:
            call = session.get(ModelCall, call_id)
            if call is None:
                return
            call.status, call.duration_ms, call.output_bytes = status, duration, size
            call.failure_category = category
            call.input_tokens, call.output_tokens = (
                usage.get("prompt_tokens"),
                usage.get("completion_tokens"),
            )


def store_candidate(engine, settings, lease, wire, candidate, diff, checks, *, final):
    """Persist the candidate (phase 1, still running) or finalize it (phase 2 / fake)."""
    with transaction(engine) as session:
        job, item = active_repair(session, lease)
        ensure_fresh(
            item,
            session.get(ScanTask, item.scan_id),
            session.get(Artifact, item.source_id),
            session.get(FindingRecord, item.finding_id),
        )
        sha = hashlib.sha256(candidate.encode()).hexdigest()
        prior = session.get(Artifact, item.candidate_id) if item.candidate_id else None
        if prior is not None and prior.sha256 == sha:
            load_artifact(settings, prior)
            candidate_id = prior.id
        else:
            candidate_id = store_artifact(
                session, settings, "candidate.py", "source", candidate.encode(), commit=False
            )["id"]
        if "contract" in checks:
            checks["contract"] = seal_contract(
                {
                    **checks["contract"],
                    "candidate_sha256": sha,
                    "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
                }
            )
        item.candidate_id, item.diff = candidate_id, diff
        item.edits_json = canonical(wire.model_dump(mode="json")["edits"])
        item.checks_json = canonical(checks)
        if final:
            item.status, item.error_code, item.finished_at = "candidate", None, utcnow()
            job.status, job.lease_token, job.lease_until = "completed", None, None


PATCH_DIAGNOSTIC_CATEGORIES = {"patch_conflict", "patch_range", "patch_newline"}


def target_location(target) -> tuple:
    location = target["location"]
    return target["cwe"], location["start_line"], location["end_line"]


async def execute_repair(engine, settings, lease, factory=None):
    checks: dict = {}
    try:
        with Session(engine) as session:
            _, item = active_repair(session, lease)
            scan, source, finding = (
                session.get(ScanTask, item.scan_id),
                session.get(Artifact, item.source_id),
                session.get(FindingRecord, item.finding_id),
            )
            ensure_fresh(item, scan, source, finding)
            parsed = repair_source(settings, source)
            if item.model_name != settings.deepseek_model:
                raise DomainError("ANALYSIS_CONFIG_CHANGED", "修复模型配置已变化。", 409)
            target = json.loads(finding.payload)["finding"]
            baseline = baseline_for(session, scan, source)
            remaining = settings.task_timeout_seconds - (utcnow() - item.started_at).total_seconds()
            checks["contract"] = capture_contract(settings, item, scan)
            simulated = item.model_alias == "fake"
            source_id = source.id
        if remaining <= 0:
            raise TimeoutError
        deadline = asyncio.get_running_loop().time() + remaining
        target_loc = target_location(target)
        req = AnalysisRequest(
            artifact_id=source_id,
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
        async with asyncio.timeout_at(deadline):
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
        line_map = build_line_map(parsed.content, candidate)
        checks = {
            "contract": checks["contract"],
            "mode": "fake" if simulated else "real",
            "syntax": "passed",
            "patch": "passed",
            "roundtrip": "passed",
            "explanation": wire.explanation,
            "delta": {},
        }
        checks["impact"] = review_structure(
            parsed.content, candidate, target_loc[1], target_loc[2], line_map
        )
        if checks["impact"]["violations"]:
            raise PatchScopeError(checks["impact"])
        checks["review"] = {"status": "not_applicable" if simulated else "pending", "error": None}
        if not simulated:
            before_rules = detect(UUID(source_id), "source", parsed)
            after_rules = detect(UUID(source_id), "source", parse_input("source", candidate))
            known = baseline + locations(before_rules.findings, "rule")
            checks["delta"]["rules"] = finding_delta(
                known,
                target_loc,
                locations(after_rules.findings, "rule"),
                line_map,
                parsed.content,
                candidate,
            )
        summarize(checks)
        if simulated:
            store_candidate(engine, settings, lease, wire, candidate, diff, checks, final=True)
            return
        store_candidate(engine, settings, lease, wire, candidate, diff, checks, final=False)

        # Phase 2: model recheck. A failure here must not discard the paid-for candidate.
        review_error, reviewed = None, None
        try:
            ledger.version = PROMPT_VERSION  # the recheck is an analysis call; ledger = contract
            reviewer = (
                factory(settings, ledger)
                if factory
                else DeepSeekProvider(settings, ledger.reserve, ledger.finish)
            )
            async with asyncio.timeout_at(deadline):
                reviewed = await reviewer.analyze(
                    req.model_copy(
                        update={"content": candidate, "end_line": len(candidate.splitlines())}
                    )
                )
        except TimeoutError:
            review_error = "TASK_TIMEOUT"
        except DomainError as error:
            if error.code in PASS_THROUGH:
                raise
            review_error = error.code
        except Exception:
            review_error = "REPAIR_REVIEW_INTERNAL"
        if reviewed is not None and not (reviewed.analysis_complete and reviewed.mode == "real"):
            review_error = "MODEL_INCOMPLETE"
        if review_error is None and reviewed is not None:
            checks["review"] = {"status": "complete", "error": None}
            checks["delta"]["model"] = finding_delta(
                known,
                target_loc,
                locations(reviewed.findings, "llm"),
                line_map,
                parsed.content,
                candidate,
            )
        else:
            checks["review"] = {"status": "failed", "error": review_error}
        summarize(checks)
        store_candidate(engine, settings, lease, wire, candidate, diff, checks, final=True)
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
            kept = checks or json.loads(item.checks_json or "{}")
            impact = getattr(error, "impact", None)
            if impact is not None:  # keep the reason a patch was refused visible to the user
                kept["impact"] = impact
            if (kept.get("review") or {}).get("status") == "pending":
                kept["review"] = {"status": "failed", "error": item.error_code}
            category, detail = getattr(error, "category", None), getattr(error, "detail", None)
            if category in PATCH_DIAGNOSTIC_CATEGORIES and detail:
                # Server-computed integers and fixed words only: explains the refusal without
                # keeping the model's raw edits, the snapshot text or any credential.
                kept["patch_diagnostic"] = {"category": category, "detail": detail}
            if kept:
                item.checks_json = canonical(summarize(kept))
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
        failing_since = None
        while not work.done():
            await asyncio.sleep(1)
            try:
                cancel = heartbeat_repair(engine, settings, lease)
            except DomainError:
                work.cancel()  # lease lost: stop paying for calls nobody can publish
                return
            except Exception:
                # Transient storage trouble must not silently stop the heartbeat (that would
                # expire the lease and repeat paid calls); give up well before expiry instead.
                failing_since = failing_since or time.monotonic()
                if time.monotonic() - failing_since > settings.lease_seconds / 2:
                    work.cancel()
                    return
                continue
            failing_since = None
            if cancel:
                work.cancel()
                return

    monitor = asyncio.create_task(pulse())
    try:
        await work
    except asyncio.CancelledError:
        if asyncio.current_task().cancelling():
            raise
        with contextlib.suppress(Exception), transaction(engine) as session:
            job, item = active_repair(session, lease, allow_cancel=True)
            if item.cancel_requested:
                item.status, job.status = "cancelled", "cancelled"
                item.finished_at, job.lease_token, job.lease_until = utcnow(), None, None
    finally:
        monitor.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await monitor
    return True
