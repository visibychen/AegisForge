import asyncio
import contextlib
import json
import time
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.llm.deepseek import DeepSeekProvider, validate_result
from app.llm.provider import FakeProvider
from app.models import ScanTask
from app.rules.detector import detect
from app.schemas.contracts import AnalysisRequest
from app.services.merge import merge_findings
from app.services.queue import (
    CallLedger,
    active,
    claim,
    heartbeat,
    publish,
    transaction,
    with_db_retry,
)
from app.services.scans import check_inputs, scan_artifacts

INTERNAL = "MODEL_PROVIDER_INTERNAL"


def chunk_fields(chunk) -> set[str]:
    """HTTP field ids present in a chunk (each public content line starts with its id)."""
    return {line.partition(" ")[0] for line in chunk.content.split("\n")}


def hints_for(findings, chunk):
    fields = chunk_fields(chunk)
    hints, size = [], 0
    for finding in findings:
        loc = finding.location
        if loc.kind == "source" and (
            loc.end_line < chunk.start_line or loc.start_line > chunk.end_line
        ):
            continue
        if loc.kind == "http" and loc.field not in fields:
            continue
        hint = finding.model_copy(
            update={
                "evidence": finding.evidence[:500],
                "explanation": finding.explanation[:500],
                "recommendation": finding.recommendation[:500],
            }
        )
        length = len(hint.model_dump_json())
        if len(hints) >= 8 or size + length > 6000:
            break
        hints.append(hint)
        size += length
    return hints


def _save_progress(engine, lease, summary):
    with transaction(engine) as session:
        _, scan = active(session, lease)
        scan.result_json = json.dumps(summary, ensure_ascii=False)


def progress(engine, lease, summary):
    with_db_retry(_save_progress, engine, lease, summary)


def coverage_plan(pairs, strategy, alias):
    """Per-chunk ledger: what rules and the model actually did for every analysed region."""
    entries = []
    for artifact, parsed in pairs:
        if strategy == "llm":
            rules = "not_requested"
        elif artifact.input_type == "source" and parsed.private_tree is None:
            rules = "ast_unavailable"
        else:
            rules = "ran"
        model = "not_requested" if strategy == "rules" else "pending"
        for index, chunk in enumerate(parsed.chunks):
            entries.append(
                {
                    "artifact_id": artifact.id,
                    "display_name": artifact.display_name,
                    "input_type": artifact.input_type,
                    "chunk": index,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "rules": rules,
                    "model": model,
                    "model_error": None,
                    "failure_category": None,
                    "llm_findings": 0,
                }
            )
    return entries


async def execute(engine, settings, lease, provider_factory=None):
    summary = {"warnings": [], "processed_chunks": 0, "completed_chunks": 0, "coverage": []}
    findings, warnings, parsed_by_id = [], [], {}

    def wrap_up(status, error_code):
        summary["warnings"] = list(dict.fromkeys(warnings))[:100]
        entries = merge_findings(findings, parsed_by_id) if parsed_by_id else []
        summary["finding_count"] = len(entries)
        with_db_retry(publish, engine, lease, status, summary, entries, error_code)

    try:
        with Session(engine) as session:
            scan = session.get(ScanTask, lease.scan_id)
            strategy, alias = scan.strategy, scan.model_alias
            pairs = check_inputs(settings, scan_artifacts(session, scan.id))
        parsed_by_id = {a.id: p for a, p in pairs}
        complete, first_error = True, None
        expected = sum(len(p.chunks) for _, p in pairs) if strategy != "rules" else 0
        coverage = coverage_plan(pairs, strategy, alias)
        summary |= {
            "strategy": strategy,
            "model_mode": "rules" if strategy == "rules" else "fake" if alias == "fake" else "real",
            "expected_chunks": expected,
            "artifact_count": len(pairs),
            "normalized_chars": sum(len(p.content) for _, p in pairs),
            "coverage": coverage,
            "analysis_complete": False,
        }
        progress(engine, lease, summary)
        ledger = CallLedger(engine, settings, lease)
        provider = (
            provider_factory(settings, ledger)
            if provider_factory
            else FakeProvider()
            if alias == "fake"
            else DeepSeekProvider(settings, ledger.reserve, ledger.finish)
        )
        cursor = 0
        for artifact, parsed in pairs:
            warnings.extend(parsed.warnings)
            rules = (
                detect(UUID(artifact.id), artifact.input_type, parsed)
                if strategy != "llm"
                else None
            )
            if rules:
                findings.extend(rules.findings)
                warnings.extend(rules.warnings)
                if rules.truncated or (
                    artifact.input_type == "source" and parsed.private_tree is None
                ):
                    complete = False
            if strategy == "rules":
                cursor += len(parsed.chunks)
                continue
            for chunk in parsed.chunks:
                entry = coverage[cursor]
                cursor += 1
                with Session(engine) as session:
                    active(session, lease)
                fields = {
                    name: parsed.fields[name]
                    for name in chunk_fields(chunk)
                    if name in parsed.fields
                }
                request = AnalysisRequest(
                    artifact_id=artifact.id,
                    input_type=artifact.input_type,
                    content=chunk.content,
                    start_line=chunk.start_line,
                    end_line=chunk.end_line,
                    fields=fields if artifact.input_type == "http" else {},
                    rule_hints=hints_for(rules.findings, chunk) if rules else [],
                )
                try:
                    result = await provider.analyze(request)
                    if alias == "fake":
                        complete = False
                        entry["model"] = "simulated"
                    else:
                        result = validate_result(result, request)
                        findings.extend(result.findings)
                        summary["completed_chunks"] += 1
                        entry["model"], entry["llm_findings"] = "succeeded", len(result.findings)
                    warnings.extend(result.warnings)
                except DomainError as error:
                    if error.code in {"LEASE_LOST", "TASK_CANCELLED"}:
                        raise
                    complete, first_error = False, first_error or error.code
                    entry["model"], entry["model_error"] = "failed", error.code
                    entry["failure_category"] = getattr(error, "category", None)
                    warnings.append(f"部分模型分析未完成（{error.code}）；空发现不代表安全。")
                except ValueError as error:
                    complete, first_error = False, first_error or "MODEL_INVALID_OUTPUT"
                    entry["model"], entry["model_error"] = "failed", "MODEL_INVALID_OUTPUT"
                    entry["failure_category"] = getattr(error, "category", None)
                    warnings.append("部分模型输出证据未通过校验。")
                except Exception:
                    # Unknown provider/storage failure: keep everything already verified and
                    # never echo the exception text (it may contain paths or credentials).
                    complete, first_error = False, first_error or INTERNAL
                    entry["model"], entry["model_error"] = "failed", INTERNAL
                    warnings.append("部分模型分析因内部错误未完成；已保留规则与已验证结果。")
                summary["processed_chunks"] += 1
                summary["warnings"] = list(dict.fromkeys(warnings))[:100]
                progress(engine, lease, summary)
        complete = complete and (strategy == "rules" or summary["completed_chunks"] == expected)
        status = "completed" if complete else "partial"
        if strategy == "llm" and alias != "fake" and summary["completed_chunks"] == 0:
            status = "failed"
        summary["analysis_complete"] = complete
        wrap_up(status, first_error)
    except asyncio.CancelledError:
        # A user cancel may publish; shutdown/lease loss leaves the lease for bounded recovery.
        with contextlib.suppress(Exception), Session(engine) as session:
            scan = session.get(ScanTask, lease.scan_id)
            if scan is not None and scan.cancel_requested:
                wrap_up("cancelled", None)
        raise
    except DomainError as error:
        if error.code == "LEASE_LOST":
            return
        if error.code == "TASK_CANCELLED":
            with contextlib.suppress(Exception):
                wrap_up("cancelled", None)
            return
        warnings.append(f"任务未完成（{error.code}）。")
        with contextlib.suppress(Exception):
            wrap_up("partial" if findings else "failed", error.code)
    except Exception:
        # Storage or internal failure: publish what is already verified as partial (only while
        # the lease is still valid; publish() re-checks it). Never echo exception text.
        warnings.append("任务执行异常，已保留已完成的规则与验证结果。")
        summary["analysis_complete"] = False
        with contextlib.suppress(Exception):
            wrap_up("partial" if findings else "failed", "WORKER_INTERNAL")


async def run_once(engine, settings, provider_factory=None):
    lease = with_db_retry(claim, engine, settings)
    if lease is None:
        return False
    work = asyncio.create_task(execute(engine, settings, lease, provider_factory))

    async def pulse():
        failing_since = None
        while not work.done():
            await asyncio.sleep(1)
            try:
                cancel = heartbeat(engine, settings, lease)
            except DomainError:
                work.cancel()  # lease lost: stop; publish() would refuse anyway
                return
            except Exception:
                # Transient storage trouble: keep the worker alive, but stop well before the
                # lease could expire so a stale owner never keeps working unnoticed.
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
    finally:
        monitor.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await monitor
    return True
