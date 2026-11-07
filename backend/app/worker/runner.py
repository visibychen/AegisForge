import asyncio
import contextlib
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.llm.deepseek import DeepSeekProvider, validate_result
from app.llm.provider import FakeProvider
from app.models import ScanTask
from app.rules.detector import detect
from app.schemas.contracts import AnalysisRequest
from app.services.merge import merge_findings
from app.services.queue import CallLedger, active, claim, heartbeat, publish, transaction
from app.services.scans import check_inputs, scan_artifacts


def hints_for(findings, chunk):
    hints, size = [], 0
    for finding in findings:
        loc = finding.location
        if loc.kind == "source" and (
            loc.end_line < chunk.start_line or loc.start_line > chunk.end_line
        ):
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


def progress(engine, lease, summary):
    import json

    with transaction(engine) as session:
        _, scan = active(session, lease)
        scan.result_json = json.dumps(summary, ensure_ascii=False)


async def execute(engine, settings, lease, provider_factory=None):
    summary = {"warnings": [], "processed_chunks": 0, "completed_chunks": 0}
    try:
        with Session(engine) as session:
            scan = session.get(ScanTask, lease.scan_id)
            strategy, alias = scan.strategy, scan.model_alias
            pairs = check_inputs(settings, scan_artifacts(session, scan.id))
        parsed_by_id = {a.id: p for a, p in pairs}
        findings, warnings, complete, first_error = [], [], True, None
        expected = sum(len(p.chunks) for _, p in pairs) if strategy != "rules" else 0
        summary |= {
            "strategy": strategy,
            "model_mode": "rules" if strategy == "rules" else "fake" if alias == "fake" else "real",
            "expected_chunks": expected,
            "artifact_count": len(pairs),
            "normalized_chars": sum(len(p.content) for _, p in pairs),
        }
        ledger = CallLedger(engine, settings, lease)
        provider = (
            provider_factory(settings, ledger)
            if provider_factory
            else FakeProvider()
            if alias == "fake"
            else DeepSeekProvider(settings, ledger.reserve, ledger.finish)
        )
        for artifact, parsed in pairs:
            warnings += parsed.warnings
            rules = (
                detect(UUID(artifact.id), artifact.input_type, parsed)
                if strategy != "llm"
                else None
            )
            if rules:
                findings += rules.findings
                warnings += rules.warnings
                if rules.truncated or (
                    artifact.input_type == "source" and parsed.private_tree is None
                ):
                    complete = False
            if strategy == "rules":
                continue
            for chunk in parsed.chunks:
                with Session(engine) as session:
                    active(session, lease)
                fields = {
                    name: parsed.fields[name]
                    for line in chunk.content.split("\n")
                    if (name := line.partition(" ")[0]) in parsed.fields
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
                    else:
                        validate_result(result, request)
                        findings += result.findings
                        summary["completed_chunks"] += 1
                    warnings += result.warnings
                except DomainError as error:
                    if error.code in {"LEASE_LOST", "TASK_CANCELLED"}:
                        raise
                    complete = False
                    first_error = first_error or error.code
                    warnings.append(f"部分模型分析未完成（{error.code}）；空发现不代表安全。")
                except (ValueError, TypeError):
                    complete = False
                    first_error = first_error or "MODEL_INVALID_OUTPUT"
                    warnings.append("部分模型输出证据未通过校验。")
                summary["processed_chunks"] += 1
                summary["warnings"] = list(dict.fromkeys(warnings))[:100]
                progress(engine, lease, summary)
        entries = merge_findings(findings, parsed_by_id)
        complete = complete and (strategy == "rules" or summary["completed_chunks"] == expected)
        status = "completed" if complete else "partial"
        if strategy == "llm" and alias != "fake" and summary["completed_chunks"] == 0:
            status = "failed"
        summary |= {
            "analysis_complete": complete,
            "warnings": list(dict.fromkeys(warnings))[:100],
            "finding_count": len(entries),
        }
        publish(engine, lease, status, summary, entries, first_error)
    except asyncio.CancelledError:
        # Cancellation requested by the user can publish; process shutdown/lease loss
        # leaves an unfinished lease for bounded recovery instead of inventing success.
        with Session(engine) as session:
            scan = session.get(ScanTask, lease.scan_id)
            cancelled = scan is not None and scan.cancel_requested
        if cancelled:
            with contextlib.suppress(DomainError):
                publish(engine, lease, "cancelled", {"warnings": ["任务已取消。"]}, [])
        raise
    except DomainError as error:
        if error.code != "LEASE_LOST":
            with contextlib.suppress(DomainError):
                publish(
                    engine,
                    lease,
                    "cancelled" if error.code == "TASK_CANCELLED" else "failed",
                    {"warnings": [f"任务未完成（{error.code}）。"]},
                    [],
                    error.code,
                )
    except Exception:
        with contextlib.suppress(DomainError):
            publish(
                engine,
                lease,
                "failed",
                {"warnings": ["任务执行异常，请检查服务状态。"]},
                [],
                "WORKER_INTERNAL",
            )


async def run_once(engine, settings, provider_factory=None):
    lease = claim(engine, settings)
    if lease is None:
        return False
    work = asyncio.create_task(execute(engine, settings, lease, provider_factory))

    async def pulse():
        while not work.done():
            await asyncio.sleep(1)
            try:
                if heartbeat(engine, settings, lease):
                    work.cancel()
                    return
            except DomainError:
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
        with contextlib.suppress(asyncio.CancelledError):
            await monitor
    return True
