"""Workspace read models: overview, lightweight history, finding filters and evidence views.

Counts come from SQL aggregates over JSON expressions (SQLite JSON1), so the finding payload
stays the single source of truth and no denormalised column can drift. Everything returned here
is already public/redacted; nothing executes uploaded or model code.
"""

import json
from collections import Counter

from sqlalchemy import String, exists, func, select

from app.core.errors import DomainError
from app.models import Artifact, FindingRecord, Repair, ScanTask, TaskArtifact
from app.services.artifacts import load_artifact
from app.services.patch_review import build_line_map
from app.services.repairs import baseline_for, evaluate_repair, require_repair
from app.services.scans import require_scan

CWE_IDS = ("CWE-79", "CWE-89", "CWE-78")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SOURCES = ("rule", "llm")
EVIDENCE_STATUSES = ("potential", "attack_indicator")
VERDICT_SAMPLE = 300  # candidates whose verdict is computed for aggregates; more are reported

CWE = func.json_extract(FindingRecord.payload, "$.finding.cwe", type_=String)
SEVERITY = func.json_extract(FindingRecord.payload, "$.finding.severity", type_=String)
EVIDENCE = func.json_extract(FindingRecord.payload, "$.finding.evidence_status", type_=String)
SOURCE_LIST = func.json_extract(FindingRecord.payload, "$.finding.sources", type_=String)


def scan_mode(strategy: str, alias: str) -> str:
    """What the task *planned*: rules only, simulated model, or a real model."""
    if strategy == "rules":
        return "rules"
    return "simulated" if alias == "fake" else "real"


def finding_conditions(cwe=None, severity=None, source=None, evidence_status=None) -> list:
    conditions = []
    if cwe:
        conditions.append(CWE == cwe)
    if severity:
        conditions.append(SEVERITY == severity)
    if evidence_status:
        conditions.append(EVIDENCE == evidence_status)
    if source:  # sources is a JSON array of the fixed words rule/llm
        conditions.append(SOURCE_LIST.like(f'%"{source}"%'))
    return conditions


def finding_facets(session, scan_id: str, attempt: int) -> dict:
    """Counts for the whole attempt (not narrowed by the active filters), so chips stay stable."""
    scope = (FindingRecord.scan_id == scan_id, FindingRecord.attempt == attempt)

    def grouped(expression):
        rows = session.execute(select(expression, func.count()).where(*scope).group_by(expression))
        return {key: count for key, count in rows if key}

    sources = {}
    for source in SOURCES:
        count = session.scalar(
            select(func.count()).where(*scope, *finding_conditions(source=source))
        )
        if count:
            sources[source] = count
    return {
        "cwe": grouped(CWE),
        "severity": grouped(SEVERITY),
        "source": sources,
        "evidence_status": grouped(EVIDENCE),
    }


def _repair_stats(session, scope_filter) -> dict:
    rows = session.execute(
        select(
            Repair.status,
            func.json_extract(Repair.checks_json, "$.mode", type_=String),
            func.json_extract(Repair.dynamic_json, "$.status", type_=String),
            func.count(),
        )
        .join(ScanTask, ScanTask.id == Repair.scan_id)
        .where(*scope_filter)
        .group_by(
            Repair.status,
            func.json_extract(Repair.checks_json, "$.mode", type_=String),
            func.json_extract(Repair.dynamic_json, "$.status", type_=String),
        )
    ).all()
    by_status: Counter = Counter()
    dynamic: Counter = Counter()
    simulated = 0
    for status, mode, dynamic_status, count in rows:
        by_status[status] += count
        dynamic[dynamic_status or "none"] += count
        if mode == "fake":
            simulated += count
    archived_count = session.scalar(
        select(func.count())
        .select_from(Repair)
        .join(ScanTask, ScanTask.id == Repair.scan_id)
        .join(FindingRecord, FindingRecord.id == Repair.finding_id)
        .where(*scope_filter, FindingRecord.attempt != ScanTask.retries)
    )
    current_candidates = session.scalar(
        select(func.count())
        .select_from(Repair)
        .join(ScanTask, ScanTask.id == Repair.scan_id)
        .join(FindingRecord, FindingRecord.id == Repair.finding_id)
        .where(
            *scope_filter, Repair.status == "candidate", FindingRecord.attempt == ScanTask.retries
        )
    )
    candidates = session.scalars(
        select(Repair)
        .join(ScanTask, ScanTask.id == Repair.scan_id)
        .join(FindingRecord, FindingRecord.id == Repair.finding_id)
        .where(
            *scope_filter, Repair.status == "candidate", FindingRecord.attempt == ScanTask.retries
        )
        .order_by(Repair.created_at.desc())
        .limit(VERDICT_SAMPLE + 1)
    ).all()
    verdicts = Counter(evaluate_repair(session, row)[3] for row in candidates[:VERDICT_SAMPLE])
    return {
        "total": sum(by_status.values()),
        "by_status": dict(by_status),
        "simulated": simulated,
        "dynamic": dict(dynamic),
        "verdicts": dict(verdicts),
        "verdicts_truncated": len(candidates) > VERDICT_SAMPLE,
        "verdict_sampled": min(len(candidates), VERDICT_SAMPLE),
        "verdict_limit": VERDICT_SAMPLE,
        "candidates_total": current_candidates,
        "archived": archived_count,
        "current": sum(by_status.values()) - archived_count,
    }


def overview(session) -> dict:
    live = ScanTask.deleted_at.is_(None)
    states: Counter = Counter()
    modes: Counter = Counter()
    real_outcomes: Counter = Counter()
    for strategy, alias, status, count in session.execute(
        select(ScanTask.strategy, ScanTask.model_alias, ScanTask.status, func.count())
        .where(live)
        .group_by(ScanTask.strategy, ScanTask.model_alias, ScanTask.status)
    ):
        mode = scan_mode(strategy, alias)
        states[status] += count
        modes[mode] += count
        if mode == "real":
            real_outcomes[status] += count
    scope = (live, FindingRecord.attempt == ScanTask.retries)

    def grouped(expression):
        rows = session.execute(
            select(expression, func.count())
            .select_from(FindingRecord)
            .join(ScanTask, ScanTask.id == FindingRecord.scan_id)
            .where(*scope)
            .group_by(expression)
        )
        return {key: count for key, count in rows if key}

    return {
        "tasks": sum(states.values()),
        "states": dict(states),
        "modes": dict(modes),
        "real_outcomes": dict(real_outcomes),
        "cwes": grouped(CWE),
        "severities": grouped(SEVERITY),
        "repairs": _repair_stats(session, (live,)),
        "notice": (
            "当前尝试的静态风险计数，不是确认漏洞数或准确率；模拟与仅规则结果不是真实模型分析。"
        ),
    }


def history_page(session, *, status, q, cwe, severity, offset, limit) -> dict:
    scope = [ScanTask.deleted_at.is_(None)]
    if status != "all":
        scope.append(ScanTask.status == status)
    if q:
        scope.append(ScanTask.id.contains(q, autoescape=True))
    if cwe or severity:
        scope.append(
            exists().where(
                FindingRecord.scan_id == ScanTask.id,
                FindingRecord.attempt == ScanTask.retries,
                *finding_conditions(cwe=cwe, severity=severity),
            )
        )
    rows = session.scalars(
        select(ScanTask)
        .where(*scope)
        .order_by(ScanTask.created_at.desc(), ScanTask.id)
        .offset(offset)
        .limit(limit)
    ).all()
    total = session.scalar(select(func.count()).select_from(ScanTask).where(*scope))
    ids = [row.id for row in rows]
    findings: dict[str, dict] = {i: {"total": 0, "severities": {}, "cwes": {}} for i in ids}
    if ids:
        for scan_id, cwe_value, severity_value, count in session.execute(
            select(FindingRecord.scan_id, CWE, SEVERITY, func.count())
            .select_from(FindingRecord)
            .join(ScanTask, ScanTask.id == FindingRecord.scan_id)
            .where(FindingRecord.scan_id.in_(ids), FindingRecord.attempt == ScanTask.retries)
            .group_by(FindingRecord.scan_id, CWE, SEVERITY)
        ):
            entry = findings[scan_id]
            entry["total"] += count
            entry["severities"][severity_value] = entry["severities"].get(severity_value, 0) + count
            entry["cwes"][cwe_value] = entry["cwes"].get(cwe_value, 0) + count
    names: dict[str, list] = {i: [] for i in ids}
    repairs = {
        i: {
            "total": 0,
            "simulated": 0,
            "by_status": {},
            "current": 0,
            "archived": 0,
            "verdicts": {},
        }
        for i in ids
    }
    if ids:
        for scan_id, name, kind in session.execute(
            select(TaskArtifact.scan_id, Artifact.display_name, Artifact.input_type)
            .join(Artifact, Artifact.id == TaskArtifact.artifact_id)
            .where(TaskArtifact.scan_id.in_(ids))
            .order_by(Artifact.id)
        ):
            if len(names[scan_id]) < 5:
                names[scan_id].append({"display_name": name, "input_type": kind})
        mode = func.json_extract(Repair.checks_json, "$.mode", type_=String)
        for sid, status_value, fake, archived, count in session.execute(
            select(
                Repair.scan_id,
                Repair.status,
                mode,
                FindingRecord.attempt != ScanTask.retries,
                func.count(),
            )
            .join(FindingRecord, FindingRecord.id == Repair.finding_id)
            .join(ScanTask, ScanTask.id == Repair.scan_id)
            .where(Repair.scan_id.in_(ids))
            .group_by(
                Repair.scan_id, Repair.status, mode, FindingRecord.attempt != ScanTask.retries
            )
        ):
            entry = repairs[sid]
            entry["total"] += count
            entry["simulated"] += count if fake == "fake" else 0
            entry["archived" if archived else "current"] += count
            entry["by_status"][status_value] = entry["by_status"].get(status_value, 0) + count
    scans = []
    for row in rows:
        result = json.loads(row.result_json or "{}")
        scans.append(
            {
                "id": row.id,
                "status": row.status,
                "strategy": row.strategy,
                "mode": scan_mode(row.strategy, row.model_alias),
                "attempt": row.retries,
                "error_code": row.error_code,
                "created_at": row.created_at.isoformat(),
                "finished_at": row.finished_at.isoformat() if row.finished_at else None,
                "analysis_complete": result.get("analysis_complete"),
                "expected_chunks": result.get("expected_chunks"),
                "completed_chunks": result.get("completed_chunks"),
                "artifacts": names[row.id],
                "findings": findings[row.id],
                "repairs": repairs[row.id],
            }
        )
    return {"total": total, "scans": scans}


def input_view(session, settings, scan_id: str, artifact_id: str) -> dict:
    """Public (redacted) text of one input of a live scan, for evidence navigation."""
    require_scan(session, scan_id)
    link = session.scalar(
        select(TaskArtifact).where(
            TaskArtifact.scan_id == scan_id, TaskArtifact.artifact_id == artifact_id
        )
    )
    artifact = session.get(Artifact, artifact_id) if link is not None else None
    if artifact is None:
        raise DomainError("ARTIFACT_NOT_FOUND", "该检测任务没有这个输入快照。", 404)
    parsed = load_artifact(settings, artifact)
    return {
        "artifact_id": artifact.id,
        "display_name": artifact.display_name,
        "input_type": artifact.input_type,
        "content": parsed.content,
        "fields": parsed.fields,
        "field_meta": parsed.field_meta,
        "chunk_count": len(parsed.chunks),
    }


def _delta_lists(checks: dict) -> tuple[dict, list]:
    positions = {}
    priority = {"persisting": 0, "introduced": 1, "preexisting": 2}
    for engine, part in (checks.get("delta") or {}).items():
        source = "rule" if engine == "rules" else "llm"
        for kind in priority:
            for e in part.get(kind, []):
                key = (e["cwe"], e["start_line"], e["end_line"])
                row = positions.setdefault(
                    key, {"cwe": key[0], "start_line": key[1], "end_line": key[2], "by_source": {}}
                )
                row["by_source"][source] = kind
                if "unchanged_line" in e:
                    row["unchanged_line"] = e["unchanged_line"]
    merged = {k: [] for k in priority}
    for row in positions.values():
        kind = min(row["by_source"].values(), key=priority.get)
        merged[kind].append(row)
    return merged, list(positions.values())


def compare_view(session, settings, repair_id: str) -> dict:
    """Original vs candidate (both redacted public text) plus where findings sit on each side."""
    item = require_repair(session, repair_id)
    if item.status != "candidate" or item.candidate_id is None:
        raise DomainError("CANDIDATE_NOT_READY", "候选尚未生成或已失效。", 409)
    scan = session.get(ScanTask, item.scan_id)
    source = session.get(Artifact, item.source_id)
    candidate = session.get(Artifact, item.candidate_id)
    finding = session.get(FindingRecord, item.finding_id)
    original_text = load_artifact(settings, source).content
    candidate_text = load_artifact(settings, candidate).content
    line_map = build_line_map(original_text, candidate_text)
    checks = json.loads(item.checks_json)
    target = json.loads(finding.payload)["finding"]
    merged, positions = _delta_lists(checks)
    return {
        "finding_attempt": finding.attempt,
        "archived": finding.attempt != scan.retries,
        "scan_attempt": scan.retries,
        "delta_status": {
            "rules": "done" if "rules" in checks.get("delta", {}) else "absent",
            "model": "done" if checks.get("review", {}).get("status") == "complete" else "absent",
        },
        "positions": positions,
        "repair_id": item.id,
        "scan_id": item.scan_id,
        "simulated": checks.get("mode") == "fake",
        "target": {
            "cwe": target["cwe"],
            "start_line": target["location"]["start_line"],
            "end_line": target["location"]["end_line"],
        },
        "original": {"sha256": source.sha256, "content": original_text},
        "candidate": {"sha256": candidate.sha256, "content": candidate_text},
        "hunks": [
            {"old_start": o1, "old_end": o2, "new_start": n1, "new_end": n2}
            for o1, o2, n1, n2 in line_map.blocks
        ],
        "baseline": [
            {"cwe": cwe, "start_line": start, "end_line": end}
            for cwe, start, end, _ in baseline_for(session, scan, source, attempt=finding.attempt)
        ],
        "after": merged,
    }
