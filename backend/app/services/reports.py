"""Source-free reports and per-repair explanation cards.

Every value that reaches a report is an enumeration, number, UUID, hash, line range or a fixed
word taken from our own constants; free text (evidence, explanations, file names, HTTP parameter
names, model prose) is never copied. Strings read back from stored JSON still pass an allow-list
filter, so a surprising stored value cannot leak into an export.
"""

import json
import re
from collections import Counter

from sqlalchemy import func, select

from app.models import FindingRecord, Repair
from app.services.adjudicate import ADJUDICATION_VERSION, CRITERIA
from app.services.queue import utcnow
from app.services.repairs import evaluate_repair
from app.services.report_integrity import seal_report
from app.services.workspace import scan_mode

REPORT_VERSION = "report-2.1"

LIMIT = 1000
REPAIR_LIMIT = 200
SAFE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
NOTICE = "静态判断与固定测试证据，不代表无漏洞；模拟与仅规则结果不是真实模型分析。"
LIMITS = [
    "报告不含源码、文件名、HTTP 参数名或模型自由文本；证据请在工作台中查看（已脱敏，尽力而为）。",
    "“受控验证全部通过”只表示登记样例的固定测试集通过，不证明没有其他漏洞。",
    "摘要用于完整性核对，不是数字签名，不能防御能同时改写记录与摘要的写入者。",
    "模型服务可能滚动更新，同一配置不保证复现相同输出。",
]


def safe(value):
    return value if isinstance(value, str) and SAFE.fullmatch(value) else None


def digest_of(value):
    return value if isinstance(value, str) and HEX.fullmatch(value) else None


def _count(value) -> int:
    return len(value) if isinstance(value, list) else 0


def proof_summary(value):
    """Only fixed criterion names and bounded integer counts, never refuted source/prose."""
    if not isinstance(value, dict) or value.get("version") != ADJUDICATION_VERSION:
        return None

    def count(number):
        return number if type(number) is int and 0 <= number <= 10000 else None

    criteria = value.get("by_criterion")
    return {
        "version": ADJUDICATION_VERSION,
        **{key: count(value.get(key)) for key in ("examined", "kept", "refuted")},
        "by_criterion": {
            key: count(number)
            for key, number in (criteria if isinstance(criteria, dict) else {}).items()
            if key in CRITERIA
        },
    }


def _delta(part) -> dict | None:
    if not isinstance(part, dict):
        return None
    return {
        "target_resolved": bool(part.get("target_resolved")),
        "persisting": _count(part.get("persisting")),
        "preexisting": _count(part.get("preexisting")),
        "introduced": _count(part.get("introduced")),
    }


def repair_card(session, row: Repair, finding_attempt: int | None, current: int) -> dict:
    """The explanation card of one repair: what ran, what was checked, what is still unproven."""
    checks, dynamic, gates, verdict = evaluate_repair(session, row)
    impact = checks.get("impact") or {}
    contract = checks.get("contract") or {}
    delta = checks.get("delta") or {}
    review = checks.get("review") or {}
    tests = [
        {"name": safe(t.get("name")), "passed": bool(t.get("passed"))}
        for t in dynamic.get("tests", [])
        if isinstance(t, dict) and safe(t.get("name"))
    ]
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "finding_attempt": finding_attempt,
        "current_attempt": finding_attempt == current,
        "status": row.status,
        "error_code": safe(row.error_code),
        "validation_status": verdict,
        "simulated": checks.get("mode") == "fake",
        "model_alias": safe(row.model_alias),
        "model": safe(row.model_name),
        "source_sha256": digest_of(row.source_sha256),
        "candidate_sha256": digest_of(contract.get("candidate_sha256")),
        "diff_sha256": digest_of(contract.get("diff_sha256")),
        "gates": [{"id": safe(g["id"]), "state": safe(g["state"])} for g in gates],
        "impact": {
            key: impact.get(key)
            for key in ("total_lines", "changed_lines", "added_lines", "hunks", "distance")
            if isinstance(impact.get(key), int)
        }
        | {
            "violations": [c for c in map(safe, impact.get("violations", [])) if c],
            "warnings": [c for c in map(safe, impact.get("warnings", [])) if c],
        },
        "delta": {name: _delta(part) for name, part in delta.items() if safe(name)},
        "review": {"status": safe(review.get("status")), "error": safe(review.get("error"))},
        "contract": {
            "digest": digest_of(contract.get("digest")),
            "versions": {
                k: safe(v)
                for k, v in (contract.get("versions") or {}).items()
                if safe(k) and safe(v)
            },
        },
        "dynamic": {
            "status": safe(dynamic.get("status")),
            "case_id": safe(dynamic.get("case_id")),
            "error_code": safe(dynamic.get("error_code")),
            "digest": digest_of(dynamic.get("digest")),
            "tests": tests,
        },
    }


def build_report(session, scan) -> dict:
    result = json.loads(scan.result_json or "{}")
    receipt = json.loads(scan.plan_json or "{}")
    configuration = receipt.get("configuration") or {}
    coverage = result.get("coverage") or []
    rows = session.scalars(
        select(FindingRecord)
        .where(FindingRecord.scan_id == scan.id, FindingRecord.attempt == scan.retries)
        .order_by(FindingRecord.position, FindingRecord.id)
        .limit(LIMIT + 1)
    ).all()
    by_attempt = {
        str(attempt): count
        for attempt, count in session.execute(
            select(FindingRecord.attempt, func.count())
            .where(FindingRecord.scan_id == scan.id)
            .group_by(FindingRecord.attempt)
        )
    }
    findings = []
    for row in rows[:LIMIT]:
        payload = json.loads(row.payload)
        finding = payload["finding"]
        location = finding["location"]
        public_location = (
            {
                "kind": "source",
                "artifact_id": location["artifact_id"],
                "start_line": location["start_line"],
                "end_line": location["end_line"],
            }
            if location["kind"] == "source"
            else {
                "kind": "http",
                "artifact_id": location["artifact_id"],
                "field": safe(location.get("field")),
            }
        )
        findings.append(
            {
                "id": row.id,
                "attempt": row.attempt,
                "category": safe(finding["category"]),
                "cwe": safe(finding["cwe"]),
                "severity": safe(finding["severity"]),
                "sources": [s for s in map(safe, finding["sources"]) if s],
                "evidence_status": safe(finding["evidence_status"]),
                "severity_disagreement": bool(payload.get("severity_disagreement")),
                "location": public_location,
            }
        )
    attempts = []
    for item in json.loads(scan.attempts_json or "[]"):
        summary = item.get("summary") or {}
        attempts.append(
            {
                "attempt": item.get("attempt"),
                "status": safe(item.get("status")),
                "error_code": safe(item.get("error_code")),
                "analysis_complete": summary.get("analysis_complete"),
                "finding_count": summary.get("finding_count"),
                "plan_digest": digest_of((item.get("receipt") or {}).get("plan_digest")),
            }
        )
    repair_rows = session.scalars(
        select(Repair)
        .where(Repair.scan_id == scan.id)
        .order_by(Repair.created_at, Repair.id)
        .limit(REPAIR_LIMIT + 1)
    ).all()
    repairs = []
    for row in repair_rows[:REPAIR_LIMIT]:
        finding_row = session.get(FindingRecord, row.finding_id)
        attempt = finding_row.attempt if finding_row is not None else None
        repairs.append(repair_card(session, row, attempt, scan.retries))
    result_report = {
        "schema_version": REPORT_VERSION,
        "generated_at": utcnow().isoformat(),
        "source_free": True,
        "notice": NOTICE,
        "scan": {
            "id": scan.id,
            "status": safe(scan.status),
            "strategy": safe(scan.strategy),
            "mode": scan_mode(scan.strategy, scan.model_alias),
            "model_alias": safe(scan.model_alias),
            "attempt": scan.retries,
            "error_code": safe(scan.error_code),
            "analysis_complete": result.get("analysis_complete"),
            "adjudication": proof_summary(result.get("adjudication")),
            "created_at": scan.created_at.isoformat(),
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "chunks": {
                "expected": result.get("expected_chunks"),
                "completed": result.get("completed_chunks"),
                "processed": result.get("processed_chunks"),
            },
            "coverage": {
                "rules": dict(Counter(safe(e.get("rules")) for e in coverage)),
                "model": dict(Counter(safe(e.get("model")) for e in coverage)),
                "model_errors": dict(
                    Counter(safe(e.get("model_error")) for e in coverage if e.get("model_error"))
                ),
            },
            "versions": {
                k: safe(v)
                for k, v in (configuration.get("versions") or {}).items()
                if safe(k) and safe(v)
            },
            "digests": {
                "input": digest_of(receipt.get("input_digest")),
                "plan": digest_of(receipt.get("plan_digest")),
            },
        },
        "findings_by_attempt": by_attempt,
        "findings": findings,
        "attempts": attempts,
        "repairs": repairs,
        "truncated": {
            "findings": len(rows) > LIMIT,
            "repairs": len(repair_rows) > REPAIR_LIMIT,
        },
        "limits": LIMITS,
    }

    return seal_report(result_report)


# --- Markdown ---------------------------------------------------------------------------

# Letters, digits, plain punctuation and CJK text/fullwidth forms; never | ` < > [ ] * # \ or "
_CELL = re.compile(r"[^A-Za-z0-9_.:/+\-,%()= ·–　-〿一-鿿＀-￯]")
MODE_TEXT = {"rules": "仅规则", "simulated": "模拟模型（未做真实分析）", "real": "真实模型"}
GATE_TEXT = {
    "passed": "通过",
    "failed": "未通过",
    "skipped": "未执行",
    "pending": "进行中",
    "error": "工具异常",
}


def cell(value) -> str:
    """One safe table cell: allow-listed characters only, so no markup or line breaks survive."""
    text = "" if value is None else str(value)
    return _CELL.sub("?", text)[:120] or "-"


def table(headers: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def _where(finding: dict) -> str:
    location = finding["location"]
    if location["kind"] == "source":
        return f"第 {location['start_line']}–{location['end_line']} 行"
    return f"字段 {location.get('field')}"


def render_markdown(report: dict) -> str:
    scan = report["scan"]
    out = [
        f"# AegisForge 检测与修复报告（{cell(scan['id'][:8])}）",
        "",
        f"> {report['notice']}",
        "",
    ]
    out += [
        "## 概览",
        "",
        table(
            ["项目", "值"],
            [
                ["检测任务", scan["id"]],
                ["状态", scan["status"]],
                ["分析模式", MODE_TEXT.get(scan["mode"], scan["mode"])],
                ["当前尝试", scan["attempt"]],
                [
                    "分析是否完整",
                    {True: "是", False: "否"}.get(scan["analysis_complete"], "未记录"),
                ],
                ["错误码", scan["error_code"]],
                [
                    "模型分块（完成/预期）",
                    f"{scan['chunks']['completed']}/{scan['chunks']['expected']}",
                ],
                ["输入摘要", scan["digests"]["input"]],
                ["方案摘要", scan["digests"]["plan"]],
            ],
        ),
        "",
    ]
    out += [
        f"JSON 内容摘要：{report['content_digest']}（不覆盖本 Markdown 的文字，不是数字签名）",
        "",
    ]
    cov = scan["coverage"]
    out += [
        "## 分析覆盖",
        "",
        table(
            ["维度", "状态与分块数"],
            [
                ["规则", "，".join(f"{k}:{v}" for k, v in cov["rules"].items())],
                ["模型", "，".join(f"{k}:{v}" for k, v in cov["model"].items())],
                ["模型错误码", "，".join(f"{k}:{v}" for k, v in cov["model_errors"].items())],
            ],
        ),
        "",
        "未被模型成功分析的区域没有智能检测结论。",
        "",
    ]
    proof = scan.get("adjudication")
    if proof:
        out += [
            "## 静态复核摘要",
            "",
            f"检查 {proof['examined']} 条线索，保留 {proof['kept']} 条，"
            f"依据受限静态判据排除 {proof['refuted']} 条。未知情况保留。",
            "排除线索不代表整个输入安全，也不替代动态验证。",
            "",
        ]
    truncated = "（已截断）" if report["truncated"]["findings"] else ""
    out += [f"## 当前尝试的发现{truncated}", ""]
    if report["findings"]:
        out += [
            table(
                ["#", "CWE", "等级", "来源", "证据状态", "位置", "发现编号"],
                [
                    [
                        i + 1,
                        f["cwe"],
                        f["severity"],
                        "+".join(f["sources"]),
                        f["evidence_status"],
                        _where(f),
                        f["id"],
                    ]
                    for i, f in enumerate(report["findings"])
                ],
            ),
            "",
        ]
    else:
        out += ["没有发现；这不代表输入安全。", ""]
    if report["attempts"]:
        out += [
            "## 以往尝试",
            "",
            table(
                ["尝试", "状态", "错误码", "完整", "发现数", "方案摘要"],
                [
                    [
                        a["attempt"],
                        a["status"],
                        a["error_code"],
                        a["analysis_complete"],
                        a["finding_count"],
                        a["plan_digest"],
                    ]
                    for a in report["attempts"]
                ],
            ),
            "",
        ]
    out += ["## 修复说明卡", ""]
    if not report["repairs"]:
        out += ["没有候选修复。", ""]
    for r in report["repairs"]:
        scope = "当前尝试" if r["current_attempt"] else "以往尝试"
        kind = "模拟（候选与原文相同，未做真实修复）" if r["simulated"] else "真实模型"
        out += [
            f"### 修复 {cell(r['id'][:8])} · {scope} · {kind}",
            "",
            table(
                ["项目", "值"],
                [
                    ["修复编号", r["id"]],
                    ["发现编号", r["finding_id"]],
                    ["状态", r["status"]],
                    ["验证结论", r["validation_status"]],
                    ["错误码", r["error_code"]],
                    [
                        "模型",
                        r["model_alias"]
                        if r["simulated"]
                        else f"{r['model_alias']} / {r['model']}",
                    ],
                    ["源码摘要", r["source_sha256"]],
                    ["候选摘要", r["candidate_sha256"]],
                    ["补丁摘要", r["diff_sha256"]],
                    ["契约摘要", r["contract"]["digest"]],
                    [
                        "改动",
                        "{}/{} 行，{} 处".format(
                            r["impact"].get("changed_lines"),
                            r["impact"].get("total_lines"),
                            r["impact"].get("hunks"),
                        ),
                    ],
                    ["受控动态验证", r["dynamic"]["status"] or "未请求"],
                ],
            ),
            "",
        ]
        out += [
            table(
                ["门禁", "状态"],
                [[g["id"], GATE_TEXT.get(g["state"], g["state"])] for g in r["gates"]],
            ),
            "",
        ]
        for name, part in r["delta"].items():
            if part:
                out += [
                    f"- {name} 复检：目标{'已消除' if part['target_resolved'] else '仍存在'}，"
                    f"原有未修复 {part['preexisting']}，新增 {part['introduced']}"
                ]
        out += [""]
    out += ["## 局限与说明", ""] + [f"- {text}" for text in report["limits"]] + [""]
    return "\n".join(out)
