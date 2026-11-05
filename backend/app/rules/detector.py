"""Versioned heuristics, deliberately not presented as complete taint analysis."""

import ast
import re
from uuid import UUID

from app.parsers.inputs import ParsedInput, qualified
from app.schemas.contracts import Finding, HttpLocation, SourceLocation

RULE_VERSION = "rules-1.0"
CWE = {"xss": "CWE-79", "sqli": "CWE-89", "cmdi": "CWE-78"}
ADVICE = {
    "xss": "按输出上下文转义，使用自动转义模板，避免将输入拼接为 HTML。",
    "sqli": "使用参数化 SQL，并以白名单限制不能绑定的标识符。",
    "cmdi": "使用参数数组并保持 shell=False，验证参数，避免构造 shell 命令。",
}


def finding(artifact_id: UUID, category: str, evidence: str, location, http=False) -> Finding:
    return Finding(
        category=category,
        cwe=CWE[category],
        severity="medium" if http else "high",
        location=location,
        evidence=evidence[:4000],
        explanation="规则发现攻击载荷特征；不证明服务端漏洞。"
        if http
        else "启发式规则发现危险操作与动态文本；需要结合上下文确认。",
        recommendation=ADVICE[category],
        sources=["rule"],
        evidence_status="attack_indicator" if http else "potential",
    )


def detect(artifact_id: UUID, input_type: str, parsed: ParsedInput) -> list[Finding]:
    results = []
    if input_type == "http":
        patterns = {
            "xss": r"<\s*(?:script|svg|img)\b|onerror\s*=|javascript:",
            "sqli": r"\bunion\s+select\b|['\"]\s*(?:or|and)\s+[\w'\"]+\s*=|\bsleep\s*\(",
            "cmdi": r"(?:;|\|\||&&)\s*(?:cat|id|whoami|curl|sh|echo)\b|\$\(|`[^`]+`",
        }
        for field, value in parsed.fields.items():
            for category, pattern in patterns.items():
                if re.search(pattern, value, re.I):
                    results.append(
                        finding(
                            artifact_id,
                            category,
                            value,
                            HttpLocation(artifact_id=artifact_id, field=field),
                            True,
                        )
                    )
        return results[:100]
    try:
        tree = ast.parse(parsed.content)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    lines = parsed.content.splitlines()
    for node in ast.walk(tree):
        category = None
        if isinstance(node, ast.Call):
            name = qualified(node.func)
            dynamic_arg = bool(node.args) and not isinstance(node.args[0], ast.Constant)
            if name.endswith((".execute", ".executemany")) and dynamic_arg and len(node.args) < 2:
                category = "sqli"
            elif name in {"os.system", "os.popen"} and dynamic_arg:
                category = "cmdi"
            elif (
                name.startswith("subprocess.")
                and dynamic_arg
                and any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in node.keywords
                )
            ):
                category = "cmdi"
            elif name.endswith(("render_template_string", "Markup")) and dynamic_arg:
                category = "xss"
        elif isinstance(node, ast.Return) and isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
            if "<" in ast.unparse(node.value):
                category = "xss"
        if category:
            start, end = node.lineno, node.end_lineno or node.lineno
            results.append(
                finding(
                    artifact_id,
                    category,
                    "\n".join(lines[start - 1 : end]),
                    SourceLocation(artifact_id=artifact_id, start_line=start, end_line=end),
                )
            )
    return results[:100]
