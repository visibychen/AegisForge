"""Versioned heuristics, deliberately not presented as complete taint analysis.

Source rules walk the AST of the *original* text (never the redacted view) and report
evidence from the redacted lines, which keep identical numbering. HTTP rules match the
unredacted normalized values held in server memory; evidence is the public redacted value,
so a credential field carrying a payload is reported without echoing it.
All traversals are iterative. Known gaps: inter-procedural flow, generators/comprehensions,
sinks not listed below; such code may yield false negatives or conservative positives.
"""

import ast
import re
from dataclasses import dataclass
from uuid import UUID

from app.core.redaction import MASK
from app.parsers.inputs import ParsedInput, qualified
from app.schemas.contracts import Finding, HttpLocation, SourceLocation

RULE_VERSION = "rules-1.1"
MAX_RULE_FINDINGS = 100
MAX_HOPS = 3
CWE = {"xss": "CWE-79", "sqli": "CWE-89", "cmdi": "CWE-78"}
ADVICE = {
    "xss": "按输出上下文转义，使用自动转义模板，避免将输入拼接为 HTML。",
    "sqli": "使用参数化 SQL，并以白名单限制不能绑定的标识符。",
    "cmdi": "使用参数数组并保持 shell=False，验证参数，避免构造 shell 命令。",
}
# Unchanged from rules-1.0 on purpose: HTTP patterns are only re-tuned on the dev split.
HTTP_PATTERNS = {
    "xss": re.compile(r"<\s*(?:script|svg|img)\b|onerror\s*=|javascript:", re.I),
    "sqli": re.compile(r"\bunion\s+select\b|['\"]\s*(?:or|and)\s+[\w'\"]+\s*=|\bsleep\s*\(", re.I),
    "cmdi": re.compile(r"(?:;|\|\||&&)\s*(?:cat|id|whoami|curl|sh|echo)\b|\$\(|`[^`]+`", re.I),
}
SANITIZERS = {
    "xss": {"escape", "html.escape", "markupsafe.escape", "flask.escape", "int", "float"},
    "sqli": {"int", "float", "uuid.UUID"},
    "cmdi": {"shlex.quote", "int", "float", "ipaddress.ip_address", "ipaddress.ip_network"},
}
SHELL_ALWAYS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
SHELL_OPTIONAL = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
SQL_METHODS = {"execute", "executemany", "executescript"}
SQL_KEYWORDS = {"sql", "statement", "operation", "query"}
PASS_THROUGH = {"Markup", "text", "str"}  # wrappers whose result is as tainted as the argument
HTML_TAG = re.compile(r"<\s*[A-Za-z!/]")


@dataclass
class RuleResult:
    findings: list[Finding]
    warnings: list[str]
    truncated: bool


@dataclass
class Shape:
    tainted: bool = False  # contains a value not proven constant or sanitized
    built: bool = False  # assembled by concatenation, %, f-string, format() or join()
    html: bool = False  # contains a literal HTML tag fragment


def finding(category: str, evidence: str, location, http=False) -> Finding:
    return Finding(
        category=category,
        cwe=CWE[category],
        severity="medium" if http else "high",
        location=location,
        evidence=(evidence or MASK)[:4000],
        evidence_truncated=len(evidence or MASK) > 4000,
        explanation="规则发现攻击载荷特征；不证明服务端漏洞。"
        if http
        else "启发式规则发现危险操作与未净化的动态文本；需要结合上下文确认。",
        recommendation=ADVICE[category],
        sources=["rule"],
        evidence_status="attack_indicator" if http else "potential",
    )


class Scope:
    """Import aliases plus module/function assignments for bounded local resolution."""

    def __init__(self, tree: ast.Module):
        self.aliases: dict[str, str] = {}
        self.owner: dict[ast.AST, ast.AST] = {}
        self.params: dict[ast.AST, set[str]] = {}
        self.tables: dict[ast.AST | None, dict[str, list[tuple[int, ast.AST]]]] = {None: {}}
        for node in ast.walk(tree):  # breadth-first, so inner functions overwrite owners
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self.aliases[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                arguments = node.args
                every = arguments.posonlyargs + arguments.args + arguments.kwonlyargs
                every += [a for a in (arguments.vararg, arguments.kwarg) if a]
                self.params[node] = {a.arg for a in every}
                for child in ast.walk(node):
                    if child is not node:
                        self.owner[child] = node
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                table = self.tables.setdefault(self.owner.get(node), {})
                value = node if isinstance(node, ast.AugAssign) else node.value
                for target in targets:
                    if isinstance(target, ast.Name):
                        table.setdefault(target.id, []).append((node.lineno, value))

    def canonical(self, func: ast.AST) -> str:
        root, _, rest = qualified(func).partition(".")
        resolved = self.aliases.get(root, root)
        return f"{resolved}.{rest}" if rest else resolved

    def resolve(self, identifier: str, owner: ast.AST | None, line: int) -> ast.AST | None:
        if owner is not None:
            if identifier in self.params.get(owner, ()):
                return None
            local = self.tables.get(owner, {}).get(identifier)
            if local:
                earlier = [value for at, value in local if at < line]
                return earlier[-1] if earlier else None
            values = self.tables[None].get(identifier)  # module value read at call time
            return values[-1][1] if values else None
        earlier = [value for at, value in self.tables[None].get(identifier, []) if at < line]
        return earlier[-1] if earlier else None

    def allowlisted(self, node: ast.AST) -> bool:
        """``ALLOWED[x]`` / ``ALLOWED.get(x, CONST)`` on a module dict of constants."""
        if isinstance(node, ast.Subscript):
            target = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and all(isinstance(arg, ast.Constant) for arg in node.args[1:])
        ):
            target = node.func.value
        else:
            return False
        if not isinstance(target, ast.Name):
            return False
        values = self.tables[None].get(target.id)
        if not values or not isinstance(values[-1][1], ast.Dict):
            return False
        return all(isinstance(value, ast.Constant) for value in values[-1][1].values)


def shape(category: str, node: ast.AST, scope: Scope) -> Shape:
    """Classify an expression for one category without recursion."""
    sanitizers = SANITIZERS[category]
    result = Shape()
    stack: list[tuple[ast.AST, int]] = [(node, 0)]
    while stack:
        current, hops = stack.pop()
        if isinstance(current, ast.Constant):
            if isinstance(current.value, str) and HTML_TAG.search(current.value):
                result.html = True
        elif isinstance(current, ast.Name):
            value = None
            if hops < MAX_HOPS:
                value = scope.resolve(current.id, scope.owner.get(current), current.lineno)
            if value is None:
                result.tainted = True
            else:
                stack.append((value, hops + 1))
        elif isinstance(current, ast.AugAssign):
            result.built = True
            stack.append((current.value, hops))
            owner = scope.owner.get(current)
            target = current.target
            earlier = scope.resolve(target.id, owner, current.lineno) if hops < MAX_HOPS else None
            if earlier is None:
                result.tainted = True
            else:
                stack.append((earlier, hops + 1))
        elif isinstance(current, ast.JoinedStr):
            result.built = True
            stack.extend((value, hops) for value in current.values)
        elif isinstance(current, ast.FormattedValue):
            stack.append((current.value, hops))
        elif isinstance(current, ast.BinOp):
            result.built = result.built or isinstance(current.op, (ast.Add, ast.Mod))
            stack += [(current.left, hops), (current.right, hops)]
        elif isinstance(current, (ast.List, ast.Tuple, ast.Set)):
            stack.extend((element, hops) for element in current.elts)
        elif isinstance(current, ast.IfExp):
            stack += [(current.body, hops), (current.orelse, hops)]
        elif scope.allowlisted(current):
            continue
        elif isinstance(current, ast.Call):
            name = scope.canonical(current.func)
            short = name.rsplit(".", 1)[-1]
            if isinstance(current.func, ast.Attribute) and current.func.attr in {"format", "join"}:
                result.built = True
                receiver = current.func.value
                stack.append((receiver, hops))
                escapes = isinstance(receiver, ast.Call) and qualified(receiver.func).endswith(
                    "Markup"
                )
                if not escapes:  # Markup(...).format() escapes its arguments
                    stack.extend((arg, hops) for arg in current.args)
                    stack.extend((keyword.value, hops) for keyword in current.keywords)
            elif short in PASS_THROUGH:
                stack.extend((arg, hops) for arg in current.args)
            elif name not in sanitizers and short not in sanitizers:
                result.tainted = True  # unknown call result, e.g. request.args.get(...)
        else:
            result.tainted = True  # attributes, subscripts, comprehensions, ...
    return result


def _argument(call: ast.Call, keywords: set[str]) -> ast.AST | None:
    if call.args:
        return call.args[0]
    return next((kw.value for kw in call.keywords if kw.arg in keywords), None)


def source_category(node: ast.AST, scope: Scope) -> str | None:
    if isinstance(node, ast.Return):
        if node.value is None:
            return None
        found = shape("xss", node.value, scope)
        return "xss" if found.tainted and found.built and found.html else None
    if not isinstance(node, ast.Call):
        return None
    name = scope.canonical(node.func)
    short = name.rsplit(".", 1)[-1]
    method = node.func.attr if isinstance(node.func, ast.Attribute) else None
    if method in SQL_METHODS or (short == "text" and name.startswith("sqlalchemy")):
        query = _argument(node, SQL_KEYWORDS)
        if query is None:
            return None
        found = shape("sqli", query, scope)
        parameters = len(node.args) > 1 or any(kw.arg == "parameters" for kw in node.keywords)
        raw_query = method in SQL_METHODS and not parameters
        return "sqli" if found.tainted and (found.built or raw_query) else None
    shell = any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in node.keywords
    )
    if name in SHELL_ALWAYS or (name in SHELL_OPTIONAL and shell):
        command = _argument(node, {"args", "cmd", "command"})
        return "cmdi" if command is not None and shape("cmdi", command, scope).tainted else None
    if short in {"render_template_string", "Markup"} and node.args:
        return "xss" if shape("xss", node.args[0], scope).tainted else None
    if short == "make_response" and node.args:
        found = shape("xss", node.args[0], scope)
        return "xss" if found.tainted and found.built and found.html else None
    return None


def _detect_source(artifact_id: UUID, parsed: ParsedInput) -> RuleResult:
    tree = parsed.private_tree
    if tree is None:
        return RuleResult([], ["源码规则未运行：AST 不可用，不能据此认为没有风险。"], False)
    scope = Scope(tree)
    lines = parsed.content.split("\n")  # redacted view with identical line numbering
    seen: set[tuple[str, int]] = set()
    results: list[Finding] = []
    nodes = sorted(
        (node for node in ast.walk(tree) if isinstance(node, (ast.Call, ast.Return))),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for node in nodes:
        category = source_category(node, scope)
        if not category or (category, node.lineno) in seen:
            continue
        seen.add((category, node.lineno))
        start, end = node.lineno, node.end_lineno or node.lineno
        location = SourceLocation(artifact_id=artifact_id, start_line=start, end_line=end)
        results.append(finding(category, "\n".join(lines[start - 1 : end]), location))
        if len(results) > MAX_RULE_FINDINGS:
            break
    return _limited(results)


def _detect_http(artifact_id: UUID, parsed: ParsedInput) -> RuleResult:
    results: list[Finding] = []
    for field_id, value in parsed.private_fields.items():
        public = parsed.fields[field_id]
        evidence = f"{MASK}（敏感字段命中攻击特征，原值不展示）" if public == MASK else public
        for category, pattern in HTTP_PATTERNS.items():
            if pattern.search(value):
                location = HttpLocation(artifact_id=artifact_id, field=field_id)
                results.append(finding(category, evidence, location, http=True))
        if len(results) > MAX_RULE_FINDINGS:
            break
    return _limited(results)


def _limited(results: list[Finding]) -> RuleResult:
    if len(results) <= MAX_RULE_FINDINGS:
        return RuleResult(results, [], False)
    warning = "规则线索超过 100 项，仅返回前 100 项；未展示部分不能据此认为安全。"
    return RuleResult(results[:MAX_RULE_FINDINGS], [warning], True)


def detect(artifact_id: UUID, input_type: str, parsed: ParsedInput) -> RuleResult:
    if input_type == "http":
        return _detect_http(artifact_id, parsed)
    return _detect_source(artifact_id, parsed)
