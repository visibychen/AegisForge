"""Versioned heuristics, deliberately not presented as complete taint analysis.

Source rules walk the AST of the *original* text (never the redacted view) and report
evidence from the redacted lines, which keep identical numbering. HTTP rules match the
unredacted normalized values held in server memory; evidence is the public redacted value,
so a credential field carrying a payload is reported without echoing it.
All traversals are iterative.

rules-1.3 (see ``app/rules/semantics.py``): reaching definitions instead of "last textual
assignment", shadowed imports/builtins are no longer trusted, tuple unpacking, comprehension
elements, recognised early-exit guards, ``shlex.join``, ``asyncio.create_subprocess_shell`` and
explicit interpreters in argument lists. Known gaps remain: inter-procedural flow, attributes,
sinks not listed below; such code may yield false negatives or conservative positives.
"""

import ast
import posixpath
import re
import shlex
from dataclasses import dataclass
from uuid import UUID

from app.core.redaction import MASK
from app.parsers.inputs import ParsedInput
from app.rules.semantics import (
    COMPREHENSIONS,
    Element,
    Guard,
    Import,
    Param,
    Semantics,
    Unknown,
)
from app.schemas.contracts import Finding, HttpLocation, SourceLocation

RULE_VERSION = "rules-1.3"
MAX_RULE_FINDINGS = 100
MAX_HOPS = 8
WORK_LIMIT = 5000  # bounded effort per expression; exhausted analysis is reported as tainted
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
# Fully qualified, trusted names only (an unshadowed import or builtin; see Semantics.trusted).
SANITIZERS = {
    "xss": {
        "html.escape",
        "markupsafe.escape",
        "markupsafe.escape_silent",
        "flask.escape",
        "jinja2.escape",
        "int",
        "float",
    },
    "sqli": {"int", "float", "uuid.UUID"},
    "cmdi": {
        "shlex.quote",
        "shlex.join",
        "int",
        "float",
        "ipaddress.ip_address",
        "ipaddress.ip_network",
    },
}
MARKUP = {"markupsafe.Markup", "flask.Markup", "jinja2.Markup"}
SQL_TEXT = {"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"}
PASS_THROUGH = MARKUP | SQL_TEXT | {"str"}  # results as tainted as their argument
SHELL_ALWAYS = {
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell",
}
SHELL_OPTIONAL = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
EXEC_ARGV = SHELL_OPTIONAL | {"asyncio.create_subprocess_exec"}
# Programs that interpret one of their arguments as code or as another command.
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "cmd", "cmd.exe", "powershell", "pwsh"}
EVAL_FLAGS = {"-c", "/c", "/k", "-e", "-r", "--eval", "-command", "-Command", "--command"}
SCRIPT_RUNNERS = {
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "php",
    "lua",
    "tclsh",
    "Rscript",
}
PROGRAM_EVALUATORS = {"awk", "gawk", "mawk", "nawk", "sed", "jq", "expect"}
COMMAND_RUNNERS = {"env", "xargs", "sudo", "nohup", "timeout", "nice", "doas", "watch", "time"}
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
SQL_METHODS = {"execute", "executemany", "executescript"}
SQL_KEYWORDS = {"sql", "statement", "operation", "query"}
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


# Backwards-compatible name used by patch review (call counting only).
Scope = Semantics

_EMPTY: dict = {}


def _markup_arguments(arguments, sem):
    """Arguments of a Markup method/``%`` that are *not* escaped by it.

    Plain values are escaped by MarkupSafe; values that are visibly ``Markup(...)`` are inserted
    as-is, so their own content is analysed. For *detection* other values of unknown type are
    treated as plain (the common idiom); the adjudicator never relies on that assumption.
    """
    passed = []
    for argument in arguments:
        candidates = [argument]
        if isinstance(argument, ast.Name):
            candidates = [d for d in sem.defs(argument.id, argument) if isinstance(d, ast.AST)]
        for candidate in candidates:
            if isinstance(candidate, ast.Call) and sem.trusted(candidate.func) in MARKUP:
                passed.extend(candidate.args)
    return passed


def shape(category: str, node: ast.AST, sem: Semantics) -> Shape:
    """Classify an expression for one category without recursion."""
    sanitizers = SANITIZERS[category]
    result = Shape()
    stack: list[tuple] = [(node, 0, _EMPTY)]
    seen: set = set()
    work = 0
    while stack:
        work += 1
        if work > WORK_LIMIT:
            result.tainted = True
            break
        current, hops, env = stack.pop()
        key = (id(current), id(env), hops)
        if key in seen:
            continue
        seen.add(key)
        if isinstance(current, Guard):
            if category not in current.safe_for:
                stack.extend((d, hops, _EMPTY) for d in current.inner)
        elif isinstance(current, (Param, Unknown, Import)):
            result.tainted = True
        elif isinstance(current, Element):
            stack.append((current.iterable, hops, _EMPTY))
        elif isinstance(current, ast.Constant):
            if isinstance(current.value, str) and HTML_TAG.search(current.value):
                result.html = True
        elif isinstance(current, ast.Name):
            if current.id in env:
                iterable, outer = env[current.id]
                stack.append((iterable, hops, outer))
            elif hops < MAX_HOPS:
                stack.extend((d, hops + 1, _EMPTY) for d in sem.defs(current.id, current))
            else:
                result.tainted = True
        elif isinstance(current, ast.AugAssign):
            result.built = True
            stack.append((current.value, hops, _EMPTY))
            target = current.target
            if hops < MAX_HOPS and isinstance(target, ast.Name):
                stack.extend((d, hops + 1, _EMPTY) for d in sem.defs(target.id, current))
            else:
                result.tainted = True
        elif isinstance(current, COMPREHENSIONS):
            inner = dict(env)
            for generator in current.generators:
                outer = dict(inner)
                for name in ast.walk(generator.target):
                    if isinstance(name, ast.Name):
                        inner[name.id] = (generator.iter, outer)
            elements = (
                [current.key, current.value] if isinstance(current, ast.DictComp) else [current.elt]
            )
            stack.extend((element, hops, inner) for element in elements)
        elif isinstance(current, ast.JoinedStr):
            result.built = True
            stack.extend((value, hops, env) for value in current.values)
        elif isinstance(current, ast.FormattedValue):
            stack.append((current.value, hops, env))
        elif isinstance(current, ast.BinOp):
            result.built = result.built or isinstance(current.op, (ast.Add, ast.Mod))
            left = current.left
            if (
                isinstance(current.op, ast.Mod)
                and isinstance(left, ast.Call)
                and sem.trusted(left.func) in MARKUP
            ):
                stack.append((left, hops, env))  # Markup.__mod__ escapes plain arguments
                values = (
                    current.right.elts if isinstance(current.right, ast.Tuple) else [current.right]
                )
                stack.extend((v, hops, env) for v in _markup_arguments(values, sem))
            else:
                stack += [(left, hops, env), (current.right, hops, env)]
        elif isinstance(current, (ast.List, ast.Tuple, ast.Set)):
            stack.extend((element, hops, env) for element in current.elts)
        elif isinstance(current, ast.Dict):
            stack.extend((v, hops, env) for v in [*current.keys, *current.values] if v is not None)
        elif isinstance(current, ast.IfExp):
            stack += [(current.body, hops, env), (current.orelse, hops, env)]
        elif allowlisted(current, sem):
            continue
        elif isinstance(current, ast.Call):
            name = sem.trusted(current.func)
            if isinstance(current.func, ast.Attribute) and current.func.attr in {"format", "join"}:
                result.built = True
                receiver = current.func.value
                stack.append((receiver, hops, env))
                arguments = [*current.args, *(k.value for k in current.keywords)]
                escapes = (
                    current.func.attr == "format"
                    and isinstance(receiver, ast.Call)
                    and sem.trusted(receiver.func) in MARKUP
                )
                if escapes:  # Markup(...).format() escapes plain arguments, not Markup ones
                    arguments = _markup_arguments(arguments, sem)
                stack.extend((argument, hops, env) for argument in arguments)
            elif name in PASS_THROUGH:
                stack.extend((argument, hops, env) for argument in current.args)
            elif name is None or name not in sanitizers:
                result.tainted = True  # unknown call result, e.g. request.args.get(...)
        else:
            result.tainted = True  # attributes, subscripts, ...
    return result


def allowlisted(node: ast.AST, sem: Semantics) -> bool:
    """``ALLOWED[x]`` / ``ALLOWED.get(x, CONST)`` on a never-mutated module dict of constants."""
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
    return isinstance(target, ast.Name) and sem.constant_dict(target)


def _argument(call: ast.Call, keywords: set[str]) -> ast.AST | None:
    if call.args:
        return call.args[0]
    return next((kw.value for kw in call.keywords if kw.arg in keywords), None)


def shell_requested(call: ast.Call) -> bool | None:
    """True/False for a constant ``shell=`` keyword, None when it is not a constant."""
    for keyword in call.keywords:
        if keyword.arg == "shell":
            if isinstance(keyword.value, ast.Constant):
                return keyword.value.value is True
            return None
    return False


def argv_elements(call: ast.Call, name: str, sem: Semantics):
    """Elements of an argument vector when they are statically known, else None."""
    if name == "asyncio.create_subprocess_exec":
        values = list(call.args)
    else:
        argv = _argument(call, {"args"})
        if isinstance(argv, ast.Name):
            defs = sem.defs(argv.id, argv)
            if len(defs) != 1 or not isinstance(next(iter(defs)), (ast.List, ast.Tuple)):
                return None
            argv = next(iter(defs))
        if not isinstance(argv, (ast.List, ast.Tuple)):
            return None
        values = list(argv.elts)
    if not values or any(isinstance(v, ast.Starred) for v in values):
        return None
    return values


def program_name(element, sem: Semantics) -> str | None:
    text = sem.constant_string(element)
    return posixpath.basename(text) if text else None


def argv_injects(call: ast.Call, name: str, sem: Semantics) -> bool:
    """An argument vector whose program or interpreted argument is caller-controlled."""
    values = argv_elements(call, name, sem)
    if values is None:
        return False
    tainted = [shape("cmdi", v, sem).tainted for v in values]
    program = program_name(values[0], sem)
    if program is None:
        return True  # quoting does not make a caller-selected executable trustworthy
    if program in SHELLS | SCRIPT_RUNNERS | PROGRAM_EVALUATORS:
        if any(
            k.arg in {"input", "stdin"} and sem.constant_string(k.value) is None
            for k in call.keywords
        ):
            return True
    if not any(tainted[1:]):
        return False
    flags = [sem.constant_string(v) for v in values]
    if program in SHELLS or program in SCRIPT_RUNNERS:
        for index in range(1, len(values) - 1):
            if flags[index] in EVAL_FLAGS and any(tainted[index + 1 :]):
                return True
        if program in SCRIPT_RUNNERS and tainted[1]:
            return True  # the caller chooses the script
        return False
    if program in PROGRAM_EVALUATORS or program in COMMAND_RUNNERS:
        return True
    if program == "find":
        for index, flag in enumerate(flags):
            if flag in FIND_EXEC and any(tainted[index + 1 :]):
                return True
    return False


def sink_name(node: ast.Call, sem: Semantics) -> str | None:
    """Callee name for sink matching (see Semantics.loose); SQL methods match by attribute."""
    name = sem.loose(node.func)
    if name is None and isinstance(node.func, ast.Attribute):
        return "." + node.func.attr  # an object method such as cursor.execute
    if name is not None and name.split(".")[0] in {"sqlalchemy"} and name.endswith(".text"):
        return "sqlalchemy.text"
    return name


def source_category(node: ast.AST, sem: Semantics) -> str | None:
    if isinstance(node, ast.Return):
        if node.value is None:
            return None
        found = shape("xss", node.value, sem)
        return "xss" if found.tainted and found.built and found.html else None
    if not isinstance(node, ast.Call):
        return None
    name = sink_name(node, sem)
    if name is None:
        return None
    short = name.rsplit(".", 1)[-1]
    method = node.func.attr if isinstance(node.func, ast.Attribute) else None
    if method in SQL_METHODS or name in SQL_TEXT:
        query = _argument(node, SQL_KEYWORDS)
        if query is None:
            return None
        found = shape("sqli", query, sem)
        parameters = len(node.args) > 1 or any(kw.arg == "parameters" for kw in node.keywords)
        raw_query = method in SQL_METHODS and not parameters
        return "sqli" if found.tainted and (found.built or raw_query) else None
    shell = shell_requested(node)
    if name in SHELL_ALWAYS or (name in SHELL_OPTIONAL and shell is not False):
        command = _argument(node, {"args", "cmd", "command"})
        if command is None:
            return None
        if shape("cmdi", command, sem).tainted:
            return "cmdi"
        # POSIX quoting neutralises shell syntax, not a second explicitly invoked interpreter.
        prefix = command
        while isinstance(prefix, ast.BinOp) and isinstance(prefix.op, ast.Add):
            prefix = prefix.left
        text = sem.constant_string(prefix)
        if text is not None and sem.constant_string(command) is None:
            try:
                parts = shlex.split(text)
            except ValueError:
                parts = []
            if parts and posixpath.basename(parts[0]) in (
                SHELLS | SCRIPT_RUNNERS | PROGRAM_EVALUATORS | COMMAND_RUNNERS
            ):
                return "cmdi"
        return None
    if name in EXEC_ARGV and argv_injects(node, name, sem):
        return "cmdi"
    if short in {"render_template_string", "Markup"} and node.args:
        return "xss" if shape("xss", node.args[0], sem).tainted else None
    if short == "make_response" and node.args:
        found = shape("xss", node.args[0], sem)
        return "xss" if found.tainted and found.built and found.html else None
    return None


def _detect_source(artifact_id: UUID, parsed: ParsedInput) -> RuleResult:
    tree = parsed.private_tree
    if tree is None:
        return RuleResult([], ["源码规则未运行：AST 不可用，不能据此认为没有风险。"], False)
    sem = Semantics(tree)
    lines = parsed.content.split("\n")  # redacted view with identical line numbering
    seen: set[tuple[str, int]] = set()
    results: list[Finding] = []
    nodes = sorted(
        (node for node in ast.walk(tree) if isinstance(node, (ast.Call, ast.Return))),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for node in nodes:
        category = source_category(node, sem)
        if not category or (category, node.lineno) in seen:
            continue
        seen.add((category, node.lineno))
        start, end = node.lineno, node.end_lineno or node.lineno
        location = SourceLocation(artifact_id=artifact_id, start_line=start, end_line=end)
        results.append(finding(category, "\n".join(lines[start - 1 : end]), location))
        if len(results) > MAX_RULE_FINDINGS:
            break
    result = _limited(results)
    if sem.exhausted:
        result.truncated = True
        result.warnings.append("源码语义分析预算已耗尽；规则覆盖不完整，不能据此判定无风险。")
    return result


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
