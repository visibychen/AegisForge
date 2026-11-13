"""Input decoding, offline parsing and budgeting.

Every public view (preview content, fields, field metadata, features, chunks for the model,
rule evidence) is redacted. The original source text, its AST and unredacted normalized
HTTP values are kept on ``ParsedInput`` private attributes for in-memory rule matching only
and must never be serialized.
"""

import ast
import json
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus, urlsplit

from app.core.errors import DomainError
from app.core.redaction import MASK, redact_name, redact_source, redact_text, sensitive

PARSER_VERSION = "inputs-1.2"
MAX_NORMALIZED = 80_000
MAX_LINE = 12_000
MAX_CHUNKS = 8
MAX_OVERLAP = 1_000
MAX_HEADER_LINE = 8_192
MAX_HEADERS = 100
MAX_DECODE_PASSES = 2
MAX_FIELDS = 1_000
MAX_JSON_DEPTH = 32
MAX_FEATURES = 2_000
LINE_SEPARATORS = frozenset("\x85  ")
SUPPORTED_BODIES = "仅支持 JSON、application/x-www-form-urlencoded 与 text/plain 正文"
REQUEST_FIELDS = frozenset(
    {
        "args",
        "form",
        "values",
        "json",
        "data",
        "cookies",
        "headers",
        "view_args",
        "get_json",
        "get_data",
    }
)
SHELL_CALLS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)
TEXT_CALL = re.compile(
    r"\b((?:[A-Za-z_]\w{0,63}\.){0,4}(?:system|popen|execute|executemany|executescript|"
    r"render_template_string|Markup|make_response))\s*\("
)


def sink_category(name: str) -> str | None:
    if name in SHELL_CALLS:
        return "cmdi"
    if name.rsplit(".", 1)[-1] in {"execute", "executemany", "executescript"}:
        return "sqli"
    if name.rsplit(".", 1)[-1] in {"render_template_string", "Markup", "make_response"}:
        return "xss"
    return None


@dataclass(frozen=True)
class Chunk:
    start_line: int
    end_line: int
    content: str


@dataclass
class ParsedInput:
    content: str
    fields: dict[str, str]
    field_meta: dict[str, dict]
    features: list[dict]
    warnings: list[str]
    chunks: list[Chunk]
    # Server-memory only. Never serialize these two attributes.
    private_tree: ast.Module | None = field(default=None, repr=False)
    private_fields: dict[str, str] = field(default_factory=dict, repr=False)


def check_budget(text: str) -> None:
    """Reject oversized input before any regex or parser touches it."""
    if len(text) > MAX_NORMALIZED:
        raise DomainError("INPUT_BUDGET", "内容超过 80,000 字符，请缩小输入。")
    if any(len(line) > MAX_LINE for line in text.split("\n")):
        raise DomainError("LINE_BUDGET", "单行超过 12,000 字符，请缩小输入。")


def chunks_for(text: str) -> list[Chunk]:
    """Line-aligned chunks: lines joined by LF without a trailing LF, each <= MAX_LINE chars.

    Every line is covered, chunk line numbers are global, overlap stays <= MAX_OVERLAP chars.
    """
    check_budget(text)
    lines = text.split("\n")
    if len(lines) > 1 and lines[-1] == "":
        lines.pop()  # a final LF does not start another line
    chunks: list[Chunk] = []
    start = 0
    while start < len(lines):
        end, size = start, 0
        while end < len(lines):
            added = len(lines[end]) + (1 if end > start else 0)
            if size + added > MAX_LINE:
                break
            size += added
            end += 1
        if end == start:  # unreachable after check_budget; never emit an empty chunk
            raise DomainError("LINE_BUDGET", "单行超过 12,000 字符，请缩小输入。")
        chunks.append(Chunk(start + 1, end, "\n".join(lines[start:end])))
        if len(chunks) > MAX_CHUNKS:
            raise DomainError("CHUNK_BUDGET", "输入超过 8 个分析分块，请缩小输入。")
        if end == len(lines):
            break
        overlap, next_start = 0, end
        while next_start > start + 1:
            added = len(lines[next_start - 1]) + 1
            if overlap + added > MAX_OVERLAP:
                break
            next_start -= 1
            overlap += added
        start = next_start
    return chunks


def decode_input(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DomainError("INVALID_ENCODING", "只接受 UTF-8 或 UTF-8 BOM 文本。") from exc
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise DomainError("INVALID_TEXT", "拒绝孤立的 CR 换行，请使用 LF 或 CRLF。")
    if any(c in LINE_SEPARATORS for c in text):
        raise DomainError("INVALID_TEXT", "不支持 U+0085/U+2028/U+2029 行分隔符，以免行号错位。")
    if not text.strip() or any(ord(c) < 32 and c not in "\n\t" for c in text):
        raise DomainError("INVALID_TEXT", "拒绝空内容、二进制或包含控制字符的文本。")
    return text


def qualified(node: ast.AST) -> str:
    """Dotted name of a call target; non-name roots become ``?`` (iterative, no recursion)."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    parts.append(node.id if isinstance(node, ast.Name) else "?")
    return ".".join(reversed(parts))


def parse_source(text: str) -> ParsedInput:
    check_budget(text)
    public = redact_source(text)
    chunks = chunks_for(public)
    features: list[dict] = []
    warnings: list[str] = []
    tree = None
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        warnings.append("Python AST 解析失败：仅提供文本线索，源码规则未运行，分析能力受限。")
    if tree is not None:
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

        def canonical(name: str) -> str:
            root, dot, rest = name.partition(".")
            return aliases.get(root, root) + dot + rest

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                original = qualified(node.func)
                feature = {"kind": "call", "name": redact_name(original)[:200], "line": node.lineno}
                category = sink_category(canonical(original))
                if category:
                    feature["sink_candidate"] = category  # A sink alone is not a vulnerability.
                features.append(feature)
            elif isinstance(node, ast.JoinedStr) or (
                isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
            ):
                features.append({"kind": "string_expression", "line": node.lineno})
            elif isinstance(node, ast.Attribute):
                original = qualified(node)
                name = canonical(original)
                root, _, member = name.rpartition(".")
                if root in {"request", "flask.request"} and member in REQUEST_FIELDS:
                    features.append(
                        {
                            "kind": "input_source",
                            "name": redact_name(original)[:200],
                            "line": node.lineno,
                        }
                    )
            if len(features) >= MAX_FEATURES:
                warnings.append("特征预览达到 2,000 项上限；模型仍覆盖全部预算内文本。")
                break
    else:
        # Text hints never become AST-verified rule findings. Expose names/line numbers,
        # not raw snippets or credentials from the private matching view.
        for line_number, line in enumerate(text.split("\n"), 1):
            for match in TEXT_CALL.finditer(line):
                features.append(
                    {
                        "kind": "text_call_hint",
                        "name": redact_name(match[1])[:200],
                        "line": line_number,
                    }
                )
                if len(features) >= MAX_FEATURES:
                    break
            if len(features) >= MAX_FEATURES:
                warnings.append("文本线索预览达到 2,000 项上限。")
                break
    return ParsedInput(public, {}, {}, features, warnings, chunks, private_tree=tree)


def decode_component(raw: str, form: bool) -> tuple[str, int, bool]:
    """Percent-decode at most twice in total; report whether encoded data remains."""
    value, passes = raw, 0
    while passes < MAX_DECODE_PASSES:
        newer = unquote_plus(value) if form and passes == 0 else unquote(value)
        if newer == value:
            break
        value, passes = newer, passes + 1
    return value, passes, passes == MAX_DECODE_PASSES and unquote(value) != value


def printable(value: str) -> str:
    """Escape control/format characters so one public field always stays on one line."""
    return "".join(
        c if c.isprintable() or c == " " else f"\\x{ord(c):02x}" if ord(c) < 256 else "�"
        for c in value
    )


_PATH_TOKEN = re.compile(r"(?=[A-Za-z0-9_\-.~=]{0,4096}\d)(?=[A-Za-z0-9_\-.~=]{0,4096}[A-Za-z])")


def redact_path(path: str) -> str:
    """Mask matrix parameters and long opaque path segments (reset links, API keys)."""
    segments = []
    for segment in redact_text(path).split("/"):
        opaque = len(segment) >= 24 and re.fullmatch(r"[A-Za-z0-9_\-.~=]+", segment)
        segments.append(MASK if opaque and _PATH_TOKEN.match(segment) else segment)
    return "/".join(segments)


class _HttpFields:
    def __init__(self, text: str):
        self.starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]
        self.public: dict[str, str] = {}
        self.meta: dict[str, dict] = {}
        self.private: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        self.limited = False

    def add(self, part, name, value, *, offset=None, length=0, passes=0, limited=False, mask=False):
        if len(self.public) >= MAX_FIELDS:
            raise DomainError("HTTP_FIELD_BUDGET", "HTTP 字段超过 1,000 个，请缩小输入。")
        index = self.counts.get(part, 0)
        self.counts[part] = index + 1
        field_id = f"{part}.{index}"
        masked = mask or sensitive(name)
        public_name = printable(redact_name(name))
        if len(public_name) > 120:
            public_name = public_name[:120] + "…"
        public_value = (
            MASK
            if masked
            else printable(redact_path(value) if part == "path" else redact_text(value))
        )
        meta = {"part": part, "name": public_name, "decode_passes": passes, "masked": masked}
        if offset is not None:
            line = bisect_right(self.starts, offset)
            column = offset - self.starts[line - 1]
            meta |= {"line": line, "raw_start": column, "raw_end": column + length}
        if limited:
            meta["decode_limited"] = True
            self.limited = True
        self.public[field_id], self.meta[field_id], self.private[field_id] = (
            public_value,
            meta,
            value,
        )


def _pairs(raw: str, base: int):
    """Split ``a=b&c=d`` keeping the raw offset/length of every value."""
    offset = 0
    for piece in raw.split("&"):
        if piece:
            key, equals, value = piece.partition("=")
            yield key, value, base + offset + len(key) + len(equals), len(value)
        offset += len(piece) + 1


def _add_pairs(fields: _HttpFields, part: str, raw: str, base: int) -> None:
    for key, value, offset, length in _pairs(raw, base):
        name = decode_component(key, True)[0]
        decoded, passes, limited = decode_component(value, True)
        fields.add(
            part, name, decoded, offset=offset, length=length, passes=passes, limited=limited
        )


def _add_json(fields: _HttpFields, body: str) -> None:
    try:
        document = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise DomainError("INVALID_HTTP", "JSON 正文无效或嵌套过深。") from exc
    stack = [("$", document, 0, False)]
    while stack:
        path, value, depth, masked = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise DomainError("INVALID_HTTP", "JSON 嵌套超过 32 层。")
        if isinstance(value, dict):
            for key, item in reversed(list(value.items())):
                stack.append((f"{path}.{key}", item, depth + 1, masked or sensitive(str(key))))
        elif isinstance(value, list):
            for index, item in reversed(list(enumerate(value))):
                stack.append((f"{path}[{index}]", item, depth + 1, masked))
        else:
            text = value if isinstance(value, str) else json.dumps(value)
            fields.add("json", path, text, mask=masked)


def _check_length(headers: dict[str, str], body: str) -> None:
    declared = headers.get("content-length")
    if declared is None:
        return
    if not (declared.isascii() and declared.isdigit() and len(declared) <= 10):
        raise DomainError("AMBIGUOUS_HTTP_LENGTH", "Content-Length 不是有效数字。")
    accepted = set()
    for candidate in {body, body[:-1] if body.endswith("\n") else body}:
        size = len(candidate.encode("utf-8"))
        accepted |= {size, size + candidate.count("\n")}  # LF or original CRLF line ends
    if int(declared) not in accepted:
        raise DomainError(
            "AMBIGUOUS_HTTP_LENGTH", "Content-Length 与正文长度不一致，请提交无歧义的请求。"
        )


def parse_http(text: str) -> ParsedInput:
    # Offline grammar only: no URL is ever fetched or replayed.
    check_budget(text)
    head, separator, body = text.partition("\n\n")
    lines = head.split("\n")
    match = re.fullmatch(r"([A-Z]{1,20}) (\S+) HTTP/1\.[01]", lines[0])
    if (
        not match
        or not separator
        or len(lines) > MAX_HEADERS + 1
        or any(len(line) > MAX_HEADER_LINE for line in lines)
    ):
        raise DomainError("INVALID_HTTP", "需要完整的 HTTP/1.x 请求行、头部和空行。")
    fields = _HttpFields(text)
    fields.add("method", "method", match[1])
    target, target_offset = match[2], len(match[1]) + 1
    try:
        url = urlsplit(target)
        if url.scheme and url.scheme not in {"http", "https"}:
            raise ValueError("scheme")
        if url.username or url.password:
            raise ValueError("userinfo")
    except ValueError as exc:
        raise DomainError("INVALID_HTTP", "HTTP 地址格式不受支持。") from exc
    if url.path:
        path_offset = target_offset + target.find(url.path, len(url.scheme) + len(url.netloc))
        path, passes, limited = decode_component(url.path, False)
        fields.add(
            "path", "path", path, offset=path_offset, length=len(url.path), passes=passes,
            limited=limited,
        )  # fmt: skip
    if url.query:
        _add_pairs(fields, "query", url.query, target_offset + target.index("?") + 1)
    if url.fragment:
        fragment, passes, limited = decode_component(url.fragment, False)
        fields.add("fragment", "fragment", fragment, passes=passes, limited=limited)
    headers: dict[str, str] = {}
    offset = len(lines[0]) + 1
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}", name):
            raise DomainError("INVALID_HTTP", "HTTP 请求头格式错误。")
        key = name.lower()
        if key in headers:
            raise DomainError("INVALID_HTTP", "暂不支持重复请求头，请提交无歧义请求。")
        stripped = value.strip()
        headers[key] = stripped
        value_offset = offset + len(name) + 1 + (len(value) - len(value.lstrip()))
        fields.add("header", key, stripped, offset=value_offset, length=len(stripped))
        offset += len(line) + 1
    if "transfer-encoding" in headers:
        raise DomainError("UNSUPPORTED_HTTP_BODY", "不支持分块传输，请提交解码后的请求。")
    _check_length(headers, body)
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    body_offset = len(head) + 2
    if body.strip():
        if content_type == "application/json" or content_type.endswith("+json"):
            _add_json(fields, body)
        elif content_type == "application/x-www-form-urlencoded":
            _add_pairs(fields, "form", body.rstrip("\n"), body_offset)
        elif content_type in {"", "text/plain"}:
            fields.add("body", "body", body, offset=body_offset, length=len(body))
        else:
            raise DomainError("UNSUPPORTED_HTTP_BODY", SUPPORTED_BODIES + "；请转换后再提交。")
    warnings = ["离线请求特征不能证明服务端存在漏洞。"]
    if fields.limited:
        warnings.append("部分字段在 2 次 URL 解码后仍含编码，已停止继续解码。")
    content = "\n".join(
        f"{field_id} {fields.meta[field_id]['name']} = {value}"
        for field_id, value in fields.public.items()
    )
    return ParsedInput(
        content,
        fields.public,
        fields.meta,
        [],
        warnings,
        chunks_for(content),
        private_fields=fields.private,
    )


def parse_input(input_type: str, text: str) -> ParsedInput:
    return parse_source(text) if input_type == "source" else parse_http(text)
