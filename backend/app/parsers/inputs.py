import ast
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from app.core.errors import DomainError
from app.core.redaction import MASK, redact_object, redact_text, sensitive

PARSER_VERSION = "inputs-1.0"
MAX_NORMALIZED = 80_000


@dataclass(frozen=True)
class Chunk:
    start_line: int
    end_line: int
    content: str


@dataclass
class ParsedInput:
    content: str
    fields: dict[str, str]
    features: list[dict]
    warnings: list[str]
    chunks: list[Chunk]


def chunks_for(text: str) -> list[Chunk]:
    if len(text) > MAX_NORMALIZED:
        raise DomainError("INPUT_BUDGET", "规范化内容超过 80,000 字符，请缩小输入。")
    lines = text.splitlines(keepends=True)
    chunks: list[Chunk] = []
    start = 0
    while start < len(lines):
        end, count = start, 0
        while end < len(lines) and count + len(lines[end]) <= 12_000:
            count += len(lines[end])
            end += 1
        if end == start:
            raise DomainError("LINE_BUDGET", "单行超过 12,000 字符，请缩小输入。")
        chunks.append(Chunk(start + 1, end, "".join(lines[start:end])))
        if len(chunks) > 8:
            raise DomainError("CHUNK_BUDGET", "输入超过 8 个分析分块，请缩小输入。")
        if end == len(lines):
            break
        overlap, next_start = 0, end
        while next_start > start + 1 and overlap + len(lines[next_start - 1]) <= 1000:
            next_start -= 1
            overlap += len(lines[next_start])
        start = next_start
    return chunks


def decode_input(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise DomainError("INVALID_ENCODING", "只接受 UTF-8 或 UTF-8 BOM 文本。") from exc
    if not text.strip() or any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        raise DomainError("INVALID_TEXT", "拒绝空内容、二进制或包含控制字符的文本。")
    return text


def qualified(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return qualified(node.value) + "." + node.attr
    return ""


def parse_source(text: str) -> ParsedInput:
    safe = redact_text(text)
    chunks = chunks_for(safe)
    features, warnings = [], []
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                features.append({"kind": "call", "name": qualified(node.func), "line": node.lineno})
            elif isinstance(node, (ast.JoinedStr, ast.BinOp)):
                features.append({"kind": "string_expression", "line": node.lineno})
            if len(features) >= 2000:
                warnings.append("特征预览达到 2,000 项上限；模型仍覆盖全部预算内文本。")
                break
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        warnings.append("Python AST 解析失败，仅提供文本线索，分析能力受限。")
    return ParsedInput(safe, {}, features, warnings, chunks)


def decoded(value: str) -> str:
    for _ in range(2):
        newer = unquote_plus(value)
        if newer == value:
            break
        value = newer
    return value


def parse_http(text: str) -> ParsedInput:
    # Offline grammar only: no URL is ever fetched or replayed.
    head, separator, body = text.partition("\n\n")
    lines = head.split("\n")
    match = re.fullmatch(r"([A-Z]{1,20}) ([^\s]+) HTTP/1\.[01]", lines[0])
    if not match or not separator or len(lines) > 101 or any(len(x) > 8192 for x in lines):
        raise DomainError("INVALID_HTTP", "需要完整的 HTTP/1.x 请求行、头部和空行。")
    fields: dict[str, str] = {"method": match[1]}
    try:
        url = urlsplit(match[2])
        if url.scheme and url.scheme not in {"http", "https"}:
            raise ValueError("scheme")
        if url.username or url.password:
            raise ValueError("userinfo")
        fields["path"] = redact_text(decoded(url.path))
        for index, (key, value) in enumerate(
            parse_qsl(url.query, keep_blank_values=True, max_num_fields=1000)
        ):
            fields[f"query.{key}[{index}]"] = (
                MASK if sensitive(key) else redact_text(decoded(value))
            )
    except ValueError as exc:
        raise DomainError("INVALID_HTTP", "HTTP 地址或参数格式不受支持。") from exc
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise DomainError("INVALID_HTTP", "HTTP 请求头格式错误。")
        key = name.lower()
        if key in headers:
            raise DomainError("INVALID_HTTP", "暂不支持重复请求头，请提交无歧义请求。")
        headers[key] = value.strip()
        fields[f"header.{key}"] = MASK if sensitive(key) else redact_text(value.strip())
    if "transfer-encoding" in headers:
        raise DomainError("UNSUPPORTED_HTTP_BODY", "不支持分块传输，请提交解码后的请求。")
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type == "application/json" and body.strip():
        try:
            document = redact_object(json.loads(body))
            fields["body"] = json.dumps(document, ensure_ascii=False)
        except (ValueError, RecursionError) as exc:
            raise DomainError("INVALID_HTTP", "JSON 正文无效。") from exc
    elif content_type == "application/x-www-form-urlencoded":
        try:
            for index, (key, value) in enumerate(
                parse_qsl(body, keep_blank_values=True, max_num_fields=1000)
            ):
                fields[f"body.{key}[{index}]"] = (
                    MASK if sensitive(key) else redact_text(decoded(value))
                )
        except ValueError as exc:
            raise DomainError("INVALID_HTTP", "正文参数过多。") from exc
    elif body:
        fields["body"] = redact_text(body)
    safe = "\n".join(f"{key}: {value}" for key, value in fields.items())
    return ParsedInput(safe, fields, [], ["离线请求特征不能证明服务端存在漏洞。"], chunks_for(safe))


def parse_input(input_type: str, text: str) -> ParsedInput:
    return parse_source(text) if input_type == "source" else parse_http(text)
