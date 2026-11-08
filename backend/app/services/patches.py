"""Pure static patch application. Uploaded/model code is never executed here."""

import ast
import difflib
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import DomainError
from app.core.redaction import redact_source
from app.parsers.inputs import decode_input

NO_NEWLINE = "\\ No newline at end of file"
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class Edit(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    old_text: str = Field(min_length=1, max_length=12000)
    new_text: str = Field(max_length=16000)


class RepairWire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["repair-1.0"]
    edits: list[Edit] = Field(min_length=1, max_length=8)
    explanation: str = Field(min_length=1, max_length=2000)


def make_diff(source: str, candidate: str) -> str:
    """Unified diff whose unterminated lines carry the standard marker, so it stays applicable."""
    rows = difflib.unified_diff(
        source.splitlines(True),
        candidate.splitlines(True),
        fromfile="original.py",
        tofile="candidate.py",
    )
    return "".join(row if row.endswith("\n") else row + "\n" + NO_NEWLINE + "\n" for row in rows)


def apply_unified_diff(source: str, diff: str) -> str:
    """Minimal strict applier for diffs produced by :func:`make_diff` (round-trip self-check)."""
    old, out, index = source.splitlines(True), [], 0
    rows, position = diff.splitlines(True), 0
    while position < len(rows) and not rows[position].startswith("@@"):
        position += 1
    while position < len(rows):
        match = _HUNK.match(rows[position])
        if match is None:
            raise ValueError("hunk header")
        count = 1 if match[2] is None else int(match[2])
        start = int(match[1]) - 1 if count else int(match[1])
        position += 1
        body: list[tuple[str, str]] = []
        while position < len(rows) and not rows[position].startswith("@@"):
            row = rows[position]
            if row.startswith("\\"):
                if not body:
                    raise ValueError("orphan marker")
                tag, text = body[-1]
                body[-1] = (tag, text[:-1] if text.endswith("\n") else text)
            elif row[:1] in {" ", "+", "-"}:
                body.append((row[0], row[1:]))
            else:
                raise ValueError("hunk row")
            position += 1
        if start < index:
            raise ValueError("hunk order")
        out.extend(old[index:start])
        index = start
        for tag, text in body:
            if tag == "+":
                out.append(text)
                continue
            if index >= len(old) or old[index] != text:
                raise ValueError("context mismatch")
            if tag == " ":
                out.append(text)
            index += 1
    out.extend(old[index:])
    return "".join(out)


def apply_edits(source: str, edits: list[Edit]):
    lines = source.splitlines(keepends=True)
    ordered = sorted(edits, key=lambda e: e.start_line)
    previous, parts, cursor = 0, [], 0
    for edit in ordered:
        if not previous < edit.start_line <= edit.end_line <= len(lines):
            raise DomainError("PATCH_RANGE", "编辑范围越界、重叠或顺序不正确。", 422)
        old = "".join(lines[edit.start_line - 1 : edit.end_line])
        if old != edit.old_text:
            raise DomainError("PATCH_CONFLICT", "编辑原文与不可变快照不匹配。", 409)
        if edit.new_text and old.endswith("\n") and not edit.new_text.endswith("\n"):
            raise DomainError(
                "PATCH_NEWLINE", "替换文本必须保留原有的行结束，避免与下一行粘连。", 422
            )
        parts.extend(["".join(lines[cursor : edit.start_line - 1]), edit.new_text])
        cursor, previous = edit.end_line, edit.end_line
    parts.append("".join(lines[cursor:]))
    candidate = "".join(parts)
    if not candidate.strip() or len(candidate) > 12000:
        raise DomainError("PATCH_SIZE", "候选为空或超过单块修复上限。", 422)
    try:
        # The candidate becomes a snapshot: it must survive the same input rules (no CR,
        # control characters, exotic line separators or stray BOM) before any further spend.
        if decode_input(candidate.encode("utf-8")) != candidate:
            raise DomainError("PATCH_ENCODING", "候选含有不被接受的字符或换行。", 422)
    except (DomainError, UnicodeError):
        raise DomainError("PATCH_ENCODING", "候选含有不被接受的字符或换行。", 422) from None
    if redact_source(candidate) != candidate:
        raise DomainError("PATCH_SENSITIVE", "候选包含需要脱敏的凭据内容。", 422)
    try:
        ast.parse(candidate)
    except (SyntaxError, ValueError, RecursionError):
        raise DomainError("PATCH_SYNTAX", "候选未通过 Python 静态语法校验。", 422) from None
    diff = make_diff(source, candidate)
    try:
        replayed = apply_unified_diff(source, diff)
    except ValueError:
        replayed = None
    if replayed != candidate:
        raise DomainError("PATCH_DIFF_MISMATCH", "生成的补丁无法精确还原候选。", 422)
    return candidate, diff
