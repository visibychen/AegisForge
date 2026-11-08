"""Pure static patch application. Uploaded/model code is never executed here."""

import ast
import difflib

from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import DomainError
from app.core.redaction import redact_source


class Edit(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    old_text: str = Field(min_length=1, max_length=12000)
    new_text: str = Field(max_length=16000)


class RepairWire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: str = Field(pattern="^repair-1.0$")
    edits: list[Edit] = Field(min_length=1, max_length=8)
    explanation: str = Field(min_length=1, max_length=2000)


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
        parts.extend(["".join(lines[cursor : edit.start_line - 1]), edit.new_text])
        cursor, previous = edit.end_line, edit.end_line
    parts.append("".join(lines[cursor:]))
    candidate = "".join(parts)
    if not candidate.strip() or len(candidate) > 12000:
        raise DomainError("PATCH_SIZE", "候选为空或超过单块修复上限。", 422)
    if redact_source(candidate) != candidate:
        raise DomainError("PATCH_SENSITIVE", "候选包含需要脱敏的凭据内容。", 422)
    try:
        ast.parse(candidate)
    except (SyntaxError, ValueError, RecursionError):
        raise DomainError("PATCH_SYNTAX", "候选未通过 Python 静态语法校验。", 422) from None
    diff = "".join(
        difflib.unified_diff(
            source.splitlines(True),
            candidate.splitlines(True),
            fromfile="original.py",
            tofile="candidate.py",
        )
    )
    return candidate, diff
