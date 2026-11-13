"""Immutable input snapshots.

Filesystem safety is scoped to a trusted single-user host: the data directory and the
``artifacts`` directory must not be symlinks/junctions, keys are internal random names,
snapshots are created exclusively and read without following links where the OS allows
(``O_NOFOLLOW`` on POSIX). A malicious process running as the same OS user can still race
these checks; that threat is out of scope and stated in docs/m2-design.md.
"""

import hashlib
import json
import os
import re
import stat
import unicodedata
from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.credentials import protect_snapshot
from app.core.errors import DomainError
from app.core.redaction import redact_name
from app.models import Artifact
from app.models.foundation import new_id
from app.parsers.inputs import PARSER_VERSION, ParsedInput, decode_input, parse_input
from app.rules.detector import RULE_VERSION, RuleResult, detect

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)


def _linked(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _artifact_root(settings: Settings) -> Path:
    data_dir = Path(settings.data_dir)
    root = data_dir / "artifacts"
    if _linked(data_dir) or _linked(root):
        raise DomainError("STORAGE_INVALID", "快照目录不可用。", 409)
    root.mkdir(parents=True, exist_ok=True)
    if _linked(root) or root.resolve(strict=True).parent != data_dir.resolve(strict=True):
        raise DomainError("STORAGE_INVALID", "快照目录不可用。", 409)
    return root


def storage_path(settings: Settings, key: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}\.blob", key):
        raise DomainError("STORAGE_INVALID", "快照不可用。", 409)
    path = _artifact_root(settings) / key
    if _linked(path):
        raise DomainError("STORAGE_INVALID", "快照不可用。", 409)
    return path


def _write_snapshot(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
    except BaseException:
        path.unlink(missing_ok=True)  # Only clean up a file this call created.
        raise


def _read_snapshot(path: Path, limit: int) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise DomainError("STORAGE_INVALID", "快照不可用。", 409)
        return stream.read(limit + 1)


def validate_name(name: str, kind: str) -> None:
    if (
        not name
        or len(name) > 150
        or name in {".", ".."}
        or re.search(r'[\\/:<>"|?*]', name)
        or any(unicodedata.category(c)[0] == "C" or c in "  " for c in name)
    ):
        raise DomainError("INVALID_FILENAME", "文件名不得包含路径、控制或特殊字符。")
    suffix = Path(name).suffix.lower()
    if suffix not in ({".py"} if kind == "source" else {".http", ".req", ".txt"}):
        raise DomainError("UNSUPPORTED_FILE", "文件后缀与输入类型不匹配。")


def build_preview(artifact: Artifact, parsed: ParsedInput, rules: RuleResult) -> dict:
    """Public, redacted view. Never include ParsedInput private attributes here."""
    return {
        "id": artifact.id,
        "input_type": artifact.input_type,
        "display_name": artifact.display_name,
        "sha256": artifact.sha256,
        "size_bytes": artifact.size_bytes,
        "parser_version": PARSER_VERSION,
        "rule_version": RULE_VERSION,
        "content": parsed.content,
        "fields": parsed.fields,
        "field_meta": parsed.field_meta,
        "features": parsed.features,
        "warnings": [*parsed.warnings, *rules.warnings],
        "chunk_count": len(parsed.chunks),
        "rule_findings": [item.model_dump(mode="json") for item in rules.findings],
        "rule_findings_truncated": rules.truncated,
    }


def store_artifact(
    session: Session, settings: Settings, name: str, kind: str, raw: bytes, *, commit=True
) -> dict:
    """Validate everything, including the full preview, before anything is persisted."""
    validate_name(name, kind)
    if not raw or len(raw) > settings.max_file_bytes:
        raise DomainError("FILE_SIZE", "文件为空或超过单文件大小限制。", 413)
    text = decode_input(raw)
    parsed = parse_input(kind, text)
    protect_snapshot(settings, name, text, parsed)
    artifact = Artifact(
        id=new_id(),
        input_type=kind,
        language="python" if kind == "source" else None,
        display_name=redact_name(name),
        storage_key=os.urandom(16).hex() + ".blob",
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )
    payload = build_preview(artifact, parsed, detect(UUID(artifact.id), kind, parsed))
    json.dumps(payload)  # a preview that cannot be served must fail now, not after commit
    path = storage_path(settings, artifact.storage_key)
    created = False
    try:
        _write_snapshot(path, raw)
        created = True
        session.add(artifact)
        session.commit() if commit else session.flush()
    except Exception:
        session.rollback()
        if created:
            path.unlink(missing_ok=True)
        raise
    return payload


def load_artifact(settings: Settings, artifact: Artifact) -> ParsedInput:
    path = storage_path(settings, artifact.storage_key)
    try:
        raw = _read_snapshot(path, settings.max_file_bytes)
    except OSError as exc:
        raise DomainError("SNAPSHOT_MISSING", "原始快照缺失，无法继续分析。", 409) from exc
    if len(raw) != artifact.size_bytes or hashlib.sha256(raw).hexdigest() != artifact.sha256:
        raise DomainError("SNAPSHOT_CHANGED", "原始快照校验失败。", 409)
    text = decode_input(raw)
    parsed = parse_input(artifact.input_type, text)
    protect_snapshot(settings, artifact.display_name, text, parsed)
    return parsed


def preview(settings: Settings, artifact: Artifact) -> dict:
    parsed = load_artifact(settings, artifact)
    return build_preview(artifact, parsed, detect(UUID(artifact.id), artifact.input_type, parsed))
