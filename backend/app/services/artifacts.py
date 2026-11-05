import hashlib
import re
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.redaction import redact_text
from app.models import Artifact
from app.parsers.inputs import PARSER_VERSION, decode_input, parse_input
from app.rules.detector import RULE_VERSION, detect


def storage_path(settings: Settings, key: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}\.blob", key):
        raise DomainError("STORAGE_INVALID", "快照不可用。", 409)
    root = settings.data_dir / "artifacts"
    if root.is_symlink() or root.is_junction():
        raise DomainError("STORAGE_INVALID", "快照目录不可用。", 409)
    root.mkdir(parents=True, exist_ok=True)
    path = root / key
    if path.is_symlink() or path.is_junction():
        raise DomainError("STORAGE_INVALID", "快照不可用。", 409)
    return path


def store_artifact(
    session: Session, settings: Settings, name: str, kind: str, raw: bytes
) -> Artifact:
    if (
        not name
        or len(name) > 150
        or name in {".", ".."}
        or re.search(r'[\\/:<>"|?*\x00-\x1f]', name)
    ):
        raise DomainError("INVALID_FILENAME", "文件名不得包含路径或特殊字符。")
    suffix = Path(name).suffix.lower()
    if suffix not in ({".py"} if kind == "source" else {".http", ".req", ".txt"}):
        raise DomainError("UNSUPPORTED_FILE", "文件后缀与输入类型不匹配。")
    if not raw or len(raw) > settings.max_file_bytes:
        raise DomainError("FILE_SIZE", "文件为空或超过单文件大小限制。", 413)
    text = decode_input(raw)
    parse_input(kind, text)  # Validate before committing anything to disk.
    key = uuid4().hex + ".blob"
    path = storage_path(settings, key)
    artifact = Artifact(
        input_type=kind,
        language="python" if kind == "source" else None,
        display_name=redact_text(name),
        storage_key=key,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )
    try:
        with path.open("xb") as stream:
            stream.write(raw)
        session.add(artifact)
        session.commit()
        session.refresh(artifact)
    except Exception:
        session.rollback()
        path.unlink(missing_ok=True)
        raise
    return artifact


def load_artifact(settings: Settings, artifact: Artifact):
    path = storage_path(settings, artifact.storage_key)
    try:
        with path.open("rb") as stream:
            raw = stream.read(settings.max_file_bytes + 1)
    except OSError as exc:
        raise DomainError("SNAPSHOT_MISSING", "原始快照缺失，无法继续分析。", 409) from exc
    if len(raw) != artifact.size_bytes or hashlib.sha256(raw).hexdigest() != artifact.sha256:
        raise DomainError("SNAPSHOT_CHANGED", "原始快照校验失败。", 409)
    return parse_input(artifact.input_type, decode_input(raw))


def preview(settings: Settings, artifact: Artifact) -> dict:
    parsed = load_artifact(settings, artifact)
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
        "features": parsed.features,
        "warnings": parsed.warnings,
        "chunk_count": len(parsed.chunks),
        "rule_findings": [
            f.model_dump(mode="json")
            for f in detect(UUID(artifact.id), artifact.input_type, parsed)
        ],
    }
