"""Content checksum of an exported report; deliberately not a digital signature."""

import hashlib
import json
import os
import stat

VERSION = "report-2.1"
MAX_BYTES = 4 * 1024 * 1024
REQUIRED = {
    "schema_version",
    "scan",
    "findings",
    "findings_by_attempt",
    "repairs",
    "attempts",
    "source_free",
    "notice",
    "limits",
    "truncated",
    "generated_at",
    "content_digest",
}


def report_digest(report):
    body = {k: v for k, v in report.items() if k not in {"generated_at", "content_digest"}}
    encoded = json.dumps(
        body, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(b"aegisforge-report-2.1\n" + encoded).hexdigest()


def seal_report(report):
    value = {**report, "content_digest": report_digest(report)}
    if len(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")) > MAX_BYTES:
        from app.core.errors import DomainError

        raise DomainError("REPORT_SIZE_LIMIT", "报告超出导出大小限制。", 422)
    return value


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("non-finite number")


def verify_bytes(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("size")
    report = json.loads(
        raw.decode("utf-8"), object_pairs_hook=strict_object, parse_constant=reject_constant
    )
    if (
        not isinstance(report, dict)
        or not REQUIRED <= report.keys()
        or report["schema_version"] != VERSION
        or report["source_free"] is not True
        or not isinstance(report["scan"], dict)
        or any(not isinstance(report[k], list) for k in ("findings", "repairs", "attempts"))
        or report["content_digest"] != report_digest(report)
    ):
        raise ValueError("invalid report")
    return report


def read_report(path):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    if os.name == "nt" and not os.path.isfile(path):
        raise ValueError("regular file required")
    with os.fdopen(os.open(path, flags | getattr(os, "O_BINARY", 0)), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular file required")
        return verify_bytes(stream.read(MAX_BYTES + 1))
