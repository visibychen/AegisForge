"""Pure (Docker-free) helpers shared by the API and the trusted validation runner."""

import hashlib
import json
from pathlib import Path

from app.core.errors import DomainError
from app.services.receipts import digest

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = ROOT / "samples" / "controlled" / "dev_cases.json"
# Everything that defines what the validator image does; also hashed by build_validator.py.
VALIDATOR_FILES = ("Dockerfile", "requirements.lock", "harness.py", "target.py", "ping_stub.py")


def load_cases() -> list[dict]:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))["cases"]


def match_case(sha256):
    for case in load_cases():
        if case["source_sha256"] == sha256:
            return case
    raise DomainError(
        "CONTROLLED_SAMPLE_REQUIRED", "此源码不是登记的受控样例，运行时效果未验证。", 422
    )


def registry_digest() -> str:
    """Hash of the registered cases (text mode, so Windows checkouts hash like Linux ones)."""
    return hashlib.sha256(REGISTRY.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def tests_digest(case: dict) -> str:
    return digest({"id": case["id"], "tests": case["tests"]})


def validator_fingerprint() -> str:
    context = ROOT / "deploy" / "validator"
    payload = b"".join(
        (context / name).read_bytes().replace(b"\r\n", b"\n") for name in VALIDATOR_FILES
    )
    return hashlib.sha256(payload).hexdigest()


def seal(record: dict) -> dict:
    """Attach an integrity digest. It detects accidental or casual edits; it is not a signature."""
    body = {k: v for k, v in record.items() if k != "digest"}
    return {**body, "digest": digest(body)}


def dynamic_binding(source_sha256, dynamic: dict, candidate_sha256):
    """None: nothing to bind yet; True/False: result belongs / does not belong to this candidate."""
    if dynamic.get("status") not in {"passed", "failed"}:
        return None
    body = {k: v for k, v in dynamic.items() if k != "digest"}
    return (
        dynamic.get("digest") == digest(body)
        and candidate_sha256 is not None
        and dynamic.get("candidate_sha256") == candidate_sha256
        and dynamic.get("source_sha256") == source_sha256
    )
