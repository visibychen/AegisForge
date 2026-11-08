import json
from pathlib import Path

from app.core.errors import DomainError

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = ROOT / "samples" / "controlled" / "dev_cases.json"


def match_case(sha256):
    cases = json.loads(REGISTRY.read_text(encoding="utf-8"))["cases"]
    for case in cases:
        if case["source_sha256"] == sha256:
            return case
    raise DomainError(
        "CONTROLLED_SAMPLE_REQUIRED", "此源码不是登记的受控样例，运行时效果未验证。", 422
    )
