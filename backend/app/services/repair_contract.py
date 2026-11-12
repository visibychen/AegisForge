"""Actual execution metadata, not a signature or a promise of deterministic model output."""

from app.core.redaction import REDACTION_VERSION
from app.llm.prompts import PROMPT_VERSION
from app.llm.repair import REPAIR_PROMPT_VERSION
from app.parsers.inputs import PARSER_VERSION
from app.rules.detector import RULE_VERSION
from app.services.adjudicate import ADJUDICATION_VERSION
from app.services.merge import MERGE_VERSION
from app.services.patch_review import PATCH_REVIEW_VERSION
from app.services.receipts import digest


def seal_contract(value):
    body = {k: v for k, v in value.items() if k != "digest"}
    return {**body, "digest": digest(body)}


def capture_contract(settings, repair, scan):
    return seal_contract(
        {
            "schema_version": "repair-contract-1.0",
            "source_sha256": repair.source_sha256,
            "finding_anchor": repair.anchor,
            "parent_attempt": scan.retries,
            "model_alias": repair.model_alias,
            "model": settings.deepseek_model if repair.model_alias != "fake" else None,
            "versions": {
                "repair_prompt": REPAIR_PROMPT_VERSION,
                "repair_wire": "repair-1.0",
                "analysis_prompt": PROMPT_VERSION,
                "rules": RULE_VERSION,
                "patch_review": PATCH_REVIEW_VERSION,
                "parser": PARSER_VERSION,
                "redaction": REDACTION_VERSION,
                "merge": MERGE_VERSION,
                "adjudication": ADJUDICATION_VERSION,
            },
            "parameters": {
                "max_tokens": settings.model_output_tokens,
                "thinking": {"type": "disabled"},
                "temperature": 0,
                "response_format": "json_object",
                "stream": False,
            },
            "limits": {
                "call_timeout_seconds": settings.model_timeout_seconds,
                "task_timeout_seconds": settings.task_timeout_seconds,
            },
        }
    )
