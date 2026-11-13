"""Whitelisted analysis receipts: no source, names, paths, secrets or model free text."""

import hashlib
import json
from uuid import UUID

from app.core.errors import DomainError
from app.core.redaction import REDACTION_VERSION
from app.llm.prompts import PROMPT_VERSION, messages
from app.llm.wire import WIRE_SCHEMA_VERSION
from app.parsers.inputs import PARSER_VERSION
from app.rules.detector import RULE_VERSION
from app.schemas.contracts import AnalysisRequest
from app.services.merge import SEVERITY_POLICY


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def build_receipt(settings, strategy, alias, pairs):
    inputs, artifacts = [], []
    for artifact, parsed in pairs:
        identity = {"input_type": artifact.input_type, "sha256": artifact.sha256}
        inputs.append(identity)
        artifacts.append(
            {
                **identity,
                "artifact_id": artifact.id,
                "normalized_sha256": digest(parsed.content),
                "fields_sha256": digest(parsed.fields),
                "chunks": [
                    {
                        "chunk": index,
                        "start_line": chunk.start_line,
                        "end_line": chunk.end_line,
                        "sha256": digest(chunk.content),
                    }
                    for index, chunk in enumerate(parsed.chunks)
                ],
            }
        )
    # IDs and order of upload do not change input identity; multiplicity is retained.
    input_digest = digest(sorted(inputs, key=canonical))
    uses_llm = strategy != "rules" and alias != "fake"
    versions = {
        "parser": PARSER_VERSION,
        "redaction": REDACTION_VERSION,
        "rules": RULE_VERSION,
        "prompt": PROMPT_VERSION,
        "wire": WIRE_SCHEMA_VERSION,
        "severity": SEVERITY_POLICY,
    }
    dummy = AnalysisRequest(artifact_id=UUID(int=0), input_type="source", content="receipt")
    configuration = {
        "strategy": strategy,
        "model_alias": alias,
        "model": settings.deepseek_model if uses_llm else None,
        "versions": versions,
        "system_prompt_sha256": digest(messages(dummy)[0]["content"]) if uses_llm else None,
        "options": {
            "thinking": {"type": "disabled"},
            "temperature": 0,
            "max_tokens": settings.model_output_tokens,
            "response_format": {"type": "json_object"},
            "stream": False,
        }
        if uses_llm
        else {},
    }
    bound_artifacts = [{k: v for k, v in a.items() if k != "artifact_id"} for a in artifacts]
    return {
        "schema_version": "receipt-1.0",
        "input_digest": input_digest,
        "plan_digest": digest(
            {
                "input_digest": input_digest,
                "configuration": configuration,
                "artifacts": sorted(bound_artifacts, key=canonical),
            }
        ),
        "configuration": configuration,
        "artifacts": artifacts,
        "limits": {
            "task_timeout_seconds": settings.task_timeout_seconds,
            "model_timeout_seconds": settings.model_timeout_seconds,
            "response_bytes": settings.model_response_bytes,
            "scan_call_limit": settings.max_model_calls,
            "daily_call_limit": settings.daily_model_calls,
        },
    }


def verify_receipt(settings, scan, pairs):
    previous = json.loads(scan.plan_json)
    if not previous:
        raise DomainError("ANALYSIS_PLAN_MISSING", "旧任务缺少检测凭证，请按当前配置重试。", 409)
    current = build_receipt(settings, scan.strategy, scan.model_alias, pairs)
    if previous["plan_digest"] != current["plan_digest"]:
        raise DomainError(
            "ANALYSIS_CONFIG_CHANGED", "输入处理或模型方案已变化，请按当前配置重试。", 409
        )
