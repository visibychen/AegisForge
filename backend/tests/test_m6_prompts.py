"""analysis-1.2 / repair-1.2: explicit line maps and a correction round with server-computed facts.

Nothing is relaxed: the declared range must still intersect the verbatim evidence, and a unique
evidence occurrence elsewhere is still a rejection. The correction round only learns integers.
"""

import asyncio
import json
from uuid import uuid4

import httpx
import pytest
from app.core.config import Settings
from app.llm.deepseek import DeepSeekProvider, OutputRejected, ProviderError
from app.llm.prompts import PROMPT_VERSION, messages, source_lines, wire_input
from app.llm.repair import REPAIR_PROMPT_VERSION, RepairProvider, repair_lines, repair_messages
from app.schemas.contracts import AnalysisRequest
from app.services.patches import RepairWire


def source_request(content="a = 1\nb = 2\nos.system(cmd)", start=10):
    rows = content.split("\n")
    return AnalysisRequest(
        artifact_id=uuid4(),
        input_type="source",
        content=content,
        start_line=start,
        end_line=start + len(rows) - 1,
    )


def wire(start, end, evidence="os.system(cmd)"):
    return {
        "schema_version": "1.1",
        "findings": [
            {
                "category": "cmdi",
                "cwe": "CWE-78",
                "severity": "high",
                "location": {"kind": "source", "start_line": start, "end_line": end},
                "evidence": evidence,
                "explanation": "Untrusted shell input",
                "recommendation": "Use an argument list",
            }
        ],
        "warnings": [],
    }


def reply(data):
    return httpx.Response(
        200,
        json={
            "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(data)}}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 3},
        },
    )


def make(monkeypatch, handler, cls=DeepSeekProvider):
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-test-credential")
    calls, finishes = [], []

    def reserve(chars):
        calls.append(chars)
        return str(len(calls))

    provider = cls(
        Settings(_env_file=None),
        reserve,
        lambda *args: finishes.append(args),
        transport=httpx.MockTransport(handler),
    )
    return provider, calls, finishes


def test_versions_are_bumped_and_the_source_map_uses_global_numbers():
    assert PROMPT_VERSION == "analysis-1.2" and REPAIR_PROMPT_VERSION == "repair-1.2"
    request = source_request()
    assert source_lines(request) == [
        {"n": 10, "text": "a = 1"},
        {"n": 11, "text": "b = 2"},
        {"n": 12, "text": "os.system(cmd)"},
    ]
    # A final line break does not start another numbered line.
    assert source_lines(source_request("x = 1\n", 5)) == [{"n": 5, "text": "x = 1"}]
    payload = wire_input(request)
    assert "content" not in payload and payload["lines"] == source_lines(request)


def test_http_input_keeps_exact_fields_and_invents_no_line_map():
    request = AnalysisRequest(
        artifact_id=uuid4(),
        input_type="http",
        content="GET /?q=1 HTTP/1.1\n",
        start_line=1,
        end_line=1,
        fields={"query.0": "1"},
    )
    payload = wire_input(request)
    assert payload["fields"] == {"query.0": "1"} and "lines" not in payload
    assert payload["content"] == request.content


def test_system_prompt_teaches_the_line_map_and_context_without_naming_samples():
    system = messages(source_request())[0]["content"]
    assert "GLOBAL line number" in system and "never part of evidence" in system
    for phrase in ("JavaScript string", "bound parameters", "shell=False", "shlex.quote"):
        assert phrase in system
    assert "rejected" not in system  # only a correction round says that
    corrected = messages(source_request(), "location_mismatch", "finding 1; declared 10-10")[0]
    assert "server check 'location_mismatch'" in corrected["content"]
    assert "Server facts: finding 1; declared 10-10." in corrected["content"]


def test_wrong_declared_lines_get_one_informed_correction_and_the_check_is_unchanged(monkeypatch):
    request = source_request()
    seen = []

    def handler(http_request):
        body = json.loads(http_request.content)
        seen.append(body["messages"])
        # First answer: the evidence is real but the declared line is wrong. Second: correct.
        return reply(wire(10, 10) if len(seen) == 1 else wire(12, 12))

    provider, calls, finishes = make(monkeypatch, handler)
    result = asyncio.run(provider.analyze(request))
    assert len(calls) == 2 and [item[5] for item in finishes] == ["location_mismatch", None]
    assert "Server facts" not in seen[0][0]["content"]
    assert "Server facts: finding 1; declared 10-10; evidence lines 12-12." in seen[1][0]["content"]
    assert json.loads(seen[1][1]["content"])["lines"][2] == {"n": 12, "text": "os.system(cmd)"}
    assert result.findings[0].location.start_line == 12


def test_a_second_wrong_answer_is_rejected_and_unique_evidence_elsewhere_is_never_accepted(
    monkeypatch,
):
    provider, calls, finishes = make(monkeypatch, lambda _: reply(wire(10, 10)))
    with pytest.raises(ProviderError, match="MODEL_INVALID_OUTPUT") as error:
        asyncio.run(provider.analyze(source_request()))
    assert len(calls) == 2  # exactly one correction, never an endless loop
    assert error.value.category == "location_mismatch"
    assert error.value.detail == "finding 1; declared 10-10; evidence lines 12-12"
    assert [item[5] for item in finishes] == ["location_mismatch", "location_mismatch"]


def test_rejection_detail_is_only_integers_and_words():
    assert OutputRejected("location_mismatch", "finding 2; declared 3-4").detail
    assert OutputRejected("evidence", "contains = quote ' and <b>").detail is None
    assert str(OutputRejected("evidence", "declared 1-1")) == "evidence"


def test_repair_lines_keep_real_line_endings_and_the_missing_final_one():
    content = "import os\n\tx = 1  \ny = 2"
    lines = repair_lines(content)
    assert [item["n"] for item in lines] == [1, 2, 3]
    assert lines[1]["text"] == "\tx = 1  \n" and lines[2]["text"] == "y = 2"
    assert "".join(item["text"] for item in lines) == content  # old_text is a plain join
    user = json.loads(repair_messages(source_request(content, 1), {"cwe": "CWE-78"})[1]["content"])
    assert user["lines"] == lines and "content" not in user


def test_repair_correction_reports_where_the_exact_text_really_is(monkeypatch):
    content = "import os\nx = 1\nos.system(cmd)\n"
    request = source_request(content.rstrip("\n"), 1).model_copy(update={"content": content})
    seen = []

    def edit(start, end, old):
        return {
            "schema_version": "repair-1.0",
            "explanation": "quote the command",
            "edits": [
                {"start_line": start, "end_line": end, "old_text": old, "new_text": "pass\n"}
            ],
        }

    def handler(http_request):
        seen.append(json.loads(http_request.content)["messages"][0]["content"])
        start = 2 if len(seen) == 1 else 3  # first answer names the wrong line
        return reply(edit(start, start, "os.system(cmd)\n"))

    provider, calls, _ = make(monkeypatch, handler, RepairProvider)
    wire_result = asyncio.run(provider.generate(request, {"cwe": "CWE-78"}))
    assert isinstance(wire_result, RepairWire) and wire_result.edits[0].start_line == 3
    assert len(calls) == 2 and "Previous output rejected: patch_conflict." in seen[1]
    assert "exact_text_at_lines_3" in seen[1] and "Previous output rejected" not in seen[0]


def test_repair_preflight_keeps_rejecting_after_the_single_correction(monkeypatch):
    content = "import os\nos.system(cmd)\n"
    request = source_request("import os\nos.system(cmd)", 1)
    request = request.model_copy(update={"content": content})
    wrong = {"start_line": 2, "end_line": 2, "old_text": "os.system(c)\n", "new_text": "p\n"}
    bad = {"schema_version": "repair-1.0", "explanation": "x", "edits": [wrong]}
    provider, calls, _ = make(monkeypatch, lambda _: reply(bad), RepairProvider)
    with pytest.raises(ProviderError, match="MODEL_INVALID_OUTPUT") as error:
        asyncio.run(provider.generate(request, {"cwe": "CWE-78"}))
    assert len(calls) == 2 and error.value.category == "patch_conflict"
    assert "declared 2-2" in error.value.detail and "os.system" not in error.value.detail
