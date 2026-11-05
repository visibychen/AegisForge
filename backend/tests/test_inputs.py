from uuid import uuid4

import pytest
from app.core.errors import DomainError
from app.core.redaction import redact_text
from app.parsers.inputs import chunks_for, decode_input, parse_input
from app.rules.detector import detect


@pytest.mark.parametrize("raw", [b"", b"\x00abc", b"\xff\xfeabc", b"PK\x03\x04"])
def test_invalid_input_text(raw):
    with pytest.raises(DomainError):
        decode_input(raw)


def test_bom_and_source_lines_are_preserved():
    text = decode_input(b"\xef\xbb\xbfimport os\r\nos.system(request.args['q'])\r\n")
    parsed = parse_input("source", text)
    assert detect(uuid4(), "source", parsed)[0].location.start_line == 2
    assert parsed.features[0]["name"] == "os.system"


@pytest.mark.parametrize(
    ("code", "category"),
    [
        ("return_value = 1\ndef index():\n return '<p>' + request.args['q']", "xss"),
        ("cursor.execute('SELECT * FROM x WHERE id=' + request.args['id'])", "sqli"),
        ("import os\nos.system(request.args['cmd'])", "cmdi"),
    ],
)
def test_rules_positive(code, category):
    result = detect(uuid4(), "source", parse_input("source", code))
    assert any(f.category == category and f.evidence_status == "potential" for f in result)


@pytest.mark.parametrize(
    "code",
    [
        "cursor.execute('SELECT * FROM x WHERE id=?', (request.args['id'],))",
        "subprocess.run(['echo', request.args['q']], shell=False)",
        "return_value = escape(request.args['q'])",
    ],
)
def test_rules_basic_safe_counterexamples(code):
    assert detect(uuid4(), "source", parse_input("source", code)) == []


def test_syntax_failure_is_explicit_and_secrets_are_not_previewed():
    parsed = parse_input("source", 'api_key = "DO_NOT_SHOW"\ndef invalid(')
    assert parsed.warnings
    assert "DO_NOT_SHOW" not in parsed.content
    assert parsed.content.count("\n") == 1
    assert "DO_NOT_SHOW" not in redact_text("Authorization: Bearer DO_NOT_SHOW")


def test_http_decoding_redaction_and_attack_boundaries():
    raw = (
        "POST /?q=%253Cscript%253E&api_key=DO_NOT_SHOW HTTP/1.1\n"
        "Host: example.invalid\nCookie: DO_NOT_SHOW\nAuthorization: Bearer DO_NOT_SHOW\n"
        'Content-Type: application/json\n\n{"password":"DO_NOT_SHOW","nested":{"q":";id"}}'
    )
    parsed = parse_input("http", raw)
    assert "DO_NOT_SHOW" not in parsed.content
    result = detect(uuid4(), "http", parsed)
    assert {f.category for f in result} == {"xss", "cmdi"}
    assert all(f.evidence_status == "attack_indicator" for f in result)
    assert all(f.location.kind == "http" for f in result)


@pytest.mark.parametrize(
    "raw",
    [
        "GET / HTTP/2\n\n",
        "GET / HTTP/1.1\nBad\n\n",
        "GET / HTTP/1.1\nHost: a\nHost: b\n\n",
        "POST / HTTP/1.1\nTransfer-Encoding: chunked\n\n",
    ],
)
def test_reject_ambiguous_http(raw):
    with pytest.raises(DomainError):
        parse_input("http", raw)


def test_chunk_budget_and_complete_coverage():
    text = "print('hello')\n" * 5000
    chunks = chunks_for(text)
    assert len(chunks) <= 8 and chunks[0].start_line == 1 and chunks[-1].end_line == 5000
    for a, b in zip(chunks, chunks[1:], strict=False):
        assert b.start_line <= a.end_line + 1
        assert len(b.content) <= 12000
    for text in ["a" * 12001, "x\n" * 40001]:
        with pytest.raises(DomainError):
            chunks_for(text)
