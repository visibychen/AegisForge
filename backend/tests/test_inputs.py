import json
import time
from uuid import uuid4

import pytest
from app.core.errors import DomainError
from app.parsers.inputs import chunks_for, decode_input, parse_input
from app.rules.detector import detect


def rules(kind, text):
    return detect(uuid4(), kind, parse_input(kind, text))


@pytest.mark.parametrize(
    "raw",
    [b"", b"\x00abc", b"\xff\xfeabc", b"PK\x03\x04", b"a\rb", "x y".encode(), "a\x85".encode()],
)
def test_invalid_input_text(raw):
    with pytest.raises(DomainError):
        decode_input(raw)


def test_bom_crlf_and_source_lines_are_preserved():
    text = decode_input(b"\xef\xbb\xbfimport os\r\nos.system(request.args['q'])\r\n")
    parsed = parse_input("source", text)
    assert rules("source", text).findings[0].location.start_line == 2
    assert parsed.features[0]["name"] == "os.system"


def test_budget_is_checked_before_any_regex_runs():
    started = time.perf_counter()
    for kind, text in [
        ("source", "a" * 2_000_000),
        ("http", "POST / HTTP/1.1\nHost: x\n\n" + "a" * 2_000_000),
        ("source", "x = 1\n" * 20_000),
    ]:
        with pytest.raises(DomainError):
            parse_input(kind, text)
    assert time.perf_counter() - started < 2


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


@pytest.mark.parametrize(
    "text",
    [
        "a" * 12_000 + "\n",
        "a" * 12_000 + "\n" + "b" * 12_000 + "\n" + "c" * 3,
        "\n".join(f"line {i} " + "x" * (i % 300) for i in range(350)) + "\n",
    ],
)
def test_chunks_cover_every_line_within_model_limit(text):
    lines = text.split("\n")[:-1] if text.endswith("\n") else text.split("\n")
    chunks = chunks_for(text)
    covered = set()
    for chunk in chunks:
        assert 0 < len(chunk.content) <= 12_000 and not chunk.content.endswith("\n")
        assert chunk.content == "\n".join(lines[chunk.start_line - 1 : chunk.end_line])
        covered |= set(range(chunk.start_line, chunk.end_line + 1))
    assert covered == set(range(1, len(lines) + 1))
    for a, b in zip(chunks, chunks[1:], strict=False):
        shared = lines[b.start_line - 1 : a.end_line]
        assert sum(len(line) + 1 for line in shared) <= 1_000


def test_http_payload_in_sensitive_field_is_detected_but_not_echoed():
    raw = (
        "POST /login HTTP/1.1\nHost: portal.example.test\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "username=admin&password=%27+or+%271%27%3D%271"
    )
    parsed = parse_input("http", raw)
    result = detect(uuid4(), "http", parsed)
    assert [f.category for f in result.findings] == ["sqli"]
    public = json.dumps([parsed.content, parsed.fields, parsed.field_meta]) + str(
        [f.model_dump() for f in result.findings]
    )
    assert "'1'='1" not in public and "or '1'" not in public
    assert result.findings[0].evidence.startswith("[REDACTED]")


def test_http_decoding_stops_after_two_passes_with_metadata():
    triple = parse_input("http", "GET /?q=%2525253Cscript%2525253E HTTP/1.1\nHost: a\n\n")
    assert "<script" not in triple.private_fields["query.0"]
    assert triple.field_meta["query.0"]["decode_limited"] is True
    assert any("2 次" in warning for warning in triple.warnings)
    double = parse_input("http", "GET /?q=%253Cscript%253E HTTP/1.1\nHost: a\n\n")
    assert double.field_meta["query.0"]["decode_passes"] == 2
    assert [f.category for f in detect(uuid4(), "http", double).findings] == ["xss"]


def test_http_raw_positions_point_at_the_raw_value():
    raw = "GET /items?a=1&q=%3Cb%3E HTTP/1.1\nX-Trace: abc\n\n"
    parsed = parse_input("http", raw)
    meta = parsed.field_meta["query.1"]
    first_line = raw.split("\n")[0]
    assert meta["line"] == 1 and first_line[meta["raw_start"] : meta["raw_end"]] == "%3Cb%3E"
    header = parsed.field_meta["header.0"]
    assert raw.split("\n")[1][header["raw_start"] : header["raw_end"]] == "abc"


@pytest.mark.parametrize(
    "raw",
    [
        "GET / HTTP/2\n\n",
        "GET / HTTP/1.1\nBad\n\n",
        "GET / HTTP/1.1\nHost: a\nHost: b\n\n",
        "POST / HTTP/1.1\nTransfer-Encoding: chunked\n\n",
        "POST / HTTP/1.1\nContent-Type: multipart/form-data; boundary=x\n\n--x\n",
        "POST / HTTP/1.1\nContent-Type: application/xml\n\n<password>x</password>",
        "POST / HTTP/1.1\nContent-Length: 3\nContent-Type: text/plain\n\nabcdef",
        "POST / HTTP/1.1\nContent-Length: +5\n\nabcde",
        "POST / HTTP/1.1\nContent-Type: application/json\n\n" + "[" * 40 + "]" * 40,
    ],
)
def test_reject_ambiguous_or_unsupported_http(raw):
    with pytest.raises(DomainError):
        parse_input("http", raw)


def test_content_length_accepts_crlf_and_trailing_newline():
    body = "a=1\nb=2"
    for declared in [len(body), len(body) + 1]:
        raw = f"POST / HTTP/1.1\nContent-Length: {declared}\nContent-Type: text/plain\n\n{body}\n"
        assert parse_input("http", raw).fields


def test_unicode_and_control_values_cannot_forge_extra_public_lines():
    parsed = parse_input("http", "GET /?a=x%0Aquery.9%20fake%20%3D%201 HTTP/1.1\nHost: a\n\n")
    assert len(parsed.content.split("\n")) == len(parsed.fields)
