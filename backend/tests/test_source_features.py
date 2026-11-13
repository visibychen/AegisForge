from uuid import uuid4

from app.parsers.inputs import parse_input
from app.rules.detector import detect


def test_request_origins_and_sink_candidates_do_not_claim_vulnerability():
    code = (
        "from flask import request as req\n"
        "q = req.args['q']\n"
        "api_key = 'FEATURE_SECRET'\n"
        "cursor.execute('SELECT * FROM users WHERE name=?', (q,))\n"
    )
    parsed = parse_input("source", code)
    assert any(
        f["kind"] == "input_source" and f["name"] == "req.args" and f["line"] == 2
        for f in parsed.features
    )
    assert any(f.get("sink_candidate") == "sqli" for f in parsed.features)
    assert not detect(uuid4(), "source", parsed).findings
    assert "FEATURE_SECRET" not in str(parsed.features)


def test_unparseable_source_keeps_text_hints_without_ast_findings():
    parsed = parse_input("source", "import os\nos.system(cmd)\ndef incomplete(\n")
    assert parsed.private_tree is None
    assert {"kind": "text_call_hint", "name": "os.system", "line": 2} in parsed.features
    rules = detect(uuid4(), "source", parsed)
    assert not rules.findings and rules.warnings
