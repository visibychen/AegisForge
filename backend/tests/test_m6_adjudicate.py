import ast
from uuid import uuid4

import pytest
from app.parsers.inputs import parse_input
from app.rules.detector import detect
from app.rules.semantics import MAX_STATE_ENTRIES, Semantics
from app.schemas.contracts import Finding, SourceLocation
from app.services.adjudicate import adjudicate
from app.services.merge import merge_findings


def pipeline(source, cwe, lines=None):
    ident = uuid4()
    parsed = parse_input("source", source)
    lines = lines or [(len(source.splitlines()), len(source.splitlines()))]
    candidates = [
        Finding(
            category={"CWE-79": "xss", "CWE-89": "sqli", "CWE-78": "cmdi"}[cwe],
            cwe=cwe,
            severity="high",
            location=SourceLocation(artifact_id=ident, start_line=start, end_line=end),
            evidence="\n".join(source.splitlines()[start - 1 : end]),
            explanation="model hypothesis",
            recommendation="review",
            sources=["llm"],
        )
        for start, end in lines
    ]
    raw = merge_findings(candidates, {str(ident): parsed})
    return raw, adjudicate(raw, {str(ident): parsed})


@pytest.mark.parametrize(
    "mutation",
    [
        "parts.append(user)",
        "other = parts\nother.append(user)",
        "parts.extend([user])",
        "parts[0] = user",
    ],
)
def test_mutable_query_fragments_are_not_frozen_at_the_initializer(mutation):
    source = (
        'parts = ["fixed"]\n' + mutation + "\n"
        'db.execute("UPDATE t SET " + ", ".join(parts) + " WHERE id = ?", (1,))'
    )
    parsed = parse_input("source", source)
    assert any(f.cwe == "CWE-89" for f in detect(uuid4(), "source", parsed).findings)
    _, (kept, audit) = pipeline(source, "CWE-89")
    assert len(kept) == 1 and audit["refuted"] == 0


def test_mutated_argv_cannot_be_proved_constant_through_an_alias():
    source = (
        'import subprocess\nargs = ["bash", "-c", "echo safe"]\n'
        "alias = args\nalias[2] = user\nsubprocess.run(args)"
    )
    _, (kept, audit) = pipeline(source, "CWE-78")
    assert len(kept) == 1 and audit["refuted"] == 0


@pytest.mark.parametrize(
    "source,cwe",
    [
        ("import subprocess\nsubprocess.run(['awk', request.args['code'], 'data.txt'])", "CWE-78"),
        (
            "import subprocess\nsubprocess.run(['find', '.', '-exec', request.args['exe'], ';'])",
            "CWE-78",
        ),
        ("import subprocess\nsubprocess.run(['bash', '-c', request.args['code']])", "CWE-78"),
        ("import subprocess\nsubprocess.run(['bash'], input=request.args['code'])", "CWE-78"),
        (
            "import subprocess, shlex\nsubprocess.run([shlex.quote(request.args['exe']), 'x'])",
            "CWE-78",
        ),
        ("import os, shlex\nos.system('sh -c ' + shlex.quote(request.args['code']))", "CWE-78"),
        ("import subprocess\nsubprocess.run(['du', '--', path], env=request.environ)", "CWE-78"),
        ("def f(sp, value):\n    sp.run(['du', '--', value])", "CWE-78"),
        (
            "from flask import render_template_string, request\n"
            "render_template_string('<a href=\"{{x}}\">open</a>', x=request.args['x'])",
            "CWE-79",
        ),
        (
            "from flask import render_template_string, request\n"
            "render_template_string('<p>{{x|safe}}</p>', x=request.args['x'])",
            "CWE-79",
        ),
        (
            "from markupsafe import Markup\nfrom flask import request\n"
            "def f():\n    return Markup('<p>{}</p>').format(Markup(request.args['x']))",
            "CWE-79",
        ),
        (
            "import json\ndef f(q):\n    return '<script>let x=%s</script>' % "
            "json.dumps(q).replace('<', '\\\\u003c').replace('\\\\u003c', '<')",
            "CWE-79",
        ),
        ("def f(q):\n    db.execute('SELECT * FROM t WHERE id='+q, ())", "CWE-89"),
    ],
)
def test_unproved_or_interpreted_input_is_never_refuted(source, cwe):
    _, (kept, summary) = pipeline(source, cwe)
    assert len(kept) == 1 and summary["refuted"] == 0


@pytest.mark.parametrize(
    "source,cwe",
    [
        ("import subprocess\nsubprocess.run(['du', '-sh', '--', path])", "CWE-78"),
        ("db.execute('SELECT * FROM t WHERE id=?', (value,))", "CWE-89"),
        (
            "from flask import render_template_string, request\n"
            "render_template_string('<p>{{x}}</p>', x=request.args['x'])",
            "CWE-79",
        ),
        (
            "from markupsafe import Markup\nfrom flask import request\n"
            "def f():\n    return Markup('<p>{}</p>').format(request.args['x'])",
            "CWE-79",
        ),
    ],
)
def test_narrow_supported_cases_have_visible_counterevidence(source, cwe):
    _, (kept, summary) = pipeline(source, cwe)
    assert not kept and summary["refuted"] == 1
    assert summary["refuted_findings"][0]["criterion"]


def test_same_flow_merges_but_two_terminal_operations_stay_distinct():
    source = "def f(q):\n    sql='SELECT '+q\n    sql+=' LIMIT 1'\n    db.execute(sql)"
    raw, _ = pipeline(source, "CWE-89", [(2, 2), (3, 3), (4, 4)])
    assert len(raw) == 1 and len(raw[0]["contributors"]) == 3
    assert raw[0]["finding"]["location"]["start_line"] == 4
    source += "\n    other.execute(sql)"
    raw, _ = pipeline(source, "CWE-89", [(2, 2), (4, 4), (5, 5)])
    assert len(raw) == 3  # ambiguous feeder is retained; separate executions never disappear


def test_state_budget_exhaustion_is_bounded_and_never_claims_complete_coverage():
    source = "\n".join(f"value_{i}={i}" for i in range(1000))
    sem = Semantics(ast.parse(source))
    assert sem.exhausted and sem.state_entries <= MAX_STATE_ENTRIES
    result = detect(uuid4(), "source", parse_input("source", source))
    assert result.truncated and result.warnings


@pytest.mark.parametrize(
    "source",
    [
        "import os, shlex\nfrom flask import request\n"
        "def f():\n    os.system('pg_dump %s > /tmp/output.sql' % shlex.quote(request.args['db']))",
        "import subprocess, shlex\nfrom flask import request\n"
        "def f():\n    command=['ffmpeg', '-i', request.args['input'], 'out.mp3']\n"
        "    subprocess.call(shlex.join(command), shell=True)",
    ],
)
def test_supported_quoted_data_has_a_narrow_posix_counterargument(source):
    _, (kept, audit) = pipeline(source, "CWE-78")
    assert not kept and audit["refuted"] == 1


@pytest.mark.parametrize(
    "source",
    [
        "import os, shlex\nfrom flask import request\n"
        "os.system('awk %s data.txt' % shlex.quote(request.args['program']))",
        "import os, shlex\nfrom flask import request\n"
        "os.system(shlex.join(['sh', '-c', request.args['program']]))",
        "import subprocess\nfrom flask import request\n"
        "subprocess.run=lambda *a, **k: None\nsubprocess.run(['du', '--', request.args['path']])",
        "from flask import abort\ndef f(value):\n    if not value.isdigit():\n"
        "        abort(400)\n    db.execute('SELECT '+value)",
    ],
)
def test_unmodelled_interpretation_monkeypatch_or_unknown_type_stays_visible(source):
    cwe = "CWE-89" if "db.execute" in source else "CWE-78"
    _, (kept, audit) = pipeline(source, cwe)
    assert kept and audit["refuted"] == 0
