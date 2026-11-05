from uuid import uuid4

import pytest
from app.parsers.inputs import parse_input
from app.rules.detector import MAX_RULE_FINDINGS, detect


def categories(code: str) -> list[str]:
    return [f.category for f in detect(uuid4(), "source", parse_input("source", code)).findings]


@pytest.mark.parametrize(
    ("code", "category"),
    [
        ("def index():\n    return '<p>' + request.args['q']", "xss"),
        ("cursor.execute('SELECT * FROM x WHERE id=' + request.args['id'])", "sqli"),
        ("import os\nos.system(request.args['cmd'])", "cmdi"),
        ("import subprocess as sp\nsp.call('ls ' + request.args['d'], shell=True)", "cmdi"),
        ("from os import system\nsystem('ping ' + host)", "cmdi"),
        ("db.executescript(f\"INSERT INTO t VALUES ('{v}')\")", "sqli"),
        ("from sqlalchemy import text\nconn.execute(text(f\"SELECT 1 WHERE a = '{a}'\"))", "sqli"),
        ("cur.execute(f\"SELECT * FROM t WHERE a = '{a}'\", ())", "sqli"),
        ("def f(q):\n    sql = 'SELECT * FROM t WHERE a = ' + q\n    cur.execute(sql)", "sqli"),
        ("from markupsafe import Markup\nhtml = Markup('<b>%s</b>' % name)", "xss"),
        (
            "def f(n):\n    body = '<p>%s</p>' % n\n    return make_response(body)",
            "xss",
        ),
    ],
)
def test_rules_positive(code, category):
    assert category in categories(code)


@pytest.mark.parametrize(
    "code",
    [
        "cursor.execute('SELECT * FROM x WHERE id=?', (request.args['id'],))",
        "subprocess.run(['echo', request.args['q']], shell=False)",
        "return_value = escape(request.args['q'])",
        "def mask(n):\n    return 1 << n",
        "QUERY = 'SELECT 1'\ndef f():\n    cursor.execute(QUERY)",
        "import os, shlex\ndef f(x):\n    os.system('whois ' + shlex.quote(x))",
        "ALLOWED = {'a': 'ls -l'}\ndef f(x):\n    os.system(ALLOWED.get(x, 'ls'))",
        "from markupsafe import Markup\ndef f(x):\n    return Markup('<b>{}</b>').format(x)",
        "from markupsafe import escape\ndef f(x):\n    return f'<p>{escape(x)}</p>'",
        "from sqlalchemy import text\nconn.execute(text('SELECT 1 WHERE a = :a'), {'a': a})",
    ],
)
def test_rules_safe_counterexamples(code):
    assert categories(code) == []


def test_escape_does_not_sanitize_sql():
    code = "from html import escape\ndef f(x):\n    cur.execute('SELECT ' + escape(x))"
    assert categories(code) == ["sqli"]


def test_truncation_is_reported_instead_of_silently_dropping():
    code = "import os\n" + "os.system(x)\n" * (MAX_RULE_FINDINGS + 20)
    result = detect(uuid4(), "source", parse_input("source", code))
    assert len(result.findings) == MAX_RULE_FINDINGS and result.truncated and result.warnings


def test_deeply_nested_expressions_do_not_crash():
    code = "def f(x):\n    return ('<p>'\n" + "+x\n" * 20_000 + ")\n"
    result = detect(uuid4(), "source", parse_input("source", code))
    assert result.truncated is False
