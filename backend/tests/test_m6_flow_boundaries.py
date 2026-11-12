"""Security-relevant control-flow and output-context boundaries, without executing snippets."""

import pytest
from tests.test_m6_adjudicate import pipeline


@pytest.mark.parametrize(
    "body,refuted",
    [
        ("query: str = 'SELECT 1'", True),
        ("query, other = ('SELECT 1', user)", True),
        ("query, *other = values", False),
        ("query = user\nif flag:\n    query = 'SELECT 1'", False),
        ("if flag:\n    query = 'SELECT 1'\nelse:\n    query = 'SELECT 2'", True),
        ("query = user\nwhile flag:\n    query = 'SELECT 1'", False),
        ("query = user\nfor x in values:\n    query = 'SELECT 1'\nelse:\n    pass", False),
        ("query = 'SELECT 1'\ntry:\n    query = user\nexcept Exception as err:\n    pass", False),
        ("query = user\ntry:\n    work()\nfinally:\n    query = 'SELECT 1'", True),
        ("query = user\nmatch mode:\n    case 'safe':\n        query = 'SELECT 1'", False),
        ("query = user\nif flag and (query := 'SELECT 1'):\n    pass", False),
        ("query = 'SELECT 1'\ndel query", False),
        ("with resource() as query:\n    pass", False),
        ("query = 'SELECT '\nquery += user", False),
        ("query = condition if flag else 'SELECT 1'", False),
        ("query = lambda: user", False),
        ("def query():\n    return user", False),
        ("class query:\n    pass", False),
        ("query = (item for item in values)", False),
        ("query = {'key': user}", False),
    ],
)
def test_sql_reaching_paths_do_not_erase_an_untrusted_alternative(body, refuted):
    source = body + "\ndb.execute(query)"
    _, (kept, audit) = pipeline(source, "CWE-89")
    assert (not kept) is refuted
    assert audit["refuted"] == int(refuted)


@pytest.mark.parametrize(
    "template,safe",
    [
        ("<p>{}</p>", True),
        ('<span title="{}">ok</span>', True),
        ("<span aria-label='{}'>ok</span>", True),
        ('<a href="{}">open</a>', False),
        ('<span onclick="{}">ok</span>', False),
        ('<span style="{}">ok</span>', False),
        ("<span title={}>ok</span>", False),
        ("<{}>ok</div>", False),
        ("<!-- {} -->", False),
        ("<style>{}</style>", False),
        ("<textarea>{}</textarea>", False),
        ('<script>let value="{}";</script>', False),
        ("<iframe>{}</iframe>", False),
        ("<template>{}</template>", False),
    ],
)
def test_markup_escaping_only_proves_supported_html_contexts(template, safe):
    source = (
        "from markupsafe import Markup\nfrom flask import request\n"
        "def render():\n    return Markup(" + repr(template) + ').format(request.args["value"])'
    )
    _, (kept, _) = pipeline(source, "CWE-79")
    assert (not kept) is safe


@pytest.mark.parametrize(
    "expression",
    [
        'subprocess.run(["python3", "-c", user])',
        'subprocess.run(["node", user])',
        'subprocess.run(["env", user])',
        'subprocess.run(["find", ".", "-execdir", user, ";"])',
        'subprocess.run(["bash"], stdin=user)',
        'subprocess.run(["cat", "--", user], executable=user)',
        'subprocess.run(["cat", "--", user], shell=unknown)',
        'subprocess.run(["cat", "--", user], preexec_fn=callback)',
        "subprocess.run(*args)",
        "subprocess.run()",
        'subprocess.run(["cat", "-n", user])',
        'asyncio.create_subprocess_exec("python", "-c", user)',
        'asyncio.create_subprocess_shell("bash -c " + user)',
    ],
)
def test_interpreters_overrides_and_unknown_launcher_options_remain_reviewable(expression):
    _, (kept, audit) = pipeline("import subprocess, asyncio\n" + expression, "CWE-78")
    assert kept and audit["refuted"] == 0


@pytest.mark.parametrize("pattern", [r".*", r"[^;]+", r"(?=x).*", r"(a)\1", "[", r"[a-z;]+"])
def test_weak_or_unparseable_validation_is_not_a_command_proof(pattern):
    source = (
        "import os, re\nfrom flask import request, abort\n"
        'def f():\n    value = request.args["value"]\n'
        f"    if not re.fullmatch({pattern!r}, value):\n        abort(400)\n"
        '    os.system("cat " + value)'
    )
    _, (kept, _) = pipeline(source, "CWE-78")
    assert kept
