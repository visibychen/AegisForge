"""Independent safety regressions before semantic adjudication is implemented."""

from uuid import uuid4

import pytest
from app.parsers.inputs import parse_input
from app.rules.detector import detect


def categories(source):
    return {f.category for f in detect(uuid4(), "source", parse_input("source", source)).findings}


@pytest.mark.parametrize(
    "branch", ["if flag:\n        value = 'literal'", "for _ in items:\n        value = 'literal'"]
)
def test_conditional_assignments_do_not_erase_a_reachable_tainted_definition(branch):
    source = (
        "def lookup(user_value, flag, items):\n    value = user_value\n    "
        + branch
        + "\n    db.execute('SELECT * FROM records WHERE id=' + value)\n"
    )
    assert "sqli" in categories(source)


def test_unconditional_overwrite_still_kills_the_previous_tainted_definition():
    assert "sqli" not in categories(
        "def lookup(user_value):\n    value = user_value\n    value = '1'\n"
        "    db.execute('SELECT * FROM records WHERE id=' + value)\n"
    )


@pytest.mark.parametrize(
    "source",
    [
        "def render(html, value):\n    return '<p>' + html.escape(value) + '</p>'\n",
        "def lookup(int, value):\n"
        "    db.execute('SELECT * FROM records WHERE id=' + str(int(value)))\n",
        "def render(value):\n    def escape(x):\n        return x\n"
        "    return '<p>' + escape(value)\n",
    ],
)
def test_shadowed_sanitizer_names_are_not_trusted(source):
    assert categories(source)


def test_wildcard_fullmatch_is_not_a_shell_sanitizer():
    source = (
        "import re, os\nfrom flask import abort\ndef run(value):\n"
        "    if not re.fullmatch('.*', value):\n        abort(400)\n"
        "    os.system('ping ' + value)\n"
    )
    assert "cmdi" in categories(source)


def test_constant_placeholder_generator_is_not_sql_data_interpolation():
    source = (
        "def lookup(values):\n    slots = ','.join('?' for _ in values)\n"
        "    db.execute('SELECT * FROM records WHERE id IN (' + slots + ')', values)\n"
    )
    assert "sqli" not in categories(source)
