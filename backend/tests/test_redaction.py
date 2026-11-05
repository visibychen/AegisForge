import json
import time
from uuid import uuid4

import pytest
from app.core.redaction import redact_source, redact_text, sensitive
from app.parsers.inputs import parse_input
from app.rules.detector import detect

SOURCE_LEAKS = [
    ('SECRET_KEY = "LEAK_ALPHA1"', "LEAK_ALPHA1"),
    ("app.config['SECRET_KEY'] = 'LEAK_ALPHA1'", "LEAK_ALPHA1"),
    ('cookies = {"session": "LEAK_ALPHA1"}', "LEAK_ALPHA1"),
    ('headers = {"Cookie": "sid=LEAK_ALPHA1"}', "LEAK_ALPHA1"),
    ('headers = {"Authorization": "Basic TEVBS19BTFBIQTE6cHc="}', "TEVBS19BTFBIQTE6cHc="),
    ('password = f"LEAK_ALPHA1{suffix}"', "LEAK_ALPHA1"),
    ('token: str = "LEAK_ALPHA1"', "LEAK_ALPHA1"),
    ('api_key = b"LEAK_ALPHA1"', "LEAK_ALPHA1"),
    ('DATABASE_URL = "postgresql://app:LEAK_ALPHA1@db.internal/app"', "LEAK_ALPHA1"),
    ("# password: LEAK_ALPHA1", "LEAK_ALPHA1"),
    ('client = Client(api_key="LEAK_ALPHA1")', "LEAK_ALPHA1"),
    ('aws = "AKIAABCDEFGHIJKLMNOP"', "AKIAABCDEFGHIJKLMNOP"),
    ('requests.get(url, headers={"X-Api-Key": "LEAK_ALPHA1"})', "LEAK_ALPHA1"),
    ('if password == "LEAK_ALPHA1":\n    pass', "LEAK_ALPHA1"),
    (
        'PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----\nLEAK_ALPHA1\n-----END PRIVATE KEY-----"""',
        "LEAK_ALPHA1",
    ),
    ('note = f"api_key=SYNTHETIC_ONLY_SECRET"', "SYNTHETIC_ONLY_SECRET"),
    ('note = f"user {name} api_key=SYNTHETIC_ONLY_SECRET"', "SYNTHETIC_ONLY_SECRET"),
    ('note = f"{{literal}} api_key=SYNTHETIC_ONLY_SECRET {x}"', "SYNTHETIC_ONLY_SECRET"),
    ('def h():\n    return "Bearer SYNTHETICLETTERS"', "SYNTHETICLETTERS"),
    ('auth = "Token SYNTHETICLETTERS"', "SYNTHETICLETTERS"),
    ('''note = f"{'Bearer SYNTHETICLETTERS'}"''', "SYNTHETICLETTERS"),
    ('''note = f"{'sk-SYNTHETICTOKENaaaaaaaaaaaa'}"''', "SYNTHETICTOKEN"),
    ('''note = f"{dict(api_key='SYNTHETIC_ONLY_SECRET')}"''', "SYNTHETIC_ONLY_SECRET"),
    ('hdr = "Basic dXNlcjpwYXNz"', "dXNlcjpwYXNz"),
    ('hdr = "Digest username=\\"u\\", response=\\"SYNTHETICDIGEST\\""', "SYNTHETICDIGEST"),
]


@pytest.mark.parametrize(("code", "secret"), SOURCE_LEAKS)
def test_source_secrets_are_masked_without_moving_lines(code, secret):
    text = code + "\nprint('done')\n"
    parsed = parse_input("source", text)
    public = json.dumps([parsed.content, parsed.features, [c.content for c in parsed.chunks]])
    assert secret not in public
    assert parsed.content.count("\n") == text.count("\n")
    assert parsed.content.split("\n")[-2] == "print('done')"


def test_source_structure_and_business_logic_stay_readable():
    code = (
        "import os\n"
        "def run(cmd, token=None):\n"
        "    if token == 'x':\n"
        "        pass\n"
        "    query = 'SELECT id FROM users WHERE token = ?'\n"
        "    password = request.form['password']\n"
        "    cursor.execute('UPDATE users SET password = %s WHERE id = %s', (password, 1))\n"
        "    os.system(cmd)\n"
    )
    parsed = parse_input("source", code)
    for unchanged in [
        "def run(cmd, token=None):",
        "WHERE token = ?",
        "password = request.form['password']",
        "SET password = %s",
    ]:
        assert unchanged in parsed.content
    result = detect(uuid4(), "source", parsed)
    assert [(f.category, f.location.start_line) for f in result.findings] == [("cmdi", 8)]
    assert not result.warnings


def test_fstring_literals_are_redacted_but_expressions_and_markup_stay():
    code = 'def f(name, rows):\n    return f"<td>{name}</td> rows={rows} Bearer ABCDEFGHIJ"\n'
    parsed = parse_input("source", code)
    assert '<td>{name}</td> rows={rows} Bearer [REDACTED]"' in parsed.content
    result = detect(uuid4(), "source", parsed)
    assert [f.category for f in result.findings] == ["xss"]


def test_basic_prose_is_not_masked():
    assert redact_text("Basic usage and Basic auth notes") == "Basic usage and Basic auth notes"


def test_untokenizable_source_falls_back_to_line_preserving_redaction():
    text = 'api_key = "DO_NOT_SHOW"\ndef invalid(\n'
    parsed = parse_input("source", text)
    assert parsed.warnings and "DO_NOT_SHOW" not in parsed.content
    assert parsed.content.count("\n") == text.count("\n")
    assert detect(uuid4(), "source", parsed).warnings


HTTP_LEAKS = [
    "GET / HTTP/1.1\nHost: a\nX-Auth-Token: LEAK_BRAVO2\n\n",
    "GET /cart;jsessionid=LEAK_BRAVO2 HTTP/1.1\nHost: a\n\n",
    "GET /?client_secret=LEAK_BRAVO2 HTTP/1.1\nHost: a\n\n",
    "GET /?sk_live_LEAKBRAVO2abc=1 HTTP/1.1\nHost: a\n\n",
    "GET /reset/LEAKBRAVO2a1b2c3d4e5f6g7h8i9 HTTP/1.1\nHost: a\n\n",
    "GET / HTTP/1.1\nHost: a\nCookie: sid=LEAK_BRAVO2\n\n",
    "GET / HTTP/1.1\nHost: a\nAuthorization: Bearer LEAK_BRAVO2\n\n",
    "GET / HTTP/1.1\nHost: a\nReferer: https://u:LEAK_BRAVO2@example.test/\n\n",
    'POST / HTTP/1.1\nContent-Type: application/json\n\n{"auth": {"value": "LEAK_BRAVO2"}}',
    "POST / HTTP/1.1\nContent-Type: text/plain\n\nnote\npassword: LEAK_BRAVO2\n",
]


@pytest.mark.parametrize("raw", HTTP_LEAKS)
def test_http_secrets_are_masked_in_every_public_view(raw):
    parsed = parse_input("http", raw)
    result = detect(uuid4(), "http", parsed)
    public = json.dumps(
        [parsed.content, parsed.fields, parsed.field_meta, [f.evidence for f in result.findings]]
    )
    assert "LEAK_BRAVO2" not in public and "LEAKBRAVO2" not in public


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("X-Auth-Token", True),
        ("accessToken", True),
        ("client_secret", True),
        ("api%255Fkey", True),
        ("author", False),
        ("content-type", False),
        ("page", False),
    ],
)
def test_sensitive_names(name, expected):
    assert sensitive(name) is expected


def test_redaction_stays_linear_on_adversarial_input():
    started = time.perf_counter()
    for text in ["a" * 79_000, "a=" * 39_000, "x " * 39_000, "Basic " * 13_000, "a='" * 26_000]:
        redact_text(text)
    redact_source('x = "' + "a" * 11_000 + '"\n' + "y = 'b'\n" * 7_000)
    assert time.perf_counter() - started < 3
