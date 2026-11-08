"""Fixed development regressions (driver process). Never sent to generation/detection models.

Trust model: this process never imports candidate code. The candidate runs in ``target.py`` as
a separate process serving HTTP on loopback with every standard stream closed; each verdict is
computed here from observed HTTP responses, files and real browser behaviour. Before anything
else the driver makes itself non-dumpable (same-uid ``/proc/<pid>/mem``, ``environ`` and
``fd`` become unreadable to the target), receives a one-time nonce over stdin, and finally
prints exactly one JSON line. Anything the candidate writes can therefore not reach, forge or
alter the result channel. A driver that cannot finish exits without a result line, which the
host reports as an environment error, never as a pass.
"""

import ctypes
import hashlib
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PORT = 18080
BUDGET = 25  # seconds for the whole run; the host enforces 30
CANDIDATE = Path("/candidate.py")
MARKER = Path("/tmp/aegis-command-marker")
PING_LOG = Path("/tmp/ping.log")
SCHEMA = "validation-2.0"
TESTS = {
    "xss-01": ["business_greeting", "business_unicode", "security_browser_no_script"],
    "sqli-01": ["business_lookup", "business_apostrophe", "security_query_boundary"],
    "cmdi-01": ["business_ping", "business_second_host", "security_shell_boundary"],
}
UNREACHABLE_HOST = "192.0.2.77"  # ping_stub.py answers this one with a non-zero exit status
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class InfrastructureError(Exception):
    """Browser/driver trouble that says nothing about the candidate."""


def make_undumpable():
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 or libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0):
        raise SystemExit(3)  # fail closed: never run a candidate next to a readable driver


def get(path, query):
    url = f"http://127.0.0.1:{PORT}{path}?{urllib.parse.urlencode(query)}"
    try:
        with OPENER.open(url, timeout=5) as response:
            return response.status, response.headers, response.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read(65536)
    except Exception:  # noqa: BLE001 - an unreachable or hung candidate simply fails its tests
        return None, None, b""


def text(headers, body):
    charset = headers.get_content_charset() if headers is not None else None
    return body.decode(charset or "utf-8", errors="replace")


def as_json(body):
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        return object()


def start_target(deadline):
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    process = subprocess.Popen(
        [sys.executable, "/opt/validator/target.py", str(PORT)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd="/tmp",
        close_fds=True,
        start_new_session=True,
    )
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return process, False  # the candidate crashed on import: its tests fail
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", PORT)) == 0:
                return process, True
        time.sleep(0.05)
    return process, False


def ping_calls():
    if not PING_LOG.exists():
        return []
    calls = []
    for line in PING_LOG.read_text(encoding="utf-8").splitlines():
        try:
            calls.append(list(json.loads(line)))
        except ValueError:
            continue
    return calls


def seed_database():
    with sqlite3.connect("/tmp/app.db") as db:
        db.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
        db.executemany(
            "INSERT INTO users VALUES (?,?,?)",
            [(1, "Alice", "alice@example.invalid"), (2, "O'Reilly", "oreilly@example.invalid")],
        )


def xss_security():
    from playwright.sync_api import Error, sync_playwright

    payload = '<svg onload="window.__aegis_xss=1"></svg>'
    url = f"http://127.0.0.1:{PORT}/greet?" + urllib.parse.urlencode({"name": payload})
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(
                headless=True, timeout=12000, args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
        except Error:
            raise InfrastructureError from None  # no browser says nothing about the candidate
        try:
            page = browser.new_page()
            page.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if route.request.url.startswith(f"http://127.0.0.1:{PORT}/")
                    else route.abort()
                ),
            )
            try:
                # Real navigation: the browser honours the candidate's Content-Type itself.
                response = page.goto(url, timeout=5000)
                page.wait_for_timeout(200)
                return bool(
                    response is not None
                    and response.status == 200
                    and page.evaluate("window.__aegis_xss === undefined")
                )
            except Error:
                return False  # the candidate's page did not load or evaluate properly
        finally:
            browser.close()


def run_case(case, ready):
    results = {name: False for name in TESTS[case]}
    if not ready:
        return results
    if case == "xss-01":
        status, headers, body = get("/greet", {"name": "Alice"})
        results["business_greeting"] = status == 200 and "Hello, Alice!" in text(headers, body)
        status, headers, body = get("/greet", {"name": "铸盾"})
        results["business_unicode"] = status == 200 and "铸盾" in text(headers, body)
        results["security_browser_no_script"] = xss_security()
    elif case == "sqli-01":
        status, _, body = get("/user", {"name": "Alice"})
        results["business_lookup"] = status == 200 and as_json(body) == {
            "user": [1, "alice@example.invalid"]
        }
        status, _, body = get("/user", {"name": "O'Reilly"})
        results["business_apostrophe"] = status == 200 and as_json(body) == {
            "user": [2, "oreilly@example.invalid"]
        }
        status, _, body = get("/user", {"name": "' OR 1=1 --"})
        with sqlite3.connect("file:/tmp/app.db?mode=ro", uri=True) as db:
            intact = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
        results["security_query_boundary"] = (
            status == 200 and as_json(body) == {"user": None} and intact
        )
    else:
        # The stub logs argv and fails only for UNREACHABLE_HOST, so a candidate that never
        # calls ping, or hard-codes True/False, cannot satisfy both business tests.
        for name, host, expected in (
            ("business_ping", "127.0.0.1", True),
            ("business_second_host", UNREACHABLE_HOST, False),
        ):
            seen = len(ping_calls())
            status, _, body = get("/ping", {"host": host})
            fresh = ping_calls()[seen:]
            results[name] = (
                status == 200
                and as_json(body) == {"reachable": expected}
                and any(host in argv for argv in fresh)
            )
        seen = len(ping_calls())
        status, _, _ = get("/ping", {"host": "127.0.0.1; touch " + str(MARKER)})
        fresh = ping_calls()[seen:]
        results["security_shell_boundary"] = (
            status in {200, 400, 422}
            and not MARKER.exists()
            and not any("touch" in argv or str(MARKER) in argv for argv in fresh)
        )
    return results


def main():
    make_undumpable()
    case = sys.argv[1] if len(sys.argv) > 1 else ""
    nonce = sys.stdin.readline().strip()
    sys.stdin.close()
    if case not in TESTS or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise SystemExit(3)
    deadline = time.monotonic() + BUDGET
    digest = hashlib.sha256(CANDIDATE.read_bytes()).hexdigest()
    if case == "sqli-01":
        seed_database()
    process = None
    try:
        process, ready = start_target(deadline)
        results = run_case(case, ready)
    except InfrastructureError:
        return 4
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
    tests = [{"name": name, "passed": bool(results[name])} for name in TESTS[case]]
    passed = all(test["passed"] for test in tests)
    sys.stdout.write(
        json.dumps(
            {
                "schema_version": SCHEMA,
                "case": case,
                "nonce": nonce,
                "candidate_sha256": digest,
                "tests": tests,
                "passed": passed,
            }
        )
        + "\n"
    )
    sys.stdout.flush()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
