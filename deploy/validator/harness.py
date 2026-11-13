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
import stat
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
from holdout_cases import TESTS as HOLDOUT_TESTS  # noqa: E402

TESTS.update(HOLDOUT_TESTS)
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
    try:
        return body.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return ""


def as_json(body):
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
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
            if process.returncode == 3:
                raise InfrastructureError
            return process, False  # the candidate crashed on import: its tests fail
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", PORT)) == 0:
                return process, True
        time.sleep(0.05)
    return process, False


def bounded_file(path, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("untrusted file")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("untrusted file")
        return data


def ping_calls():
    try:
        raw = bounded_file(PING_LOG)
    except FileNotFoundError:
        return []
    calls = []
    for line in raw.decode("utf-8").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, list) and all(isinstance(x, str) for x in value):
                calls.append(value)
        except (ValueError, RecursionError):
            continue
    return calls


def seed_database():
    with sqlite3.connect("/tmp/app.db") as db:
        db.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
        db.executemany(
            "INSERT INTO users VALUES (?,?,?)",
            [
                (1, "Alice", "alice@example.invalid"),
                (2, "O'Reilly", "oreilly@example.invalid"),
            ],
        )


def xss_security(browser):
    from playwright.sync_api import Error

    payload = '<svg onload="window.__aegis_xss=1"></svg>'
    url = f"http://127.0.0.1:{PORT}/greet?" + urllib.parse.urlencode({"name": payload})
    page = browser.new_page()
    try:
        page.route(
            "**/*",
            lambda route: (
                route.continue_()
                if route.request.url.startswith(f"http://127.0.0.1:{PORT}/")
                else route.abort()
            ),
        )
        response = page.goto(url, timeout=5000)
        page.wait_for_timeout(200)
        return bool(
            response is not None
            and response.status == 200
            and page.evaluate("window.__aegis_xss === undefined")
        )
    except Error:
        return False
    finally:
        page.close()


def run_case(case, ready, browser, results):
    if case in HOLDOUT_TESTS:
        from holdout_cases import run_case as run_holdout

        return run_holdout(case, ready, browser, results)
    if not ready:
        return results
    if case == "xss-01":
        status, headers, body = get("/greet", {"name": "Alice"})
        results["business_greeting"] = status == 200 and "Hello, Alice!" in text(headers, body)
        status, headers, body = get("/greet", {"name": "铸盾"})
        results["business_unicode"] = status == 200 and "铸盾" in text(headers, body)
        try:
            results["security_browser_no_script"] = xss_security(browser)
        except Exception:  # noqa: BLE001 - preserve completed business observations
            results["security_browser_no_script"] = False
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
        try:
            bounded_file(Path("/tmp/app.db"))
            with sqlite3.connect("file:/tmp/app.db?mode=ro", uri=True, timeout=0.1) as db:
                intact = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
            results["security_query_boundary"] = (
                status == 200 and as_json(body) == {"user": None} and intact
            )
        except Exception:  # noqa: BLE001 - a corrupt candidate database fails only this test
            results["security_query_boundary"] = False
    else:
        # Two observed calls and opposite expected statuses reject hard-coded returns.
        for name, host, expected in (
            ("business_ping", "127.0.0.1", True),
            ("business_second_host", UNREACHABLE_HOST, False),
        ):
            try:
                seen = len(ping_calls())
                status, _, body = get("/ping", {"host": host})
                fresh = ping_calls()[seen:]
                results[name] = (
                    status == 200
                    and as_json(body) == {"reachable": expected}
                    and any(host in argv for argv in fresh)
                )
            except Exception:  # noqa: BLE001 - malformed logs cannot stop the other tests
                results[name] = False
        try:
            seen = len(ping_calls())
            status, _, _ = get("/ping", {"host": "127.0.0.1; touch " + str(MARKER)})
            fresh = ping_calls()[seen:]
            results["security_shell_boundary"] = (
                status in {200, 400, 422}
                and not MARKER.exists()
                and not any("touch" in argv or str(MARKER) in argv for argv in fresh)
            )
        except Exception:  # noqa: BLE001 - malformed candidate files are test failures
            results["security_shell_boundary"] = False

    return results


def main():
    make_undumpable()
    case = sys.argv[1] if len(sys.argv) > 1 else ""
    nonce = sys.stdin.readline().strip()
    sys.stdin.close()
    if case not in TESTS or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise SystemExit(3)
    digest = hashlib.sha256(CANDIDATE.read_bytes()).hexdigest()
    results = {name: False for name in TESTS[case]}
    emitted, candidate_phase = False, False

    def emit():
        nonlocal emitted
        if emitted:
            return
        emitted = True
        tests = [{"name": name, "passed": bool(results[name])} for name in TESTS[case]]
        payload = {
            "schema_version": SCHEMA,
            "case": case,
            "nonce": nonce,
            "candidate_sha256": digest,
            "tests": tests,
            "passed": all(test["passed"] for test in tests),
        }
        os.write(1, (json.dumps(payload) + "\n").encode("utf-8"))

    def watchdog(*_):
        if candidate_phase:
            # Incomplete tests stay false. No partial run can be reported as passed.
            emit()
            os._exit(1)
        os._exit(4)  # trusted setup/browser failure, not candidate evidence

    signal.signal(signal.SIGALRM, watchdog)
    signal.setitimer(signal.ITIMER_REAL, BUDGET)
    process = browser = playwright = None
    try:
        # Test the child guard and browser before candidate execution. Failure is an error.
        probe = subprocess.run(
            [sys.executable, "/opt/validator/target_guard.py"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        if probe.returncode:
            raise InfrastructureError
        if case == "xss-01" or case.startswith("h-xss-"):
            from playwright.sync_api import sync_playwright

            playwright = sync_playwright().start()
            browser = playwright.chromium.launch(
                headless=True,
                timeout=12000,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
        if case == "sqli-01":
            seed_database()
        if case in HOLDOUT_TESTS:
            from holdout_cases import setup

            setup(case)
        candidate_phase = True
        process, ready = start_target(time.monotonic() + BUDGET)
        try:
            results = run_case(case, ready, browser, results)
        except Exception:  # noqa: BLE001 - malformed candidate responses fail closed
            pass
        emit()
        return 0 if all(results.values()) else 1
    except InfrastructureError:
        return 4
    except Exception:  # noqa: BLE001 - never expose runtime details or fabricate a pass
        if candidate_phase:
            emit()
            return 1
        return 4
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        if browser is not None:
            browser.close()
        if playwright is not None:
            playwright.stop()


if __name__ == "__main__":
    raise SystemExit(main())
