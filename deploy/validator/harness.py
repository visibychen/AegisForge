"""Fixed development regressions; not sent to generation or detection models."""

import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path


def main():
    case = sys.argv[1]
    assert case in {"xss-01", "sqli-01", "cmdi-01"}
    # Candidate is read-only; all database/browser state is confined to the tmpfs.
    os.chdir("/tmp")
    spec = importlib.util.spec_from_file_location("candidate", "/candidate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client = module.app.test_client()
    module.app.config["TESTING"] = False
    tests = []

    def check(name, ok):
        tests.append({"name": name, "passed": bool(ok)})

    if case == "xss-01":
        normal = client.get("/greet", query_string={"name": "Alice"})
        check("business_greeting", normal.status_code == 200 and "Hello, Alice!" in normal.text)
        unicode = client.get("/greet", query_string={"name": "铸盾"})
        check("business_unicode", unicode.status_code == 200 and "铸盾" in unicode.text)
        from playwright.sync_api import sync_playwright

        attack = client.get(
            "/greet", query_string={"name": '<svg onload="window.__aegis_xss=1"></svg>'}
        )
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            page = browser.new_page()
            page.route("**/*", lambda route: route.abort())
            page.set_content(attack.text)
            page.wait_for_timeout(200)
            check(
                "security_browser_no_script",
                attack.status_code == 200 and page.evaluate("window.__aegis_xss === undefined"),
            )
            browser.close()
    elif case == "sqli-01":
        with sqlite3.connect("app.db") as db:
            db.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
            db.executemany(
                "INSERT INTO users VALUES (?,?,?)",
                [(1, "Alice", "alice@example.invalid"), (2, "O'Reilly", "oreilly@example.invalid")],
            )
        normal = client.get("/user", query_string={"name": "Alice"})
        check(
            "business_lookup",
            normal.status_code == 200 and normal.json == {"user": [1, "alice@example.invalid"]},
        )
        quote = client.get("/user", query_string={"name": "O'Reilly"})
        check(
            "business_apostrophe",
            quote.status_code == 200 and quote.json == {"user": [2, "oreilly@example.invalid"]},
        )
        attack = client.get("/user", query_string={"name": "' OR 1=1 --"})
        check(
            "security_query_boundary", attack.status_code == 200 and attack.json == {"user": None}
        )
    else:
        normal = client.get("/ping", query_string={"host": "127.0.0.1"})
        check("business_ping", normal.status_code == 200 and normal.json == {"reachable": True})
        other = client.get("/ping", query_string={"host": "192.0.2.1"})
        check(
            "business_second_host", other.status_code == 200 and other.json == {"reachable": True}
        )
        marker = Path("/tmp/aegis-command-marker")
        attack = client.get(
            "/ping", query_string={"host": "127.0.0.1; touch /tmp/aegis-command-marker"}
        )
        check(
            "security_shell_boundary", not marker.exists() and attack.status_code in {200, 400, 422}
        )
    print(
        json.dumps(
            {
                "schema_version": "validation-1.0",
                "case": case,
                "tests": tests,
                "passed": all(t["passed"] for t in tests),
            }
        )
    )
    return 0 if all(t["passed"] for t in tests) else 1


if __name__ == "__main__":
    raise SystemExit(main())
