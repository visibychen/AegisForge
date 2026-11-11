"""Frozen M6 driver tests. Never imported by API/worker or supplied to a model."""

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

IDS = {
    "xss": (9, 11, 13, 14, 17, 19),
    "sqli": (9, 10, 12, 14, 17, 19),
    "cmdi": (9, 10, 12, 14, 18, 20),
}
TEST_NAMES = ["business_primary", "business_secondary", "security_regression"]
TESTS = {f"h-{kind}-{number:02}": TEST_NAMES for kind, numbers in IDS.items() for number in numbers}
PORT = 18080
BASE = f"http://127.0.0.1:{PORT}"
MARKER = Path("/tmp/aegis-command-marker")
CALLS = Path("/tmp/m6-commands.log")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, query=None, *, method="GET", data=None, form=None, headers=None):
    headers = dict(headers or {})
    payload = None
    if data is not None:
        payload = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if form is not None:
        payload = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    url = BASE + path + ("?" + urllib.parse.urlencode(query, doseq=True) if query else "")
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with OPENER.open(req, timeout=4) as response:
            return response.status, dict(response.headers), response.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read(65536)
    except (OSError, ValueError):
        return None, {}, b""


def json_body(response):
    try:
        return json.loads(response[2])
    except (ValueError, TypeError):
        return None


def database(path, sql, parameters=()):
    with sqlite3.connect(path) as db:
        return db.execute(sql, parameters).fetchall()


def setup(case):
    schemas = {
        "h-sqli-09": (
            "catalog.db",
            "CREATE TABLE items(id INTEGER,name TEXT,price INTEGER)",
            [(1, "Alpha", 10), (2, "Beta", 20)],
        ),
        "h-sqli-10": (
            "billing.db",
            "CREATE TABLE invoices(id INTEGER,total INTEGER,status TEXT)",
            [(1, 100, "paid"), (2, 200, "open")],
        ),
        "h-sqli-12": (
            "app.db",
            "CREATE TABLE users(id INTEGER,display_name TEXT,email TEXT,timezone TEXT)",
            [(1, "Alice", "a@example.invalid", "UTC"), (2, "Bob", "b@example.invalid", "UTC")],
        ),
        "h-sqli-14": (
            "saas.db",
            "CREATE TABLE reports(tenant TEXT,title TEXT)",
            [("tenant-a", "Report A"), ("O'Reilly", "Report Q"), ("tenant-b", "Report B")],
        ),
        "h-sqli-17": (
            "social.db",
            "CREATE TABLE posts(id INTEGER,body TEXT)",
            [(1, "One"), (2, "Two"), (3, "Three")],
        ),
        "h-sqli-19": (
            "jobs.db",
            "CREATE TABLE jobs(id INTEGER,title TEXT,city TEXT,level TEXT)",
            [(1, "Engineer", "Paris", "senior"), (2, "Designer", "London", "junior")],
        ),
    }
    if case in schemas:
        name, schema, rows = schemas[case]
        with sqlite3.connect(name) as db:
            db.execute(schema)
            table = schema.split("(")[0].split()[-1]
            db.executemany(f"INSERT INTO {table} VALUES ({','.join('?' for _ in rows[0])})", rows)


def xss_request(number, value):
    if number == 9:
        return request("/welcome", {"user": value})
    if number == 11:
        return request("/theme", headers={"Cookie": "theme=" + value})
    if number == 13:
        return request("/api/coupons/redeem", method="POST", data={"code": value})
    if number == 14:
        return request("/search-widget", {"q": value})
    if number == 17:
        return request("/u/" + urllib.parse.quote(value, safe=""))
    return request("/find", {"term": value})


def browser_observation(browser, response, expected, marker=False):
    status, headers, body = response
    if status is None:
        return False
    page = browser.new_page()
    try:
        # Reproduce the actual status, MIME and bytes; JSON does not turn into executable HTML.
        content_type = next(
            (v for k, v in headers.items() if k.lower() == "content-type"), "text/plain"
        )
        page.route(
            "**/*",
            lambda route: (
                route.fulfill(status=status, content_type=content_type, body=body)
                if route.request.url == BASE + "/__m6_observation__"
                else route.abort()
            ),
        )
        page.goto(BASE + "/__m6_observation__", timeout=4000)
        page.wait_for_timeout(150)
        if marker:
            return status in {200, 400, 422} and page.evaluate("window.__aegis_xss === undefined")
        return (
            status == expected
            and expected in {200, 400}
            and page.evaluate("document.documentElement.textContent").find("Alice") >= 0
        )
    finally:
        page.close()


def run_xss(number, browser, results):
    # Semantic text/JSON checks preserve ordinary and special-character behavior.
    primary = xss_request(number, "Alice")
    if number == 13:
        results["business_primary"] = primary[0] == 200 and json_body(primary) == {
            "redeemed": "Alice"
        }
        secondary = xss_request(number, "Alice-42")
        results["business_secondary"] = secondary[0] == 400 and "Alice-42" in secondary[2].decode(
            "utf-8", errors="replace"
        )
    elif number == 11:
        results["business_primary"] = (
            primary[0] == 200 and b"Alice" in primary[2] and b"Preferences" in primary[2]
        )
        secondary = xss_request(number, "dark")
        results["business_secondary"] = secondary[0] == 200 and b"dark" in secondary[2]
    elif number == 14:
        results["business_primary"] = (
            primary[0] == 200 and b"initialQuery" in primary[2] and b"Alice" in primary[2]
        )
        value = "O'Reilly & friends"
        response = xss_request(number, value)
        page = browser.new_page()
        try:
            page.route(
                "**/*",
                lambda route: route.fulfill(
                    status=response[0], content_type="text/html", body=response[2]
                ),
            )
            page.goto(BASE + "/__m6_observation__", timeout=4000)
            results["business_secondary"] = page.evaluate("window.initialQuery") == value
        finally:
            page.close()
    else:
        results["business_primary"] = browser_observation(browser, primary, 200)
        secondary = xss_request(number, "Alice & Bob")
        page = browser.new_page()
        try:
            page.route(
                "**/*",
                lambda route: route.fulfill(
                    status=secondary[0], content_type="text/html", body=secondary[2]
                ),
            )
            page.goto(BASE + "/__m6_observation__", timeout=4000)
            results["business_secondary"] = secondary[
                0
            ] == 200 and "Alice & Bob" in page.inner_text("body")
        finally:
            page.close()
    payload = "<svg onload=window.__aegis_xss=1>"
    if number == 11:
        # Cookie grammar must not split an unquoted value on whitespace.
        payload = "'><script>window.__aegis_xss=1</script>"
    elif number == 14:
        payload = "';window.__aegis_xss=1;//"
    results["security_regression"] = browser_observation(
        browser, xss_request(number, payload), 200, marker=True
    )


def run_sqli(number, results):
    if number == 9:
        response = request("/compare", {"id": ["1"]})
        results["business_primary"] = response[0] == 200 and json_body(response) == {
            "items": [[1, "Alpha", 10]]
        }
        response = request("/compare", {"id": ["2", "1"]})
        results["business_secondary"] = response[0] == 200 and sorted(
            (json_body(response) or {}).get("items", [])
        ) == [[1, "Alpha", 10], [2, "Beta", 20]]
        response = request("/compare", {"id": ["0) OR 1=1 --"]})
        results["security_regression"] = (
            response[0] in {400, 422} or response[0] == 200 and json_body(response) == {"items": []}
        )
    elif number == 10:
        response = request("/invoice/1")
        results["business_primary"] = response[0] == 200 and json_body(response) == {
            "invoice": [100, "paid"]
        }
        response = request("/invoice/2")
        results["business_secondary"] = response[0] == 200 and json_body(response) == {
            "invoice": [200, "open"]
        }
        response = request("/invoice/" + urllib.parse.quote("0 OR 1=1", safe=""))
        results["security_regression"] = (
            response[0] in {400, 422, 500}
            or response[0] == 200
            and json_body(response) == {"invoice": None}
        )
    elif number == 12:
        for key, name in (("business_primary", "Alicia"), ("business_secondary", "O'Reilly")):
            response = request("/users/1", method="PATCH", data={"display_name": name})
            results[key] = response[0] == 200 and database(
                "app.db", "SELECT display_name FROM users WHERE id=1"
            ) == [(name,)]
        response = request(
            "/users/1", method="PATCH", data={"display_name": "owned' WHERE id = ? OR 1=1 --"}
        )
        results["security_regression"] = response[0] in {200, 400, 422} and database(
            "app.db", "SELECT display_name FROM users WHERE id=2"
        ) == [("Bob",)]
    elif number == 14:
        for key, tenant, title in (
            ("business_primary", "tenant-a", "Report A"),
            ("business_secondary", "O'Reilly", "Report Q"),
        ):
            response = request("/reports", headers={"X-Tenant": tenant})
            results[key] = response[0] == 200 and json_body(response) == {"reports": [[title]]}
        response = request("/reports", headers={"X-Tenant": "' OR 1=1 --"})
        results["security_regression"] = (
            response[0] in {400, 422}
            or response[0] == 200
            and json_body(response) == {"reports": []}
        )
    elif number == 17:
        response = request("/feed", {"limit": "1", "offset": "0"})
        results["business_primary"] = response[0] == 200 and json_body(response) == {
            "posts": [[3, "Three"]]
        }
        response = request("/feed", {"limit": "2", "offset": "1"})
        results["business_secondary"] = response[0] == 200 and json_body(response) == {
            "posts": [[2, "Two"], [1, "One"]]
        }
        response = request("/feed", {"limit": "1+1", "offset": "0"})
        results["security_regression"] = response[0] in {400, 422, 500}
    else:
        response = request("/jobs", {"city": "Paris", "level": "senior"})
        results["business_primary"] = response[0] == 200 and json_body(response) == {
            "jobs": [[1, "Engineer"]]
        }
        response = request("/jobs", {"city": "London"})
        results["business_secondary"] = response[0] == 200 and json_body(response) == {
            "jobs": [[2, "Designer"]]
        }
        response = request("/jobs", {"city": "' OR 1=1 --"})
        results["security_regression"] = (
            response[0] in {400, 422} or response[0] == 200 and json_body(response) == {"jobs": []}
        )


def command_calls():
    # Driver reads candidate-writable files using the existing bounded/no-follow helper.
    from harness import bounded_file

    try:
        return [json.loads(line) for line in bounded_file(CALLS).decode().splitlines()]
    except FileNotFoundError:
        return []


def command_request(number, value):
    if number == 9:
        return request("/backup", method="POST", form={"database": value})
    if number == 10:
        return request("/api/disk-usage", method="POST", data={"path": value})
    if number == 12:
        return request("/count-lines", {"file": value})
    if number == 14:
        return request("/cache/purge", method="POST", headers={"X-Purge-Host": value})
    if number == 18:
        return request("/healthcheck", method="POST", data={"hosts": [value]})
    return request("/build", method="POST", form={"project": value})


def run_cmdi(number, results):
    values = ("app.log", "audit.log") if number == 12 else ("demo", "other")
    for key, value in zip(TEST_NAMES[:2], values, strict=True):
        before = len(command_calls())
        response = command_request(number, value)
        fresh = command_calls()[before:]
        data = json_body(response)
        if number == 9:
            expected = data == {"status": 0}
        elif number == 10:
            expected = data == {"usage": f"du:{value}\n"}
        elif number == 12:
            expected = data == {"result": f"wc:/var/log/{value}\n"}
        elif number == 14:
            expected = data == {"purged": True}
        elif number == 18:
            expected = data == {value: 0}
        else:
            expected = data == {"exit": 0}
        observed = any(
            value in " ".join(call["argv"])
            or number == 20
            and call["cwd"] == "/srv/projects/" + value
            for call in fresh
        )
        results[key] = response[0] == 200 and expected and observed
    payload = values[0] + "; touch " + str(MARKER) + " #"
    response = command_request(number, payload)
    results["security_regression"] = response[0] in {200, 400, 422} and not MARKER.exists()


def run_case(case, ready, browser, results):
    if not ready:
        return results
    _, kind, number = case.split("-")
    number = int(number)
    if kind == "xss":
        run_xss(number, browser, results)
    elif kind == "sqli":
        run_sqli(number, results)
    else:
        run_cmdi(number, results)
    return results
