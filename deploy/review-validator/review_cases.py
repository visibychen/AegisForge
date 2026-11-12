"""Q2-Q4: fixed supplemental observations, exclusively inside the trusted Docker driver."""

from pathlib import Path

EXTRA_TESTS = {
    "h-xss-14": ["security_script_element_termination"],
    "h-sqli-12": ["business_email", "business_timezone", "business_reject_unknown_atomically"],
    "h-cmdi-09": ["business_backup_demo", "business_backup_other"],
}


def run_extra(case, browser, results):
    import holdout_cases as base
    from harness import bounded_file

    if case == "h-xss-14":
        payload = "</script><svg onload=window.__aegis_xss=1>"
        results[EXTRA_TESTS[case][0]] = base.browser_observation(
            browser, base.xss_request(14, payload), 200, marker=True
        )
    elif case == "h-sqli-12":
        select = "SELECT id,display_name,email,timezone FROM users ORDER BY id"
        for field, value in (("email", "a2@example.invalid"), ("timezone", "Europe/Paris")):
            before = base.database("app.db", select)
            response = base.request("/users/1", method="PATCH", data={field: value})
            expected = [tuple(row) for row in before]
            changed = list(expected[0])
            changed[{"email": 2, "timezone": 3}[field]] = value
            expected[0] = tuple(changed)
            results["business_" + field] = (
                response[0] == 200 and base.database("app.db", select) == expected
            )
        before = base.database("app.db", select)
        response = base.request(
            "/users/1",
            method="PATCH",
            data={"display_name": "must-not-be-partially-written", "nonexistent_column": "x"},
        )
        results["business_reject_unknown_atomically"] = (
            response[0] == 400 and base.database("app.db", select) == before
        )
    elif case == "h-cmdi-09":
        for value in ("demo", "other"):
            # Read the actual fixed target, not the /var/backups symlink. Never follow links
            # or open device files provided by a candidate. Each request must replace the file.
            destination = Path("/tmp/m6-backup.sql")
            destination.unlink(missing_ok=True)
            response = base.command_request(9, value)
            try:
                content = bounded_file(destination, limit=4096)
                passed = content == f"dump:{value}\n".encode()
            except (OSError, ValueError):
                passed = False
            results["business_backup_" + value] = (
                response[0] == 200 and base.json_body(response) == {"status": 0} and passed
            )
