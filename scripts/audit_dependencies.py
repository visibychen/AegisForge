"""Audit exact locked Python versions via the PyPI JSON advisory database (no installs)."""

import json
import re
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from _environment import ROOT, require_conda


def inspect_package(item):
    name, version = item
    url = (
        "https://pypi.org/pypi/"
        + urllib.parse.quote(name, safe="")
        + "/"
        + urllib.parse.quote(version, safe="")
        + "/json"
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=20) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("advisory response too large")
        payload = json.loads(raw)
        vulns = payload["vulnerabilities"]
        if not isinstance(vulns, list):
            raise ValueError("invalid advisory response")
        return {
            "name": name,
            "version": version,
            "source": url,
            "status": "checked",
            "advisories": [
                {k: v.get(k) for k in ("id", "aliases", "fixed_in", "link", "summary", "withdrawn")}
                for v in vulns
                if not v.get("withdrawn")
            ],
        }
    except (OSError, ValueError, KeyError, TypeError):
        return {
            "name": name,
            "version": version,
            "source": url,
            "status": "unavailable",
            "advisories": [],
        }


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.experiment import file_hash, write_json

    paths = [
        "backend/requirements.lock",
        "backend/requirements-dev.lock",
        "deploy/validator/requirements.lock",
    ]
    packages = set()
    for path in paths:
        packages.update(
            re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", (ROOT / path).read_text(), re.MULTILINE)
        )
    with ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(inspect_package, sorted(packages)))
    report = {
        "checked_at": datetime.now(UTC).isoformat(),
        "method": (
            "exact locked transitive versions via public PyPI JSON vulnerability advisories; "
            "no package installation or execution"
        ),
        "locks": {p: file_hash(ROOT / p) for p in paths},
        "passed": bool(rows)
        and all(r["status"] == "checked" and not r["advisories"] for r in rows),
        "packages": rows,
        "limitations": (
            "Advisory snapshot only; does not audit OS libraries or unknown vulnerabilities."
        ),
    }
    write_json(ROOT / "data/m6-python-audit.json", report)
    print(
        json.dumps(
            {
                "packages": len(rows),
                "passed": report["passed"],
                "unavailable": sum(r["status"] != "checked" for r in rows),
                "advisories": [
                    {"name": r["name"], "version": r["version"], "advisories": r["advisories"]}
                    for r in rows
                    if r["advisories"]
                ],
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
