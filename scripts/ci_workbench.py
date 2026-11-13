"""Disposable GitHub Ubuntu Compose acceptance. Never imports model credentials."""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

from _environment import ROOT, require_conda

EVIDENCE = ROOT / "frontend" / "test-results" / "evidence"
BROWSER_VERSION = "1.64.1"
BROWSER_IMAGE = (
    "mcr.microsoft.com/playwright:v1.64.1-noble@"
    "sha256:ee15712262f017b8157421b212b12099146645f44b1bc5c0514cbbe6a229b1d0"
)


def browser_image():
    package = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
    if package["devDependencies"]["@playwright/test"] != BROWSER_VERSION:
        raise ValueError("Update the verified browser image when changing Playwright")
    return BROWSER_IMAGE


def browser_command(browser, report, node, user, *specs):
    """Trusted CI UI tests only; no model credential or Docker socket enters this container."""
    if browser not in {"chromium", "firefox"}:
        raise ValueError("Unsupported browser")
    return [
        "docker",
        "run",
        "--rm",
        "--init",
        "--network=host",
        "--shm-size=1g",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        user,
        "--volume",
        f"{ROOT}:{ROOT}",
        "--workdir",
        str(ROOT),
        # Keep the project's Node 24 runtime; the browser image supplies browser OS libraries.
        "--volume",
        f"{node}:/usr/local/bin/node:ro",
        "--env",
        "HOME=/tmp",
        "--env",
        f"PLAYWRIGHT_BROWSER={browser}",
        "--env",
        f"PLAYWRIGHT_JSON_REPORT={report}",
        "--env",
        "AEGISFORGE_DEEPSEEK_API_KEY=",
        browser_image(),
        "npm",
        "--prefix",
        "frontend",
        "run",
        "test:e2e",
        "--",
        "--workers=1",
        *specs,
    ]


def ready(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise RuntimeError("Local acceptance service was not ready.")


def counts(report):
    """Only the four integers of Playwright's stats; the raw report may contain error text."""
    keys = ("expected", "skipped", "unexpected", "flaky")
    try:
        stats = json.loads(report.read_text(encoding="utf-8"))["stats"]
        return {key: int(stats.get(key, 0)) for key in keys}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def collect(browser):
    """Keep this browser's screenshots under its own name before anything can overwrite them."""
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for source in sorted((ROOT / "frontend" / "test-results").glob("*.png")):
        source.replace(EVIDENCE / f"{browser}-{source.name}")


def playwright(npm, browser, directory, *specs):
    """One real browser run. Returns its (never raw) result entry and the process status."""
    report = directory / f"playwright-{browser}.json"  # ignored data directory, never uploaded
    report.unlink(missing_ok=True)
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node 24 is required")
    command = browser_command(browser, report, node, f"{os.getuid()}:{os.getgid()}", *specs)
    status = subprocess.run(command, cwd=ROOT, check=False).returncode
    entry = {"browser": browser, "specs": list(specs) or "all", "exit_code": status}
    entry["runner"] = {"image": browser_image(), "node": "host Node 24, mounted read-only"}
    stats = entry["stats"] = counts(report)
    entry["passed"] = status == 0 and stats is not None and not stats["unexpected"]
    return entry


def main():
    require_conda()
    if os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "linux":
        raise SystemExit("This launcher is for a disposable GitHub Linux runner only.")
    if os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY") or os.environ.get("AEGISFORGE_E2E_REAL"):
        raise SystemExit("Acceptance requires no model credential and no live model opt-in.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pull-browser-image", action="store_true")
    args = parser.parse_args()
    if args.pull_browser_image:
        subprocess.run(["docker", "pull", browser_image()], check=True, timeout=360)
        return
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT / "backend"))
    from app.core.config import Settings

    def run(*args):
        subprocess.run(args, cwd=ROOT, check=True)

    run(sys.executable, "scripts/dev.py", "init")
    # GitHub consumes this command and masks the ephemeral API token in Playwright failures.
    print("::add-mask::" + Settings().api_token.get_secret_value(), flush=True)
    run(sys.executable, "scripts/build_validator.py")
    run(sys.executable, "scripts/deploy.py", "build")
    directory = ROOT / "data"
    directory.mkdir(exist_ok=True)
    directory.chmod(0o777)  # disposable synthetic CI data only; container UID1000, runner UID1001
    npm = shutil.which("npm")
    process = None
    passed = False
    runs = []  # only browsers that were really started are ever listed
    try:
        run(sys.executable, "scripts/deploy.py", "up")
        ready("http://127.0.0.1:8000/health")
        run(sys.executable, "scripts/probe_deployment.py")
        with (directory / "m5-vite.log").open("wb") as output:
            process = subprocess.Popen(
                [npm, "--prefix", "frontend", "run", "dev"],
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            ready("http://127.0.0.1:5173/")
            runs.append(playwright(npm, "chromium", directory))
            collect("chromium")
            if not runs[-1]["passed"]:
                raise SystemExit("Chromium end-to-end run failed.")
            runs.append(playwright(npm, "firefox", directory, "tests/e2e/foundation.spec.ts"))
            collect("firefox")
            if not runs[-1]["passed"]:
                raise SystemExit("Firefox core run failed.")
            run(sys.executable, "scripts/verify_report.py", "data/m5-e2e-report.json")
            passed = True
    finally:
        (directory / "m5-e2e-summary.json").write_text(
            json.dumps(
                {
                    "passed": passed,
                    "mode": "fake",
                    "external_model_calls": 0,
                    "browsers": [item["browser"] for item in runs],
                    "runs": runs,
                    "commit": os.environ.get("GITHUB_SHA"),
                    "run_id": os.environ.get("GITHUB_RUN_ID"),
                    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                    "deployment": "Compose API/worker and trusted Docker controller",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        with (directory / "m5-ci-services.log").open("wb") as output:
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "--env-file",
                    ".env.example",
                    "-f",
                    "deploy/compose.yml",
                    "logs",
                    "--no-color",
                    "--tail",
                    "100",
                ],
                stdout=output,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=20,
            )
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
        run(sys.executable, "scripts/deploy.py", "down")


if __name__ == "__main__":
    main()
