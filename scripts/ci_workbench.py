"""Disposable GitHub Ubuntu Compose acceptance. Never imports model credentials."""

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


def main():
    require_conda()
    if os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "linux":
        raise SystemExit("This launcher is for a disposable GitHub Linux runner only.")
    if os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY") or os.environ.get("AEGISFORGE_E2E_REAL"):
        raise SystemExit("Acceptance requires no model credential and no live model opt-in.")
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
            run(npm, "--prefix", "frontend", "run", "test:e2e", "--", "--workers=1")
            subprocess.run(
                [
                    npm,
                    "--prefix",
                    "frontend",
                    "run",
                    "test:e2e",
                    "--",
                    "--workers=1",
                    "tests/e2e/foundation.spec.ts",
                ],
                cwd=ROOT,
                env={**os.environ, "PLAYWRIGHT_BROWSER": "firefox"},
                check=True,
            )
            for viewport in ("desktop", "mobile"):
                screenshot = ROOT / "frontend/test-results" / f"foundation-{viewport}.png"
                screenshot.rename(screenshot.with_name(f"m6-firefox-foundation-{viewport}.png"))
            run(sys.executable, "scripts/verify_report.py", "data/m5-e2e-report.json")
            passed = True
    finally:
        (directory / "m5-e2e-summary.json").write_text(
            json.dumps(
                {
                    "passed": passed,
                    "mode": "fake",
                    "external_model_calls": 0,
                    "browsers": ["chromium", "firefox"],
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
