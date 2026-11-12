import argparse
import shutil
import subprocess
import sys

from _environment import ROOT, require_conda


def run(command: list[str], cwd=ROOT) -> None:
    print("Checking:", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def main() -> None:
    require_conda()
    parser = argparse.ArgumentParser(description="Run the implemented AegisForge quality checks")
    parser.add_argument("--backend-only", action="store_true")
    args = parser.parse_args()
    config = "backend/pyproject.toml"
    run([sys.executable, "-m", "pip", "check"])
    run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--config",
            config,
            "backend",
            "scripts",
            "evaluation",
            "deploy/validator",
            "deploy/review-validator",
        ]
    )
    run(
        [
            sys.executable,
            "-m",
            "ruff",
            "format",
            "--check",
            "--config",
            config,
            "backend",
            "scripts",
            "evaluation",
            "deploy/validator",
            "deploy/review-validator",
        ]
    )
    run([sys.executable, "-m", "pytest"], cwd=ROOT / "backend")
    run([sys.executable, "evaluation/datasets.py", "check"])
    if not args.backend_only:
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm:
            raise SystemExit("Node.js / npm is required.")
        for script in ["typecheck", "test", "build"]:
            run([npm, "run", script], cwd=ROOT / "frontend")


if __name__ == "__main__":
    main()
