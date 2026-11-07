import argparse
import secrets
import shutil
import subprocess
import sys

from _environment import ROOT, model_environment, require_conda


def main() -> None:
    require_conda()
    parser = argparse.ArgumentParser(description="AegisForge local development commands")
    parser.add_argument("command", choices=["init", "migrate", "api", "web", "worker"])
    args = parser.parse_args()
    if args.command == "init":
        target = ROOT / ".env"
        try:
            with target.open("x", encoding="utf-8", newline="\n") as stream:
                template = (ROOT / ".env.example").read_text(encoding="utf-8")
                stream.write(
                    template.replace(
                        "AEGISFORGE_API_TOKEN=\n",
                        f"AEGISFORGE_API_TOKEN={secrets.token_urlsafe(32)}\n",
                    )
                )
        except FileExistsError:
            print(".env already exists; kept unchanged.")
        else:
            print("Created .env. Read its API token locally; do not share or commit it.")
        return
    if args.command == "migrate":
        command = [sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"]
    elif args.command == "api":
        command = [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--app-dir",
            "backend",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ]
    elif args.command == "worker":
        command = [sys.executable, "-m", "app.worker"]
    else:
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm:
            raise SystemExit("Node.js / npm is required.")
        command = [npm, "--prefix", "frontend", "run", "dev"]
    subprocess.run(
        command,
        cwd=ROOT / "backend" if args.command == "worker" else ROOT,
        env=model_environment() if args.command in {"api", "worker"} else None,
        check=True,
    )


if __name__ == "__main__":
    main()
