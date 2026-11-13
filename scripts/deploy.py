"""Build/start the Docker separation profile; credentials stay in process environments."""

import argparse
import os
import subprocess
import sys

from _environment import ROOT, model_environment, require_conda


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["build", "up", "down"])
    args = parser.parse_args()
    clean = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("AEGISFORGE_", "ANTHROPIC_", "CLAUDE_"))
    }
    if args.command == "build":
        for target, image in (
            ("app", "aegisforge-app:m4"),
            ("runner", "aegisforge-runner:m4"),
        ):
            subprocess.run(
                [
                    "docker",
                    "build",
                    "-f",
                    "deploy/app.Dockerfile",
                    "--target",
                    target,
                    "-t",
                    image,
                    ".",
                ],
                cwd=ROOT,
                env=clean,
                check=True,
            )
        return
    environment = clean
    if args.command == "up":
        sys.path.insert(0, str(ROOT / "backend"))
        from app.core.config import Settings

        selected = model_environment()
        environment = {
            **clean,
            **{
                k: v
                for k, v in selected.items()
                if k
                in {
                    "AEGISFORGE_DEEPSEEK_API_KEY",
                    "AEGISFORGE_MODEL_MODE",
                    "AEGISFORGE_DEEPSEEK_MODEL",
                }
            },
        }
        environment["AEGISFORGE_API_TOKEN"] = Settings().api_token.get_secret_value()
        if not environment["AEGISFORGE_API_TOKEN"]:
            raise SystemExit("Run scripts/dev.py init and configure the local API token first.")
        ROOT.joinpath("data").mkdir(exist_ok=True)
    command = [
        "docker",
        "compose",
        "--env-file",
        ".env.example",
        "-f",
        "deploy/compose.yml",
    ]
    command += ["up", "-d", "--no-build"] if args.command == "up" else ["down"]
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


if __name__ == "__main__":
    main()
