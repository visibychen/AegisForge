"""Build the local fixed validator image; no model or API credentials in build context."""

import argparse
import os
import subprocess
import sys

from _environment import ROOT, require_conda


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", action="store_true", help="also build additive review-v1 image")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "backend"))
    from app.validation.registry import validator_fingerprint

    context = ROOT / "deploy" / "validator"
    environment = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("AEGISFORGE_", "ANTHROPIC_", "CLAUDE_"))
    }
    subprocess.run(
        [
            "docker",
            "build",
            "--build-arg",
            "VALIDATOR_FINGERPRINT=" + validator_fingerprint(),
            "-t",
            "aegisforge-validator:m4",
            str(context),
        ],
        check=True,
        env=environment,
    )
    if args.review:
        from app.validation.registry import review_validator_fingerprint

        subprocess.run(
            [
                "docker",
                "build",
                "--build-arg",
                "VALIDATOR_FINGERPRINT=" + review_validator_fingerprint(),
                "-t",
                "aegisforge-validator:review-v1",
                str(ROOT / "deploy/review-validator"),
            ],
            check=True,
            env=environment,
        )


if __name__ == "__main__":
    main()
