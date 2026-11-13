"""Build the local fixed validator image; no model or API credentials in build context."""

import os
import subprocess
import sys

from _environment import ROOT, require_conda


def main():
    require_conda()
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


if __name__ == "__main__":
    main()
