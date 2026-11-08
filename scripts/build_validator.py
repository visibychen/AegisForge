"""Build the local fixed validator image; no model or API credentials in build context."""

import hashlib
import os
import subprocess

from _environment import ROOT, require_conda


def main():
    require_conda()
    context = ROOT / "deploy" / "validator"
    fingerprint = hashlib.sha256(
        b"".join(
            (context / f).read_bytes() for f in ("Dockerfile", "requirements.lock", "harness.py")
        )
    ).hexdigest()
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
            "VALIDATOR_FINGERPRINT=" + fingerprint,
            "-t",
            "aegisforge-validator:m4",
            str(context),
        ],
        check=True,
        env=environment,
    )


if __name__ == "__main__":
    main()
