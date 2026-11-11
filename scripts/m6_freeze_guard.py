"""Compare frozen samples and historical M6 baseline evidence with the recorded pre-tuning commit.

This is a reviewable Git history guard, not a digital signature. The original baseline records
were all committed before the second collaboration round. Later diagnostic files have other names.
"""

import subprocess

from _environment import ROOT, require_conda

BASELINE_COMMIT = "e527d91fe49fd1e0991c15f2a3e2b9d3d7d9be20"


def main():
    require_conda()
    result = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            BASELINE_COMMIT,
            "--",
            "samples",
            ":(glob)evaluation/results/*baseline*",
        ],
        cwd=ROOT,
        check=False,
    )
    print("M6 frozen history: " + ("unchanged" if result.returncode == 0 else "FAILED"))
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
