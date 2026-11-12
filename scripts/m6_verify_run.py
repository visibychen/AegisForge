"""Recompute diagnostic record integrity only; a valid exposed-case result is not acceptance."""

import argparse
import json
import sys

from _environment import ROOT, require_conda


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from evaluation.targeted import verify_run

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=lambda p: ROOT / p)
    args = parser.parse_args()
    result = verify_run(args.run)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["integrity_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
