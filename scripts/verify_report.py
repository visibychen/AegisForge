"""Verify a bounded source-free JSON report checksum; does not execute or trust report content."""

import argparse
import sys

from _environment import ROOT, require_conda


def main():
    require_conda()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "backend"))
    from app.services.report_integrity import read_report

    try:
        read_report(args.report)
    except (OSError, ValueError, TypeError, RecursionError):
        print("Report verification failed.")
        return 1
    print("Report content checksum matches. This is not a signature or a model-quality verdict.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
