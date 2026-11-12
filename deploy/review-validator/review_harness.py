"""Trusted additive test profile; reuses the original process and result-channel isolation."""

import sys

sys.path.insert(0, "/opt/validator")
import harness  # noqa: E402
from review_cases import EXTRA_TESTS, run_extra  # noqa: E402


def main():
    original = harness.run_case
    for case, names in EXTRA_TESTS.items():
        harness.TESTS[case] = [*harness.TESTS[case], *names]

    def reviewed(case, ready, browser, results):
        original(case, ready, browser, results)
        if ready:
            run_extra(case, browser, results)
        return results

    harness.run_case = reviewed
    return harness.main()


if __name__ == "__main__":
    raise SystemExit(main())
