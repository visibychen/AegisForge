"""Trusted fixed development-case runner. API and model workers never import Docker."""

import argparse
import sys
import time

from _environment import ROOT, require_conda


def main():
    require_conda()
    sys.path.insert(0, str(ROOT / "backend"))
    from app.core.config import Settings
    from app.core.database import build_engine
    from app.validation.runner import validate_one

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--repair")
    args = parser.parse_args()
    settings = Settings()
    engine = build_engine(settings)
    try:
        while True:
            worked = validate_one(engine, settings, args.repair)
            if args.once or args.repair:
                return
            if not worked:
                time.sleep(1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
