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
    from app.validation.runner import docker_environment, sweep_orphans, validate_one

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--repair")
    args = parser.parse_args()
    settings = Settings()
    engine = build_engine(settings)
    try:
        # Only containers carrying this project's validation label are ever removed.
        try:
            removed = sweep_orphans(docker_environment())
            if removed:
                print(f"Removed {removed} orphaned validation container(s).", flush=True)
        except Exception:  # noqa: BLE001 - Docker may be absent; runs then report an error
            print("Docker is unavailable; orphan sweep skipped.", flush=True)
        while True:
            try:
                worked = validate_one(engine, settings, args.repair)
            except Exception:  # noqa: BLE001 - one bad request must not kill the runner
                print(
                    "Validation request failed; see the repair's dynamic record.",
                    flush=True,
                )
                worked = False
            if args.once or args.repair:
                return
            if not worked:
                time.sleep(1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
