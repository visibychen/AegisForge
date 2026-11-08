"""Trusted Compose runner: discovers only its own data mount, never accepts host paths via API."""

import json
import os
import socket
import subprocess
import time

from app.core.config import Settings
from app.core.database import build_engine
from app.validation.runner import docker_environment, sweep_orphans, validate_one


def main():
    # Compose's default hostname is the controller's container ID. Docker is controller-only.
    inspected = subprocess.run(
        ["docker", "inspect", socket.gethostname()],
        capture_output=True,
        env=docker_environment(),
        timeout=10,
        check=True,
    )
    mounts = json.loads(inspected.stdout)[0]["Mounts"]
    sources = [
        m["Source"] for m in mounts if m["Destination"] == "/srv/data" and m["Type"] == "bind"
    ]
    if len(sources) != 1:
        raise SystemExit("Trusted controller requires exactly one data bind mount.")
    os.environ["AEGISFORGE_VALIDATOR_HOST_DATA_DIR"] = sources[0]
    engine = build_engine(Settings())
    try:
        sweep_orphans()
        while True:
            try:
                worked = validate_one(engine, Settings())
            except Exception:  # noqa: BLE001 - fixed log; no source or credentials
                print("Validation request could not be processed.", flush=True)
                worked = False
            if not worked:
                time.sleep(1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
