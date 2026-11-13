import argparse
import asyncio

from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.core.database import build_engine
from app.worker.runner import run_once


async def main(once=False):
    settings = Settings()
    engine = build_engine(settings)
    try:
        while True:
            try:
                worked = await run_once(engine, settings)
            except OperationalError:
                # Storage still unavailable after bounded retries: back off, do not exit.
                worked = False
                await asyncio.sleep(2)
            if once:
                return
            if not worked:
                await asyncio.sleep(0.5)
    finally:
        engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisForge single worker (never executes inputs)")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(main(args.once))
    except KeyboardInterrupt:
        pass
