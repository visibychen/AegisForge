import site
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require_conda() -> None:
    prefix = Path(sys.prefix)
    if prefix.name.casefold() != "aegisforge" or not (prefix / "conda-meta").is_dir():
        raise SystemExit("Use the Anaconda environment: conda run -n AegisForge python ...")
    if site.ENABLE_USER_SITE:
        raise SystemExit("User-site isolation is missing. Recreate or update environment.yml.")
