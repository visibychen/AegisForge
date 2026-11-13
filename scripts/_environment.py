import os
import site
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def model_environment():
    """Only model launchers import Windows user env; never hand credentials to Claude."""
    environment = os.environ.copy()
    if sys.platform == "win32":
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as registry:
            for name in (
                "AEGISFORGE_DEEPSEEK_API_KEY",
                "AEGISFORGE_MODEL_MODE",
                "AEGISFORGE_DEEPSEEK_MODEL",
            ):
                if name not in environment:
                    try:
                        environment[name] = winreg.QueryValueEx(registry, name)[0]
                    except FileNotFoundError:
                        pass
    return environment


def require_conda() -> None:
    prefix = Path(sys.prefix)
    if prefix.name.casefold() != "aegisforge" or not (prefix / "conda-meta").is_dir():
        raise SystemExit("Use the Anaconda environment: conda run -n AegisForge python ...")
    if site.ENABLE_USER_SITE:
        raise SystemExit("User-site isolation is missing. Recreate or update environment.yml.")
