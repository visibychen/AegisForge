from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGISFORGE_", env_file=REPO_ROOT / ".env", extra="ignore"
    )

    api_token: SecretStr = SecretStr("")
    data_dir: Path = REPO_ROOT / "data"
    database_url: str | None = None
    allowed_origins: list[str] = ["http://127.0.0.1:5173", "http://localhost:5173"]
    model_mode: Literal["fake"] = "fake"
    max_file_bytes: int = Field(default=2 * 1024 * 1024, gt=0)
    max_files: int = Field(default=10, gt=0, le=10)
    max_total_bytes: int = Field(default=10 * 1024 * 1024, gt=0)

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite+pysqlite:///{self.data_dir.resolve().as_posix()}/aegisforge.db"
