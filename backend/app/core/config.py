import os
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
    model_mode: Literal["fake", "real"] = "fake"
    deepseek_model: Literal["deepseek-flash", "deepseek-v4-pro"] = "deepseek-flash"
    model_timeout_seconds: float = Field(default=60, gt=0, le=120)
    model_response_bytes: int = Field(default=131072, ge=4096, le=262144)
    model_output_tokens: int = Field(default=4096, ge=256, le=4096)
    max_model_calls: int = Field(default=32, ge=1, le=32)
    # Server-wide external call COUNT per UTC day (not a currency limit).
    daily_model_calls: int = Field(default=64, ge=1, le=10_000)
    queue_limit: int = Field(default=10, ge=1, le=10)
    lease_seconds: int = Field(default=60, ge=10, le=300)
    max_file_bytes: int = Field(default=2 * 1024 * 1024, gt=0)
    max_files: int = Field(default=10, gt=0, le=10)
    max_total_bytes: int = Field(default=10 * 1024 * 1024, gt=0)

    @property
    def deepseek_api_key(self) -> SecretStr:
        # Intentionally NOT a BaseSettings field: .env cannot supply this credential.
        return SecretStr(os.environ.get("AEGISFORGE_DEEPSEEK_API_KEY", ""))

    @property
    def model_aliases(self) -> list[str]:
        aliases = ["fake"]
        if self.model_mode == "real" and self.deepseek_api_key.get_secret_value():
            aliases.append("deepseek")
        return aliases

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite+pysqlite:///{self.data_dir.resolve().as_posix()}/aegisforge.db"
