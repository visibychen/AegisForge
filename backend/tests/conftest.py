from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from app.core.config import Settings
from app.core.database import build_engine
from app.main import create_app
from fastapi.testclient import TestClient
from pydantic import SecretStr


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(
        "AEGISFORGE_DATABASE_URL", f"sqlite+pysqlite:///{tmp_path.as_posix()}/test.db"
    )
    command.upgrade(Config(str(Path(__file__).resolve().parents[1] / "alembic.ini")), "head")
    settings = Settings(_env_file=None, api_token=SecretStr("test-token"))
    app = create_app(settings)
    app.state.engine = build_engine(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers["Authorization"] = "Bearer test-token"
        yield client
    app.state.engine.dispose()
