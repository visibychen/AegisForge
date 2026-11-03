from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url

from app.core.config import Settings


def build_engine(settings: Settings) -> Engine:
    url = make_url(settings.resolved_database_url)
    if url.get_backend_name() != "sqlite":
        raise ValueError("M1 only supports SQLite databases")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 5})

    @event.listens_for(engine, "connect")
    def configure_sqlite(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    return engine
