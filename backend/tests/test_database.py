from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from app.core.config import Settings
from app.core.database import build_engine
from app.models import Artifact, Base, Job, ScanTask, TaskArtifact
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(
        "AEGISFORGE_DATABASE_URL", f"sqlite+pysqlite:///{tmp_path.as_posix()}/test.db"
    )
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    engine = build_engine(Settings())
    yield engine, config
    engine.dispose()


def test_migrations_roundtrip_and_metadata_match(database):
    engine, config = database
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    command.upgrade(config, "head")
    assert {"artifacts", "scan_tasks", "task_artifacts", "jobs"} <= set(
        inspect(engine).get_table_names()
    )


def test_task_relations_survive_reconnect_and_enforce_deletion_rules(database):
    engine, _ = database
    with Session(engine) as session:
        artifact = Artifact(
            input_type="source",
            language="python",
            display_name="example.py",
            storage_key="random-id",
            sha256="a" * 64,
            size_bytes=20,
        )
        scan = ScanTask()
        session.add_all([artifact, scan])
        session.commit()
        artifact_id, scan_id = artifact.id, scan.id
        session.add_all(
            [
                TaskArtifact(scan_id=scan_id, artifact_id=artifact_id),
                Job(scan_id=scan_id, idempotency_key="scan-once"),
            ]
        )
        session.commit()
    engine.dispose()
    with Session(engine) as session:
        scan = session.get(ScanTask, scan_id)
        assert scan.status == "queued"
        assert scan.created_at.utcoffset().total_seconds() == 0
        session.delete(session.get(Artifact, artifact_id))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.delete(session.get(ScanTask, scan_id))
        session.commit()
        assert session.scalars(select(Job)).all() == []
        assert session.scalars(select(TaskArtifact)).all() == []
        assert session.get(Artifact, artifact_id) is not None


def test_invalid_scan_status_cannot_be_persisted(database):
    engine, _ = database
    with Session(engine) as session:
        session.add(ScanTask(status="made-up-success"))
        with pytest.raises(IntegrityError):
            session.commit()
