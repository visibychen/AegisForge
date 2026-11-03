from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def new_id() -> str:
    return str(uuid4())


class UTCDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, _dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Timestamps must include a timezone")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value, _dialect):
        return value.replace(tzinfo=UTC) if value is not None else None


class Base(DeclarativeBase):
    pass


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint("input_type IN ('source','http')", name="ck_artifact_input_type"),
        CheckConstraint("size_bytes > 0", name="ck_artifact_size"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    input_type: Mapped[str] = mapped_column(String(16))
    language: Mapped[str | None] = mapped_column(String(32))
    display_name: Mapped[str] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(128), unique=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=lambda: datetime.now(UTC))


class ScanTask(Base):
    __tablename__ = "scan_tasks"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','completed','partial','failed','cancelled')",
            name="ck_scan_status",
        ),
        CheckConstraint("strategy IN ('rules','llm','hybrid')", name="ck_scan_strategy"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    strategy: Mapped[str] = mapped_column(String(16), default="hybrid")
    model_alias: Mapped[str] = mapped_column(String(64), default="fake")
    rule_version: Mapped[str] = mapped_column(String(32), default="not-implemented")
    prompt_version: Mapped[str] = mapped_column(String(32), default="not-implemented")
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=lambda: datetime.now(UTC))
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class TaskArtifact(Base):
    __tablename__ = "task_artifacts"

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scan_tasks.id", ondelete="CASCADE"), primary_key=True
    )
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), primary_key=True
    )


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("kind = 'scan'", name="ck_job_kind"),
        CheckConstraint(
            "status IN ('queued','running','completed','failed','cancelled')", name="ck_job_status"
        ),
        CheckConstraint("attempts >= 0", name="ck_job_attempts"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16), default="scan")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    lease_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=lambda: datetime.now(UTC))
