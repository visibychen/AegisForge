"""Persist artifacts, scans, associations and durable job metadata."""

import sqlalchemy as sa
from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("input_type", sa.String(16), nullable=False),
        sa.Column("language", sa.String(32)),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("storage_key", sa.String(128), nullable=False, unique=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("input_type IN ('source','http')", name="ck_artifact_input_type"),
        sa.CheckConstraint("size_bytes > 0", name="ck_artifact_size"),
    )
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])
    op.create_table(
        "scan_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("strategy", sa.String(16), nullable=False),
        sa.Column("model_alias", sa.String(64), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("prompt_version", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime()),
        sa.CheckConstraint(
            "status IN ('queued','running','completed','partial','failed','cancelled')",
            name="ck_scan_status",
        ),
        sa.CheckConstraint("strategy IN ('rules','llm','hybrid')", name="ck_scan_strategy"),
    )
    op.create_index("ix_scan_tasks_status", "scan_tasks", ["status"])
    op.create_table(
        "task_artifacts",
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scan_tasks.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "artifact_id",
            sa.String(36),
            sa.ForeignKey("artifacts.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scan_tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("lease_until", sa.DateTime()),
        sa.Column("heartbeat_at", sa.DateTime()),
        sa.Column("error_code", sa.String(64)),
        sa.Column("error_detail", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("kind = 'scan'", name="ck_job_kind"),
        sa.CheckConstraint(
            "status IN ('queued','running','completed','failed','cancelled')", name="ck_job_status"
        ),
        sa.CheckConstraint("attempts >= 0", name="ck_job_attempts"),
    )
    op.create_index("ix_jobs_status", "jobs", ["status"])


def downgrade():
    op.drop_table("jobs")
    op.drop_table("task_artifacts")
    op.drop_table("scan_tasks")
    op.drop_table("artifacts")
