"""Detection results, call ledger and durable cancellation/lease fencing."""

import sqlalchemy as sa
from alembic import op

revision = "0002_detection"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "scan_tasks",
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_tasks", sa.Column("retries", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "scan_tasks", sa.Column("result_json", sa.Text(), nullable=False, server_default="{}")
    )
    op.add_column("jobs", sa.Column("lease_token", sa.String(36)))
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scan_tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "artifact_id",
            sa.String(36),
            sa.ForeignKey("artifacts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_table(
        "model_calls",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scan_tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "job_id", sa.String(36), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("input_chars", sa.Integer(), nullable=False),
        sa.Column("output_bytes", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer()),
        sa.Column("output_tokens", sa.Integer()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_model_calls_scan_id", "model_calls", ["scan_id"])


def downgrade():
    op.drop_table("model_calls")
    op.drop_table("findings")
    op.drop_column("jobs", "lease_token")
    op.drop_column("scan_tasks", "result_json")
    op.drop_column("scan_tasks", "retries")
    op.drop_column("scan_tasks", "cancel_requested")
