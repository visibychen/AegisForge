"""Durable repair jobs and independently recorded validation evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0005_repairs"
down_revision = "0004_receipts"
branch_labels = None
depends_on = None


def job_constraint(expression):
    # SQLite DROP TABLE during a batch rebuild can cascade-delete existing model_calls.
    # Disable FK enforcement outside a transaction, then rebuild atomically and restore it.
    with op.get_context().autocommit_block():
        op.execute("PRAGMA foreign_keys=OFF")
        op.execute("BEGIN IMMEDIATE")
        try:
            with op.batch_alter_table("jobs") as batch:
                batch.drop_constraint("ck_job_kind", type_="check")
                batch.create_check_constraint("ck_job_kind", expression)
            op.execute("COMMIT")
        except BaseException:
            op.execute("ROLLBACK")
            raise
        finally:
            op.execute("PRAGMA foreign_keys=ON")


def upgrade():
    job_constraint("kind IN ('scan','repair')")
    op.create_table(
        "repairs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scan_tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("artifacts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "job_id",
            sa.String(36),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column(
            "candidate_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="RESTRICT")
        ),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("anchor", sa.String(64), nullable=False),
        sa.Column("model_alias", sa.String(64), nullable=False),
        sa.Column("model_name", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(64)),
        sa.Column("edits_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("diff", sa.Text(), nullable=False, server_default=""),
        sa.Column("checks_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("dynamic_requested", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("dynamic_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
    )


def downgrade():
    # Refuse a destructive downgrade while repair jobs still exist.
    count = op.get_bind().scalar(sa.text("SELECT count(*) FROM jobs WHERE kind='repair'"))
    if count:
        raise RuntimeError("Cannot downgrade while repair jobs exist")
    op.drop_table("repairs")
    job_constraint("kind = 'scan'")
