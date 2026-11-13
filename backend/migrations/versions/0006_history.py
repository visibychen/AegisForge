"""Logical history removal preserves model accounting and shared artifacts."""

import sqlalchemy as sa
from alembic import op

revision = "0006_history"
down_revision = "0005_repairs"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scan_tasks", sa.Column("deleted_at", sa.DateTime(), nullable=True))


def downgrade():
    # Dropping the column would silently bring removed history back. Refuse, like 0005 does.
    removed = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM scan_tasks WHERE deleted_at IS NOT NULL")
    )
    if removed:
        raise RuntimeError("Cannot downgrade while removed scan history exists")
    op.drop_column("scan_tasks", "deleted_at")
