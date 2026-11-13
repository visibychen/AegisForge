"""Analysis receipts and a deadline anchored across lease recovery."""

import sqlalchemy as sa
from alembic import op

revision = "0004_receipts"
down_revision = "0003_attempts"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "scan_tasks", sa.Column("plan_json", sa.Text(), nullable=False, server_default="{}")
    )
    op.add_column("scan_tasks", sa.Column("attempt_started_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("scan_tasks", "attempt_started_at")
    op.drop_column("scan_tasks", "plan_json")
