"""Attempt history, stable finding order and content-free model failure categories."""

import sqlalchemy as sa
from alembic import op

revision = "0003_attempts"
down_revision = "0002_detection"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "scan_tasks", sa.Column("attempts_json", sa.Text(), nullable=False, server_default="[]")
    )
    op.add_column(
        "findings", sa.Column("attempt", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "findings", sa.Column("position", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("model_calls", sa.Column("failure_category", sa.String(32)))


def downgrade():
    op.drop_column("model_calls", "failure_category")
    op.drop_column("findings", "position")
    op.drop_column("findings", "attempt")
    op.drop_column("scan_tasks", "attempts_json")
