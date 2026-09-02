"""Add sanitized failure context to persisted scans.

Revision ID: 0002_add_scan_failure_reason
Revises: 0001_initial_persistence_schema
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_add_scan_failure_reason"
down_revision: Union[str, None] = "0001_initial_persistence_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("failure_reason", sa.String(length=1024), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "failure_reason")
