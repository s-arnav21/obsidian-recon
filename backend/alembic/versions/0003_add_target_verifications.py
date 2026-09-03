"""Add persisted exact-origin DNS ownership verification.

Revision ID: 0003_add_target_verifications
Revises: 0002_add_scan_failure_reason
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_add_target_verifications"
down_revision: Union[str, None] = "0002_add_scan_failure_reason"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "target_verifications",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("origin", sa.String(length=512), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("challenge_token", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_target_verifications"),
        sa.UniqueConstraint(
            "origin",
            name="uq_target_verifications_origin",
        ),
    )
    op.create_index(
        "ix_target_verifications_status",
        "target_verifications",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_target_verifications_status",
        table_name="target_verifications",
    )
    op.drop_table("target_verifications")
