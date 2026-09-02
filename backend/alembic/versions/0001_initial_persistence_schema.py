"""Initial unified recon and validation persistence schema.

Revision ID: 0001_initial_persistence_schema
Revises: None
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0001_initial_persistence_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("authorized", sa.Boolean(), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("scan_id", sa.String(length=128), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("base_url", sa.String(length=2048), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_assets_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
    )
    op.create_index("ix_assets_scan_id", "assets", ["scan_id"])
    op.create_table(
        "services",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("scan_id", sa.String(length=128), nullable=False),
        sa.Column("asset_id", sa.String(length=128), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=True),
        sa.Column("service_name", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=255), nullable=True),
        sa.Column("state", sa.String(length=64), nullable=True),
        sa.Column("source", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="fk_services_asset_id_assets", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_services_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_services"),
    )
    op.create_index("ix_services_asset_id", "services", ["asset_id"])
    op.create_index("ix_services_scan_id", "services", ["scan_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("scan_id", sa.String(length=128), nullable=False),
        sa.Column("asset_id", sa.String(length=128), nullable=True),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("scanner_template_id", sa.String(length=255), nullable=True),
        sa.Column("validator_id", sa.String(length=255), nullable=True),
        sa.Column("vulnerability_type", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=64), nullable=True),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("endpoint", sa.String(length=2048), nullable=True),
        sa.Column("http_method", sa.String(length=16), nullable=True),
        sa.Column("parameter_name", sa.String(length=255), nullable=True),
        sa.Column("parameter_location", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="fk_findings_asset_id_assets", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_findings_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_table(
        "validations",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("validator_id", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("decision_reason", sa.String(length=1024), nullable=True),
        sa.Column(
            "validated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="fk_validations_finding_id_findings", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_validations"),
    )
    op.create_index("ix_validations_finding_id", "validations", ["finding_id"])
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("validation_id", sa.String(length=128), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("evidence_type", sa.String(length=128), nullable=True),
        sa.Column("evidence_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="fk_evidence_finding_id_findings", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["validation_id"], ["validations.id"], name="fk_evidence_validation_id_validations", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence"),
    )
    op.create_index("ix_evidence_finding_id", "evidence", ["finding_id"])
    op.create_index("ix_evidence_validation_id", "evidence", ["validation_id"])
    op.create_table(
        "mitre_mappings",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("technique_id", sa.String(length=64), nullable=False),
        sa.Column("technique_name", sa.String(length=255), nullable=False),
        sa.Column("tactic", sa.String(length=255), nullable=False),
        sa.Column("mapping_confidence", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="fk_mitre_mappings_finding_id_findings", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_mitre_mappings"),
    )
    op.create_index("ix_mitre_mappings_finding_id", "mitre_mappings", ["finding_id"])
    op.create_table(
        "attack_chains",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("scan_id", sa.String(length=128), nullable=False),
        sa.Column("asset_id", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="fk_attack_chains_asset_id_assets", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_attack_chains_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_attack_chains"),
    )
    op.create_index("ix_attack_chains_asset_id", "attack_chains", ["asset_id"])
    op.create_index("ix_attack_chains_scan_id", "attack_chains", ["scan_id"])
    op.create_table(
        "attack_chain_steps",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("chain_id", sa.String(length=128), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=True),
        sa.Column("technique_id", sa.String(length=64), nullable=True),
        sa.Column("capability", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["chain_id"], ["attack_chains.id"], name="fk_attack_chain_steps_chain_id_attack_chains", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="fk_attack_chain_steps_finding_id_findings", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_attack_chain_steps"),
        sa.UniqueConstraint("chain_id", "step_number", name="uq_attack_chain_steps_order"),
    )
    op.create_index("ix_attack_chain_steps_chain_id", "attack_chain_steps", ["chain_id"])
    op.create_index("ix_attack_chain_steps_finding_id", "attack_chain_steps", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_attack_chain_steps_finding_id", table_name="attack_chain_steps")
    op.drop_index("ix_attack_chain_steps_chain_id", table_name="attack_chain_steps")
    op.drop_table("attack_chain_steps")
    op.drop_index("ix_attack_chains_scan_id", table_name="attack_chains")
    op.drop_index("ix_attack_chains_asset_id", table_name="attack_chains")
    op.drop_table("attack_chains")
    op.drop_index("ix_mitre_mappings_finding_id", table_name="mitre_mappings")
    op.drop_table("mitre_mappings")
    op.drop_index("ix_evidence_validation_id", table_name="evidence")
    op.drop_index("ix_evidence_finding_id", table_name="evidence")
    op.drop_table("evidence")
    op.drop_index("ix_validations_finding_id", table_name="validations")
    op.drop_table("validations")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_services_scan_id", table_name="services")
    op.drop_index("ix_services_asset_id", table_name="services")
    op.drop_table("services")
    op.drop_index("ix_assets_scan_id", table_name="assets")
    op.drop_table("assets")
    op.drop_table("scans")
