"""Add configurable signing proxies.

Revision ID: 20260911_02
Revises: 20260911_01
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_02"
down_revision: str | None = "20260911_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "signing_proxies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("base_url", sa.String(length=1000), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("base_url"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_signing_proxies_active", "signing_proxies", ["active"])
    op.create_index(
        "ix_signing_proxies_created_by_user_id", "signing_proxies", ["created_by_user_id"]
    )
    op.add_column("signature_jobs", sa.Column("signing_proxy_id", sa.Uuid(), nullable=True))
    op.add_column(
        "signature_jobs", sa.Column("signing_proxy_name", sa.String(length=255), nullable=True)
    )
    with op.batch_alter_table("signature_jobs") as batch:
        batch.create_foreign_key(
            "fk_signature_jobs_signing_proxy_id",
            "signing_proxies",
            ["signing_proxy_id"],
            ["id"],
        )
    op.create_index("ix_signature_jobs_signing_proxy_id", "signature_jobs", ["signing_proxy_id"])


def downgrade() -> None:
    op.drop_index("ix_signature_jobs_signing_proxy_id", table_name="signature_jobs")
    with op.batch_alter_table("signature_jobs") as batch:
        batch.drop_constraint("fk_signature_jobs_signing_proxy_id", type_="foreignkey")
    op.drop_column("signature_jobs", "signing_proxy_name")
    op.drop_column("signature_jobs", "signing_proxy_id")
    op.drop_table("signing_proxies")
