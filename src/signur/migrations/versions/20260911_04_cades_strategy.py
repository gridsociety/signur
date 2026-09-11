"""Persist the selected CAdES strategy.

Revision ID: 20260911_04
Revises: 20260911_03
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_04"
down_revision: str | None = "20260911_03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "signature_jobs",
        sa.Column(
            "cades_strategy",
            sa.Enum("NEW", "NESTED", "PARALLEL", name="cadesstrategy", native_enum=False),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("signature_jobs", "cades_strategy")
