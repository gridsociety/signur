"""Persist the selected XAdES packaging.

Revision ID: 20260911_07
Revises: 20260911_06
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_07"
down_revision: str | None = "20260911_06"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("signature_jobs") as batch:
        batch.add_column(
            sa.Column(
                "xades_packaging",
                sa.Enum("ENVELOPED", "ENVELOPING", name="xadespackaging", native_enum=False),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("signature_jobs") as batch:
        batch.drop_column("xades_packaging")
