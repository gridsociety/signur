"""Record the PDF/A check performed on the uploaded document.

Revision ID: 20260911_08
Revises: 20260911_07
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_08"
down_revision: str | None = "20260911_07"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUSES = ("PENDING", "CONFORMANT", "NON_CONFORMANT", "INDETERMINATE", "NOT_APPLICABLE")


def upgrade() -> None:
    with op.batch_alter_table("documents") as batch:
        batch.add_column(
            sa.Column(
                "pdfa_status",
                sa.Enum(*STATUSES, name="pdfastatus", native_enum=False),
                nullable=False,
                server_default="not_applicable",
            )
        )
        batch.add_column(sa.Column("pdfa_declared_part", sa.String(length=8), nullable=True))
        batch.add_column(
            sa.Column("pdfa_violations", sa.JSON(), nullable=False, server_default="[]")
        )


def downgrade() -> None:
    with op.batch_alter_table("documents") as batch:
        batch.drop_column("pdfa_violations")
        batch.drop_column("pdfa_declared_part")
        batch.drop_column("pdfa_status")
