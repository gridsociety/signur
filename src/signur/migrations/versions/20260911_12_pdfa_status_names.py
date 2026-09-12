"""Store the PDF/A status as the enum member name, like every other column.

Revision ID: 20260911_12
Revises: 20260911_11
Create Date: 2026-09-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_12"
down_revision: str | None = "20260911_11"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUSES = ("PENDING", "CONFORMANT", "NON_CONFORMANT", "INDETERMINATE", "NOT_APPLICABLE")
STATUS_TYPE = sa.Enum(*STATUSES, name="pdfastatus", native_enum=False)

documents = sa.table("documents", sa.column("pdfa_status", sa.String()))


def upgrade() -> None:
    # Revision 08 added the column defaulting to the member value,
    # "not_applicable", while the model writes and reads the member name. Every
    # document that already existed came back unreadable and the listing
    # answered 500, so the rows that default wrote are named properly here.
    op.execute(
        documents.update()
        .where(documents.c.pdfa_status.in_([status.lower() for status in STATUSES]))
        .values(pdfa_status=sa.func.upper(documents.c.pdfa_status))
    )
    with op.batch_alter_table("documents") as batch:
        batch.alter_column(
            "pdfa_status",
            existing_type=STATUS_TYPE,
            existing_nullable=False,
            server_default="NOT_APPLICABLE",
        )


def downgrade() -> None:
    with op.batch_alter_table("documents") as batch:
        batch.alter_column(
            "pdfa_status",
            existing_type=STATUS_TYPE,
            existing_nullable=False,
            server_default="not_applicable",
        )
