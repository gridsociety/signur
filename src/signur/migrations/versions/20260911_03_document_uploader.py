"""Preserve document uploader separately from its current owner.

Revision ID: 20260911_03
Revises: 20260911_02
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_03"
down_revision: str | None = "20260911_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("documents", sa.Column("uploaded_by_user_id", sa.Uuid(), nullable=True))
    op.execute("UPDATE documents SET uploaded_by_user_id = owner_user_id")
    with op.batch_alter_table("documents") as batch:
        batch.alter_column("uploaded_by_user_id", existing_type=sa.Uuid(), nullable=False)
        batch.create_foreign_key(
            "fk_documents_uploaded_by_user_id",
            "users",
            ["uploaded_by_user_id"],
            ["id"],
        )
    op.create_index(
        "ix_documents_uploaded_by_user_id", "documents", ["uploaded_by_user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_documents_uploaded_by_user_id", table_name="documents")
    with op.batch_alter_table("documents") as batch:
        batch.drop_constraint("fk_documents_uploaded_by_user_id", type_="foreignkey")
    op.drop_column("documents", "uploaded_by_user_id")
