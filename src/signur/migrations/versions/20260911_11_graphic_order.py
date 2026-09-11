"""Let an administrator order the graphic signatures offered when signing.

Revision ID: 20260911_11
Revises: 20260911_10
Create Date: 2026-09-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_11"
down_revision: str | None = "20260911_10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

graphics = sa.table(
    "graphic_signatures",
    sa.column("id", sa.Uuid()),
    sa.column("name", sa.String()),
    sa.column("sort_order", sa.Integer()),
)


def upgrade() -> None:
    with op.batch_alter_table("graphic_signatures") as batch:
        batch.add_column(sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_graphic_signatures_sort_order", "graphic_signatures", ["sort_order"])
    # Keep the alphabetical order the catalogue had until now, so nobody finds a
    # different default the next time they sign.
    connection = op.get_bind()
    existing = (
        connection.execute(sa.select(graphics.c.id).order_by(graphics.c.name, graphics.c.id))
        .scalars()
        .all()
    )
    for position, graphic_id in enumerate(existing):
        connection.execute(
            sa.update(graphics).where(graphics.c.id == graphic_id).values(sort_order=position)
        )


def downgrade() -> None:
    op.drop_index("ix_graphic_signatures_sort_order", table_name="graphic_signatures")
    with op.batch_alter_table("graphic_signatures") as batch:
        batch.drop_column("sort_order")
