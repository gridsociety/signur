"""Let an administrator order the certificates offered when signing.

Revision ID: 20260911_09
Revises: 20260911_08
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_09"
down_revision: str | None = "20260911_08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

proxies = sa.table(
    "signing_proxies",
    sa.column("id", sa.Uuid()),
    sa.column("name", sa.String()),
    sa.column("sort_order", sa.Integer()),
)


def upgrade() -> None:
    with op.batch_alter_table("signing_proxies") as batch:
        batch.add_column(sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_signing_proxies_sort_order", "signing_proxies", ["sort_order"])
    # Start from the alphabetical order the list had before this revision, so
    # nothing moves under the feet of whoever is signing today.
    connection = op.get_bind()
    existing = (
        connection.execute(sa.select(proxies.c.id).order_by(proxies.c.name, proxies.c.id))
        .scalars()
        .all()
    )
    for position, proxy_id in enumerate(existing):
        connection.execute(
            sa.update(proxies).where(proxies.c.id == proxy_id).values(sort_order=position)
        )


def downgrade() -> None:
    op.drop_index("ix_signing_proxies_sort_order", table_name="signing_proxies")
    with op.batch_alter_table("signing_proxies") as batch:
        batch.drop_column("sort_order")
