"""Record how long the signing key was.

Revision ID: 20260911_10
Revises: 20260911_09
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_10"
down_revision: str | None = "20260911_09"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("signature_jobs") as batch:
        batch.add_column(sa.Column("signing_key_bits", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("signature_jobs") as batch:
        batch.drop_column("signing_key_bits")
