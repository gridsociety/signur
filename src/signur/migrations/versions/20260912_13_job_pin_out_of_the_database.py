"""Keep the PIN of a single signature out of the database entirely.

Revision ID: 20260912_13
Revises: 20260911_12
Create Date: 2026-09-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260912_13"
down_revision: str | None = "20260911_12"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The worker signs inside the server process, so the PIN typed for one
    # signature waits in memory instead. Dropping the column takes whatever is
    # still written in it away with it, which is the whole point; a signature
    # queued at the moment of the upgrade asks for its PIN again.
    with op.batch_alter_table("signature_jobs") as batch:
        batch.drop_column("signing_pin_ciphertext")


def downgrade() -> None:
    op.add_column(
        "signature_jobs", sa.Column("signing_pin_ciphertext", sa.LargeBinary(), nullable=True)
    )
