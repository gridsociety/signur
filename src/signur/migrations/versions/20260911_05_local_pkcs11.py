"""Add local PKCS11 certificate configurations.

Revision ID: 20260911_05
Revises: 20260911_04
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_05"
down_revision: str | None = "20260911_04"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "signing_proxies",
        sa.Column(
            "backend",
            sa.Enum(
                "PKCS11_WEB_PROXY",
                "LOCAL",
                name="certificatebackend",
                native_enum=False,
            ),
            server_default="PKCS11_WEB_PROXY",
            nullable=True,
        ),
    )
    # Preserve every configuration created before local middleware support as a
    # PKCS11 Web Proxy, independently of database-specific DEFAULT behaviour.
    op.execute(
        sa.text("UPDATE signing_proxies SET backend = 'PKCS11_WEB_PROXY' WHERE backend IS NULL")
    )
    with op.batch_alter_table("signing_proxies") as batch:
        batch.alter_column(
            "backend",
            existing_type=sa.Enum(
                "PKCS11_WEB_PROXY",
                "LOCAL",
                name="certificatebackend",
                native_enum=False,
            ),
            nullable=False,
            server_default="PKCS11_WEB_PROXY",
        )
        batch.alter_column("base_url", existing_type=sa.String(1000), nullable=True)
    op.add_column(
        "signing_proxies", sa.Column("pkcs11_library_path", sa.String(2000), nullable=True)
    )
    op.add_column("signing_proxies", sa.Column("pkcs11_token_label", sa.String(255), nullable=True))
    op.add_column(
        "signing_proxies", sa.Column("pkcs11_certificate_label", sa.String(255), nullable=True)
    )
    op.add_column(
        "signing_proxies", sa.Column("saved_pin_ciphertext", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "signature_jobs", sa.Column("signing_pin_ciphertext", sa.LargeBinary(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("signature_jobs", "signing_pin_ciphertext")
    op.drop_column("signing_proxies", "saved_pin_ciphertext")
    op.drop_column("signing_proxies", "pkcs11_certificate_label")
    op.drop_column("signing_proxies", "pkcs11_token_label")
    op.drop_column("signing_proxies", "pkcs11_library_path")
    with op.batch_alter_table("signing_proxies") as batch:
        batch.alter_column("base_url", existing_type=sa.String(1000), nullable=False)
    op.drop_column("signing_proxies", "backend")
