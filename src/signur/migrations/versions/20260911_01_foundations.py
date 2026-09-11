"""Create identity, document, blob, and audit foundations.

Revision ID: 20260911_01
Revises:
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260911_01"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("identity_authority", sa.String(length=512), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column(
            "role",
            sa.Enum("NO_ACCESS", "USER", "ADMIN", name="userrole", native_enum=False),
            nullable=False,
        ),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("identity_authority", "external_id"),
    )
    op.create_index("ix_users_role", "users", ["role"])
    op.create_table(
        "bootstrap_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("completed", sa.Boolean(), nullable=False),
        sa.Column("initial_admin_user_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_bootstrap_singleton"),
        sa.ForeignKeyConstraint(["initial_admin_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        sa.table(
            "bootstrap_state",
            sa.column("id", sa.Integer()),
            sa.column("completed", sa.Boolean()),
        ),
        [{"id": 1, "completed": False}],
    )
    op.create_table(
        "blobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("storage_key", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "state",
            sa.Enum("STORED", "DELETED", name="blobstate", native_enum=False),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key"),
    )
    op.create_table(
        "documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_user_id", sa.Uuid(), nullable=False),
        sa.Column("original_name", sa.String(length=512), nullable=False),
        sa.Column(
            "input_format",
            sa.Enum("PDF", "XML", "CMS_ATTACHED", "OPAQUE", name="inputformat", native_enum=False),
            nullable=False,
        ),
        sa.Column("detected_media_type", sa.String(length=255), nullable=False),
        sa.Column("original_blob_id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "state",
            sa.Enum("TO_SIGN", "SIGNING_FAILED", "SIGNED", name="documentstate", native_enum=False),
            nullable=False,
        ),
        sa.Column(
            "analysis_status",
            sa.Enum(
                "PENDING", "COMPLETE", "INDETERMINATE", name="analysisstatus", native_enum=False
            ),
            nullable=False,
        ),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("analysis_warnings", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["original_blob_id"], ["blobs.id"]),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("original_blob_id"),
    )
    op.create_index("ix_documents_owner_created", "documents", ["owner_user_id", "created_at"])
    op.create_index("ix_documents_owner_user_id", "documents", ["owner_user_id"])
    op.create_index("ix_documents_state", "documents", ["state"])
    op.create_table(
        "graphic_signatures",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("current_version_number", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_graphic_signatures_active", "graphic_signatures", ["active"])
    op.create_index(
        "ix_graphic_signatures_created_by_user_id", "graphic_signatures", ["created_by_user_id"]
    )
    op.create_table(
        "graphic_signature_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("graphic_signature_id", sa.Uuid(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("blob_id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("width_pixels", sa.Integer(), nullable=False),
        sa.Column("height_pixels", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["blob_id"], ["blobs.id"]),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["graphic_signature_id"], ["graphic_signatures.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("blob_id"),
        sa.UniqueConstraint("graphic_signature_id", "version_number"),
    )
    op.create_index(
        "ix_graphic_signature_versions_created_by_user_id",
        "graphic_signature_versions",
        ["created_by_user_id"],
    )
    op.create_index(
        "ix_graphic_signature_versions_graphic_signature_id",
        "graphic_signature_versions",
        ["graphic_signature_id"],
    )
    op.create_table(
        "signature_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("operator_user_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column(
            "mode",
            sa.Enum("GRAPHIC", "CADES", "PADES", "XADES", name="signaturemode", native_enum=False),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "RUNNING",
                "COMPLETED",
                "FAILED",
                name="signaturejobstatus",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("document_version", sa.Integer(), nullable=False),
        sa.Column("document_sha256", sa.String(length=64), nullable=False),
        sa.Column("signing_identity_sha256", sa.String(length=64), nullable=True),
        sa.Column("signing_certificate_der", sa.LargeBinary(), nullable=True),
        sa.Column("signing_display_name", sa.String(length=512), nullable=True),
        sa.Column("signing_subject", sa.String(length=2048), nullable=True),
        sa.Column("signing_issuer", sa.String(length=2048), nullable=True),
        sa.Column("signing_serial_number", sa.String(length=128), nullable=True),
        sa.Column("signing_not_valid_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signing_not_valid_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"]),
        sa.ForeignKeyConstraint(["operator_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_id", "attempt_number"),
    )
    op.create_index("ix_signature_jobs_document_id", "signature_jobs", ["document_id"])
    op.create_index("ix_signature_jobs_operator_user_id", "signature_jobs", ["operator_user_id"])
    op.create_index("ix_signature_jobs_status", "signature_jobs", ["status"])
    op.create_index("ix_signature_jobs_status_created", "signature_jobs", ["status", "created_at"])
    op.create_table(
        "placements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("signature_job_id", sa.Uuid(), nullable=False),
        sa.Column("graphic_signature_version_id", sa.Uuid(), nullable=False),
        sa.Column("page", sa.Integer(), nullable=False),
        sa.Column("x", sa.Float(), nullable=False),
        sa.Column("y", sa.Float(), nullable=False),
        sa.Column("width", sa.Float(), nullable=False),
        sa.Column("height", sa.Float(), nullable=False),
        sa.Column("layer_order", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["graphic_signature_version_id"], ["graphic_signature_versions.id"]
        ),
        sa.ForeignKeyConstraint(["signature_job_id"], ["signature_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("signature_job_id", "layer_order"),
    )
    op.create_index(
        "ix_placements_graphic_signature_version_id",
        "placements",
        ["graphic_signature_version_id"],
    )
    op.create_index("ix_placements_signature_job_id", "placements", ["signature_job_id"])
    op.create_table(
        "signed_artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("signature_job_id", sa.Uuid(), nullable=False),
        sa.Column("blob_id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["blob_id"], ["blobs.id"]),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"]),
        sa.ForeignKeyConstraint(["signature_job_id"], ["signature_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("blob_id"),
        sa.UniqueConstraint("document_id"),
        sa.UniqueConstraint("signature_job_id"),
    )
    op.create_index("ix_signed_artifacts_document_id", "signed_artifacts", ["document_id"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index("ix_audit_events_entity_id", "audit_events", ["entity_id"])
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("signed_artifacts")
    op.drop_table("placements")
    op.drop_table("signature_jobs")
    op.drop_table("graphic_signature_versions")
    op.drop_table("graphic_signatures")
    op.drop_table("documents")
    op.drop_table("blobs")
    op.drop_table("bootstrap_state")
    op.drop_table("users")
