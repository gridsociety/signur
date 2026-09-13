import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from signur.database import Base


class UserRole(StrEnum):
    NO_ACCESS = "no_access"
    USER = "user"
    ADMIN = "admin"


class DocumentState(StrEnum):
    TO_SIGN = "to_sign"
    SIGNING_FAILED = "signing_failed"
    SIGNED = "signed"


class SignatureMode(StrEnum):
    GRAPHIC = "graphic"
    CADES = "cades"
    PADES = "pades"
    XADES = "xades"


class XadesPackaging(StrEnum):
    ENVELOPED = "enveloped"
    ENVELOPING = "enveloping"


class CadesStrategy(StrEnum):
    NEW = "new"
    NESTED = "nested"
    PARALLEL = "parallel"


class CertificateBackend(StrEnum):
    PKCS11_WEB_PROXY = "pkcs11_web_proxy"
    LOCAL = "local"


class SignatureJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class InputFormat(StrEnum):
    PDF = "pdf"
    XML = "xml"
    CMS_ATTACHED = "cms_attached"
    OPAQUE = "opaque"


class AnalysisStatus(StrEnum):
    PENDING = "pending"
    COMPLETE = "complete"
    INDETERMINATE = "indeterminate"


class PdfaStatus(StrEnum):
    PENDING = "pending"
    CONFORMANT = "conformant"
    NON_CONFORMANT = "non_conformant"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"


class BlobState(StrEnum):
    STORED = "stored"
    DELETED = "deleted"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("identity_authority", "external_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    identity_authority: Mapped[str] = mapped_column(String(512))
    external_id: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, native_enum=False), index=True)
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    user: Mapped[User] = relationship(foreign_keys=[user_id])
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class GraphicSignature(Base):
    __tablename__ = "graphic_signatures"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, index=True)
    current_version_number: Mapped[int] = mapped_column(Integer, default=1)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    created_by: Mapped[User] = relationship(foreign_keys=[created_by_user_id])
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    versions: Mapped[list["GraphicSignatureVersion"]] = relationship(
        back_populates="graphic_signature", cascade="all, delete-orphan"
    )


class GraphicSignatureVersion(Base):
    __tablename__ = "graphic_signature_versions"
    __table_args__ = (UniqueConstraint("graphic_signature_id", "version_number"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    graphic_signature_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("graphic_signatures.id"), index=True
    )
    graphic_signature: Mapped[GraphicSignature] = relationship(back_populates="versions")
    version_number: Mapped[int] = mapped_column(Integer)
    blob_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("blobs.id"), unique=True)
    blob: Mapped["Blob"] = relationship()
    sha256: Mapped[str] = mapped_column(String(64))
    width_pixels: Mapped[int] = mapped_column(Integer)
    height_pixels: Mapped[int] = mapped_column(Integer)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    created_by: Mapped[User] = relationship(foreign_keys=[created_by_user_id])
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SigningProxy(Base):
    __tablename__ = "signing_proxies"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    backend: Mapped[CertificateBackend] = mapped_column(
        Enum(CertificateBackend, native_enum=False), default=CertificateBackend.PKCS11_WEB_PROXY
    )
    base_url: Mapped[str | None] = mapped_column(String(1000), unique=True, nullable=True)
    pkcs11_library_path: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    pkcs11_token_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pkcs11_certificate_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    saved_pin_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_user_id])
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @property
    def pin_saved(self) -> bool:
        return self.saved_pin_ciphertext is not None


class BootstrapState(Base):
    __tablename__ = "bootstrap_state"
    __table_args__ = (CheckConstraint("id = 1", name="ck_bootstrap_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    initial_admin_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    initial_admin: Mapped[User | None] = relationship(foreign_keys=[initial_admin_user_id])


class Blob(Base):
    __tablename__ = "blobs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)
    kind: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[BlobState] = mapped_column(Enum(BlobState, native_enum=False))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    owner: Mapped[User] = relationship(foreign_keys=[owner_user_id])
    uploaded_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    uploaded_by: Mapped[User] = relationship(foreign_keys=[uploaded_by_user_id])
    original_name: Mapped[str] = mapped_column(String(512))
    input_format: Mapped[InputFormat] = mapped_column(Enum(InputFormat, native_enum=False))
    detected_media_type: Mapped[str] = mapped_column(String(255))
    original_blob_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("blobs.id"), unique=True)
    original_blob: Mapped[Blob] = relationship()
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[DocumentState] = mapped_column(
        Enum(DocumentState, native_enum=False), default=DocumentState.TO_SIGN, index=True
    )
    analysis_status: Mapped[AnalysisStatus] = mapped_column(Enum(AnalysisStatus, native_enum=False))
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    analysis_warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    pdfa_status: Mapped[PdfaStatus] = mapped_column(
        Enum(PdfaStatus, native_enum=False), default=PdfaStatus.NOT_APPLICABLE
    )
    pdfa_declared_part: Mapped[str | None] = mapped_column(String(8), nullable=True)
    pdfa_violations: Mapped[list[str]] = mapped_column(JSON, default=list)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    signature_jobs: Mapped[list["SignatureJob"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )
    signed_artifact: Mapped["SignedArtifact | None"] = relationship(
        back_populates="document", cascade="all, delete-orphan", uselist=False
    )

    @property
    def signature_mode(self) -> SignatureMode | None:
        return self.signed_artifact.job.mode if self.signed_artifact is not None else None


class SignatureJob(Base):
    __tablename__ = "signature_jobs"
    __table_args__ = (
        UniqueConstraint("document_id", "attempt_number"),
        Index("ix_signature_jobs_status_created", "status", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id"), index=True)
    document: Mapped[Document] = relationship(back_populates="signature_jobs")
    operator_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    operator: Mapped[User] = relationship()
    signing_proxy_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("signing_proxies.id"), nullable=True, index=True
    )
    signing_proxy: Mapped[SigningProxy | None] = relationship()
    signing_proxy_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attempt_number: Mapped[int] = mapped_column(Integer)
    mode: Mapped[SignatureMode] = mapped_column(Enum(SignatureMode, native_enum=False))
    cades_strategy: Mapped[CadesStrategy | None] = mapped_column(
        Enum(CadesStrategy, native_enum=False), nullable=True
    )
    xades_packaging: Mapped[XadesPackaging | None] = mapped_column(
        Enum(XadesPackaging, native_enum=False), nullable=True
    )
    status: Mapped[SignatureJobStatus] = mapped_column(
        Enum(SignatureJobStatus, native_enum=False), index=True
    )
    document_version: Mapped[int] = mapped_column(Integer)
    document_sha256: Mapped[str] = mapped_column(String(64))
    signing_identity_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signing_certificate_der: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    signing_display_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    signing_subject: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    signing_issuer: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    signing_key_bits: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signing_serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signing_not_valid_before: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    signing_not_valid_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    request_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    placements: Mapped[list["Placement"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )

    artifact: Mapped["SignedArtifact | None"] = relationship(
        back_populates="job", cascade="all, delete-orphan", uselist=False
    )


class SignedArtifact(Base):
    __tablename__ = "signed_artifacts"
    __table_args__ = (Index("ix_signed_artifacts_document_id", "document_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id"), unique=True)
    document: Mapped[Document] = relationship(back_populates="signed_artifact")
    signature_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("signature_jobs.id"), unique=True
    )
    job: Mapped[SignatureJob] = relationship(back_populates="artifact")
    blob_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("blobs.id"), unique=True)
    blob: Mapped[Blob] = relationship()
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    media_type: Mapped[str] = mapped_column(String(255))
    filename: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Placement(Base):
    __tablename__ = "placements"
    __table_args__ = (UniqueConstraint("signature_job_id", "layer_order"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    signature_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("signature_jobs.id"), index=True)
    job: Mapped[SignatureJob] = relationship(back_populates="placements")
    graphic_signature_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("graphic_signature_versions.id"), index=True
    )
    graphic_signature_version: Mapped[GraphicSignatureVersion] = relationship()
    page: Mapped[int] = mapped_column(Integer)
    x: Mapped[float] = mapped_column(Float)
    y: Mapped[float] = mapped_column(Float)
    width: Mapped[float] = mapped_column(Float)
    height: Mapped[float] = mapped_column(Float)
    layer_order: Mapped[int] = mapped_column(Integer)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


Index("ix_documents_owner_created", Document.owner_user_id, Document.created_at)
