import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from signur.models import (
    AnalysisStatus,
    CadesStrategy,
    CertificateBackend,
    DocumentState,
    InputFormat,
    SignatureJobStatus,
    SignatureMode,
    UserRole,
)


class UserView(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    username: str = Field(validation_alias="external_id", serialization_alias="username")
    display_name: str
    email: str | None
    role: UserRole
    first_seen_at: datetime
    last_seen_at: datetime


class MeView(UserView):
    access_granted: bool
    access_message: str | None = None
    password_set: bool = False


class AuthStatus(BaseModel):
    auth_mode: str
    authenticated: bool
    password_set: bool
    user: UserView | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(default="", max_length=1024)
    # Non-browser clients ask for a long-lived session and read the token back.
    persistent: bool = False


class LoginResult(UserView):
    session_token: str | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(default="", max_length=1024)
    new_password: str = Field(min_length=8, max_length=1024)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    email: str | None = Field(default=None, max_length=320)
    role: UserRole = UserRole.USER
    password: str = Field(min_length=8, max_length=1024)


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=255)
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    email: str | None = Field(default=None, max_length=320)


class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=8, max_length=1024)


class UserList(BaseModel):
    items: list[UserView]
    total: int
    limit: int
    offset: int


class GraphicSignatureVersionView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    graphic_signature_id: uuid.UUID
    version_number: int
    sha256: str
    width_pixels: int
    height_pixels: int
    created_by_user_id: uuid.UUID
    created_at: datetime


class GraphicSignatureView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    active: bool
    current_version_number: int
    created_by_user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    versions: list[GraphicSignatureVersionView]


class GraphicSignatureList(BaseModel):
    items: list[GraphicSignatureView]
    total: int


class GraphicSignatureUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    active: bool | None = None


class RoleUpdate(BaseModel):
    role: UserRole


class DocumentOwnerUpdate(BaseModel):
    owner_user_id: uuid.UUID


class DocumentView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_user_id: uuid.UUID
    uploaded_by_user_id: uuid.UUID
    original_name: str
    input_format: InputFormat
    detected_media_type: str
    sha256: str
    size_bytes: int
    state: DocumentState
    analysis_status: AnalysisStatus
    capabilities: list[str]
    analysis_warnings: list[str]
    version: int
    created_at: datetime
    completed_at: datetime | None
    signature_mode: SignatureMode | None = None


class DocumentDetail(DocumentView):
    owner: UserView
    uploaded_by: UserView


class DocumentList(BaseModel):
    items: list[DocumentDetail]
    total: int
    limit: int
    offset: int


class PlacementCreate(BaseModel):
    graphic_signature_version_id: uuid.UUID
    page: int = Field(ge=1)
    x: float = Field(ge=0, lt=1)
    y: float = Field(ge=0, lt=1)
    width: float = Field(gt=0, le=1)
    height: float = Field(gt=0, le=1)
    order: int = Field(ge=0)

    @model_validator(mode="after")
    def inside_page(self) -> "PlacementCreate":
        if self.x + self.width > 1 or self.y + self.height > 1:
            raise ValueError("Il posizionamento deve rientrare nella pagina.")
        return self


class PlacementView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    graphic_signature_version_id: uuid.UUID
    page: int
    x: float
    y: float
    width: float
    height: float
    layer_order: int


class SignatureCreate(BaseModel):
    mode: SignatureMode = SignatureMode.CADES
    cades_strategy: CadesStrategy | None = None
    placements: list[PlacementCreate] = Field(default_factory=list, max_length=100)
    signing_proxy_id: uuid.UUID | None = None
    pin: SecretStr | None = None

    @model_validator(mode="after")
    def compatible_placements(self) -> "SignatureCreate":
        if self.mode is SignatureMode.GRAPHIC and not self.placements:
            raise ValueError("La firma grafica richiede almeno un posizionamento.")
        if self.mode in {SignatureMode.CADES, SignatureMode.XADES} and self.placements:
            raise ValueError("Questa modalità non ammette posizionamenti grafici.")
        if self.cades_strategy is not None and self.mode is not SignatureMode.CADES:
            raise ValueError("La strategia CAdES è valida soltanto per la modalità CAdES.")
        if len({placement.order for placement in self.placements}) != len(self.placements):
            raise ValueError("L'ordine dei posizionamenti deve essere univoco.")
        return self


class SignatureJobView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    document_id: uuid.UUID
    operator_user_id: uuid.UUID
    signing_proxy_id: uuid.UUID | None
    signing_proxy_name: str | None
    attempt_number: int
    mode: SignatureMode
    cades_strategy: CadesStrategy | None
    status: SignatureJobStatus
    document_version: int
    document_sha256: str
    signing_identity_sha256: str | None
    signing_display_name: str | None
    signing_subject: str | None
    signing_issuer: str | None
    signing_serial_number: str | None
    signing_not_valid_before: datetime | None
    signing_not_valid_after: datetime | None
    error_code: str | None
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    placements: list[PlacementView] = Field(default_factory=list)


class SigningIdentityView(BaseModel):
    display_name: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    certificate_sha256: str
    digest_algorithm: str = "SHA-256"
    signature_algorithm: str = "RSASSA-PKCS1-v1_5"


class SigningProxyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    backend: CertificateBackend = CertificateBackend.PKCS11_WEB_PROXY
    base_url: str | None = Field(default=None, min_length=1, max_length=1000)
    pkcs11_library_path: str | None = Field(default=None, min_length=1, max_length=2000)
    pkcs11_token_label: str | None = Field(default=None, min_length=1, max_length=255)
    pkcs11_certificate_label: str | None = Field(default=None, min_length=1, max_length=255)
    pin: SecretStr | None = None
    save_pin: bool = False


class SigningProxyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: str | None = Field(default=None, min_length=1, max_length=1000)
    pkcs11_library_path: str | None = Field(default=None, min_length=1, max_length=2000)
    pkcs11_token_label: str | None = Field(default=None, min_length=1, max_length=255)
    pkcs11_certificate_label: str | None = Field(default=None, min_length=1, max_length=255)
    active: bool | None = None
    saved_pin_action: Literal["keep", "replace", "remove"] = "keep"
    pin: SecretStr | None = None


class SigningProxyAdminView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    backend: CertificateBackend
    base_url: str | None
    pkcs11_library_path: str | None
    pkcs11_token_label: str | None
    pkcs11_certificate_label: str | None
    pin_saved: bool
    active: bool
    version: int
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class SigningProxyPublicView(BaseModel):
    id: uuid.UUID
    name: str
    version: int
    backend: CertificateBackend
    requires_pin: bool
    available: bool
    identity: SigningIdentityView | None = None


class SigningProxyAdminList(BaseModel):
    items: list[SigningProxyAdminView]
    total: int


class SigningProxyPublicList(BaseModel):
    items: list[SigningProxyPublicView]
    total: int


class LocalPkcs11DiscoverRequest(BaseModel):
    library_path: str = Field(min_length=1, max_length=2000)


class LocalPkcs11CertificateView(BaseModel):
    token_label: str
    certificate_label: str
    identity: SigningIdentityView


class LocalPkcs11CertificateList(BaseModel):
    items: list[LocalPkcs11CertificateView]
    total: int


class KnownPkcs11LibrariesView(BaseModel):
    pin_encryption_enabled: bool = True
    items: list[str]


class LocalPkcs11LibraryStatusView(BaseModel):
    exists: bool


class HealthView(BaseModel):
    status: str = Field(examples=["ok"])
