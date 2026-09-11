import hashlib
import io
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID
from PIL import Image
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from signur.cades import verify_cades_b_b
from signur.config import Settings
from signur.database import Base
from signur.errors import ApiError
from signur.models import (
    AnalysisStatus,
    Blob,
    BlobState,
    CertificateBackend,
    Document,
    DocumentState,
    GraphicSignature,
    GraphicSignatureVersion,
    InputFormat,
    SignatureJob,
    SignatureJobStatus,
    SignatureMode,
    SignedArtifact,
    SigningProxy,
    User,
    UserRole,
)
from signur.secret_box import seal_pin
from signur.signature_service import (
    PlacementSpec,
    claim_next_signature,
    enqueue_signature,
    process_claimed_signature,
)
from signur.signing_proxy import ProxySigningError, SigningIdentity
from signur.storage import LocalBlobStorage


class FakeSigningClient:
    def __init__(self, *, fail: bool = False) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mario Firmatario")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(self.key, hashes.SHA256())
        )
        certificate_der = certificate.public_bytes(serialization.Encoding.DER)
        self.identity = SigningIdentity(
            certificate_der=certificate_der,
            certificate_sha256=hashlib.sha256(certificate_der).hexdigest(),
            certificate=certificate,
            signature_length=256,
        )
        self.fail = fail

    def get_identity(self) -> SigningIdentity:
        return self.identity

    def sign_digest(self, digest: bytes, _expected: SigningIdentity) -> bytes:
        if self.fail:
            raise ProxySigningError("synthetic proxy failure")
        return self.key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


def _setup(tmp_path: Path) -> tuple[sessionmaker[Session], Settings, uuid.UUID, uuid.UUID, bytes]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(
        environment="test",
        storage_root=tmp_path / "blobs",
        pin_encryption_key="test-pin-encryption-key-with-at-least-32-characters",
    )
    storage = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes)
    original = b"documento da firmare\x00"
    stored = storage.store_bytes(original)
    user_id = uuid.uuid4()
    document_id = uuid.uuid4()
    with factory.begin() as session:
        user = User(
            id=user_id,
            identity_authority="https://auth.test/",
            external_id="operator",
            display_name="Operator",
            role=UserRole.USER,
        )
        blob = Blob(
            storage_key=stored.key,
            kind="original",
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            state=BlobState.STORED,
        )
        session.add_all(
            [
                user,
                Document(
                    id=document_id,
                    owner=user,
                    uploaded_by=user,
                    original_name="documento.bin",
                    input_format=InputFormat.OPAQUE,
                    detected_media_type="application/octet-stream",
                    original_blob=blob,
                    sha256=stored.sha256,
                    size_bytes=stored.size_bytes,
                    state=DocumentState.TO_SIGN,
                    analysis_status=AnalysisStatus.COMPLETE,
                    capabilities=["cades"],
                    analysis_warnings=[],
                ),
            ]
        )
    return factory, settings, user_id, document_id, original


def _enqueue(
    factory: sessionmaker[Session], user_id: uuid.UUID, document_id: uuid.UUID
) -> SignatureJob:
    with factory() as session:
        user = session.get_one(User, user_id)
        document = session.get_one(Document, document_id)
        return enqueue_signature(
            session,
            document=document,
            operator=user,
            mode=SignatureMode.CADES,
            request_id=str(uuid.uuid4()),
        )


def test_cades_job_persists_verified_artifact_and_signer_snapshot(tmp_path: Path):
    factory, settings, user_id, document_id, original = _setup(tmp_path)
    job = _enqueue(factory, user_id, document_id)

    with factory() as session:
        document = session.get_one(Document, document_id)
        user = session.get_one(User, user_id)
        try:
            enqueue_signature(
                session,
                document=document,
                operator=user,
                mode=SignatureMode.CADES,
                request_id=str(uuid.uuid4()),
            )
        except ApiError as exc:
            assert exc.code == "signature_in_progress"
        else:
            raise AssertionError("a second active job was accepted")

    with factory() as session:
        assert claim_next_signature(session) == job.id
    with factory() as session:
        assert process_claimed_signature(session, settings, job.id, FakeSigningClient()) is True

    with factory() as session:
        document = session.get_one(Document, document_id)
        completed = session.get_one(SignatureJob, job.id)
        artifact = session.scalar(
            select(SignedArtifact).where(SignedArtifact.document_id == document_id)
        )
        assert document.state is DocumentState.SIGNED
        assert document.signature_mode is SignatureMode.CADES
        assert completed.status is SignatureJobStatus.COMPLETED
        assert completed.signing_display_name == "Mario Firmatario"
        assert completed.signing_certificate_der
        assert artifact is not None
        result = (
            LocalBlobStorage(settings.storage_root, settings.max_upload_bytes)
            .path_for(artifact.blob.storage_key)
            .read_bytes()
        )
    verify_cades_b_b(result, original)


def test_any_signing_failure_is_retryable(tmp_path: Path):
    factory, settings, user_id, document_id, _original = _setup(tmp_path)
    first = _enqueue(factory, user_id, document_id)
    with factory() as session:
        assert claim_next_signature(session) == first.id
    with factory() as session:
        assert (
            process_claimed_signature(session, settings, first.id, FakeSigningClient(fail=True))
            is False
        )

    with factory() as session:
        document = session.get_one(Document, document_id)
        failed = session.get_one(SignatureJob, first.id)
        assert document.state is DocumentState.SIGNING_FAILED
        assert failed.status is SignatureJobStatus.FAILED
        assert failed.error_code == "proxy_signing_failed"

    second = _enqueue(factory, user_id, document_id)
    assert second.attempt_number == 2
    assert second.status is SignatureJobStatus.QUEUED


def test_local_pkcs11_job_decrypts_pin_and_clears_ephemeral_copy(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    factory, settings, user_id, document_id, _original = _setup(tmp_path)
    captured: dict[str, str | None] = {}

    class FakeLocalSigningClient(FakeSigningClient):
        def __init__(
            self, library_path: str, token_label: str, certificate_label: str, pin: str | None
        ) -> None:
            super().__init__()
            captured.update(
                library_path=library_path,
                token_label=token_label,
                certificate_label=certificate_label,
                pin=pin,
            )

        def close(self) -> None:
            captured["closed"] = "yes"

    monkeypatch.setattr("signur.signature_service.LocalPkcs11SigningClient", FakeLocalSigningClient)
    with factory() as session:
        user = session.get_one(User, user_id)
        document = session.get_one(Document, document_id)
        certificate = SigningProxy(
            name="Carta locale",
            backend=CertificateBackend.LOCAL,
            base_url=None,
            pkcs11_library_path="/middleware/pkcs11.so",
            pkcs11_token_label="Token stabile",
            pkcs11_certificate_label="Certificato firma",
            active=True,
            version=1,
            created_by=user,
        )
        job = enqueue_signature(
            session,
            document=document,
            operator=user,
            mode=SignatureMode.CADES,
            request_id=str(uuid.uuid4()),
            signing_proxy=certificate,
            signing_pin_ciphertext=seal_pin("654321", settings.pin_encryption_key),
        )
        job_id = job.id

    with factory() as session:
        assert claim_next_signature(session) == job_id
    with factory() as session:
        assert process_claimed_signature(session, settings, job_id) is True
    with factory() as session:
        completed = session.get_one(SignatureJob, job_id)
        assert completed.signing_pin_ciphertext is None
    assert captured == {
        "library_path": "/middleware/pkcs11.so",
        "token_label": "Token stabile",
        "certificate_label": "Certificato firma",
        "pin": "654321",
        "closed": "yes",
    }


def test_graphic_job_produces_pdf_without_using_signing_proxy(tmp_path: Path) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(environment="test", storage_root=tmp_path / "blobs")
    storage = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes)

    pdf_writer = PdfFileWriter()
    stream = pdf_writer.add_object(generic.StreamObject(stream_data=b""))
    pdf_writer.insert_page(PageObject(stream, (0, 0, 200, 300)))
    pdf_output = io.BytesIO()
    pdf_writer.write(pdf_output)
    original = pdf_output.getvalue()
    original_stored = storage.store_bytes(original)

    png_output = io.BytesIO()
    Image.new("RGBA", (20, 10), (20, 80, 120, 128)).save(png_output, format="PNG")
    png_stored = storage.store_bytes(png_output.getvalue())

    with factory.begin() as session:
        user = User(
            identity_authority="https://auth.test/",
            external_id="graphic-operator",
            display_name="Graphic operator",
            role=UserRole.USER,
        )
        document = Document(
            owner=user,
            uploaded_by=user,
            original_name="documento.pdf",
            input_format=InputFormat.PDF,
            detected_media_type="application/pdf",
            original_blob=Blob(
                storage_key=original_stored.key,
                kind="original",
                sha256=original_stored.sha256,
                size_bytes=original_stored.size_bytes,
                state=BlobState.STORED,
            ),
            sha256=original_stored.sha256,
            size_bytes=original_stored.size_bytes,
            state=DocumentState.TO_SIGN,
            analysis_status=AnalysisStatus.COMPLETE,
            capabilities=["graphic", "cades", "pades"],
            analysis_warnings=[],
        )
        graphic = GraphicSignature(
            name="Firma test",
            description="",
            active=True,
            current_version_number=1,
            created_by=user,
        )
        version = GraphicSignatureVersion(
            graphic_signature=graphic,
            version_number=1,
            blob=Blob(
                storage_key=png_stored.key,
                kind="graphic_signature",
                sha256=png_stored.sha256,
                size_bytes=png_stored.size_bytes,
                state=BlobState.STORED,
            ),
            sha256=png_stored.sha256,
            width_pixels=20,
            height_pixels=10,
            created_by=user,
        )
        session.add_all([document, version])

    with factory() as session:
        user = session.scalar(select(User).where(User.external_id == "graphic-operator"))
        document = session.scalar(select(Document))
        version = session.scalar(select(GraphicSignatureVersion))
        assert user is not None and document is not None and version is not None
        job = enqueue_signature(
            session,
            document=document,
            operator=user,
            mode=SignatureMode.GRAPHIC,
            request_id=str(uuid.uuid4()),
            placements=[PlacementSpec(version, 1, 0.1, 0.7, 0.25, 0.12, 0)],
        )

    with factory() as session:
        assert claim_next_signature(session) == job.id
    with factory() as session:
        assert process_claimed_signature(session, settings, job.id) is True
    with factory() as session:
        completed = session.get_one(SignatureJob, job.id)
        artifact = session.scalar(select(SignedArtifact))
        assert completed.status is SignatureJobStatus.COMPLETED
        assert completed.signing_identity_sha256 is None
        assert artifact is not None
        assert artifact.media_type == "application/pdf"
        result = storage.path_for(artifact.blob.storage_key).read_bytes()
        assert result.startswith(original)
