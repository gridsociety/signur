import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from signur.config import Settings
from signur.database import Base
from signur.models import (
    AnalysisStatus,
    Blob,
    BlobState,
    Document,
    DocumentState,
    InputFormat,
    SignatureJob,
    SignatureJobStatus,
    SignatureMode,
    User,
    UserRole,
)
from signur.signature_service import enqueue_signature
from signur.storage import LocalBlobStorage


def _queued_job(tmp_path: Path) -> tuple[sessionmaker[Session], Settings, uuid.UUID]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(environment="test", storage_root=tmp_path / "blobs")
    storage = LocalBlobStorage(settings.storage_root, settings.max_upload_bytes)
    stored = storage.store_bytes(b"documento")
    with factory.begin() as session:
        user = User(
            identity_authority="https://auth.test/",
            external_id="operator",
            display_name="Operator",
            role=UserRole.USER,
        )
        session.add(
            Document(
                owner=user,
                uploaded_by=user,
                original_name="documento.bin",
                input_format=InputFormat.OPAQUE,
                detected_media_type="application/octet-stream",
                original_blob=Blob(
                    storage_key=stored.key,
                    kind="original",
                    sha256=stored.sha256,
                    size_bytes=stored.size_bytes,
                    state=BlobState.STORED,
                ),
                sha256=stored.sha256,
                size_bytes=stored.size_bytes,
                state=DocumentState.TO_SIGN,
                analysis_status=AnalysisStatus.COMPLETE,
                capabilities=["cades"],
                analysis_warnings=[],
            )
        )
    with factory() as session:
        user = session.scalar(select(User))
        document = session.scalar(select(Document))
        assert user is not None and document is not None
        job = enqueue_signature(
            session,
            document=document,
            operator=user,
            mode=SignatureMode.CADES,
            request_id=str(uuid.uuid4()),
        )
    return factory, settings, job.id


def test_the_running_service_works_off_the_queue_it_accepts(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A stock installation is one command: the server must execute its own jobs."""
    factory, settings, job_id = _queued_job(tmp_path)
    monkeypatch.setattr("signur.config.get_settings", lambda: settings)
    monkeypatch.setattr("signur.worker.get_settings", lambda: settings)
    monkeypatch.setattr("signur.worker.SessionLocal", factory)

    from signur.main import create_app

    with TestClient(create_app()):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with factory() as session:
                job = session.get_one(SignatureJob, job_id)
                if job.status is not SignatureJobStatus.QUEUED:
                    break
            time.sleep(0.05)

    with factory() as session:
        job = session.get_one(SignatureJob, job_id)

    # It has no signing proxy reachable here, so it must fail rather than sit in the queue.
    assert job.status is SignatureJobStatus.FAILED, "il servizio non ha preso in carico il job"
