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


def _installation(
    tmp_path: Path, **options: object
) -> tuple[sessionmaker[Session], Settings]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(environment="test", storage_root=tmp_path / "blobs", **options)
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
    return factory, settings


def _enqueue(factory: sessionmaker[Session]) -> uuid.UUID:
    with factory() as session:
        user = session.scalar(select(User))
        document = session.scalar(select(Document))
        assert user is not None and document is not None
        return enqueue_signature(
            session,
            document=document,
            operator=user,
            mode=SignatureMode.CADES,
            request_id=str(uuid.uuid4()),
        ).id


def _settled(factory: sessionmaker[Session], job_id: uuid.UUID, within: float) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        with factory() as session:
            if session.get_one(SignatureJob, job_id).status is not SignatureJobStatus.QUEUED:
                return True
        time.sleep(0.05)
    return False


def _in_process(monkeypatch, settings: Settings, factory: sessionmaker[Session]) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("signur.config.get_settings", lambda: settings)
    monkeypatch.setattr("signur.worker.get_settings", lambda: settings)
    # The lifespan reads its own copy, and that is where the sweep interval
    # the worker will wait on comes from.
    monkeypatch.setattr("signur.main.get_settings", lambda: settings)
    monkeypatch.setattr("signur.worker.SessionLocal", factory)


def test_the_running_service_works_off_the_queue_it_accepts(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A stock installation is one command: the server must execute its own jobs."""
    factory, settings = _installation(tmp_path)
    job_id = _enqueue(factory)
    _in_process(monkeypatch, settings, factory)

    from signur.main import create_app

    with TestClient(create_app()):
        settled = _settled(factory, job_id, within=5)

    with factory() as session:
        job = session.get_one(SignatureJob, job_id)

    # It has no signing proxy reachable here, so it must fail rather than sit in the queue.
    assert settled and job.status is SignatureJobStatus.FAILED, (
        "il servizio non ha preso in carico il job"
    )


def test_a_signature_starts_when_it_is_queued_not_when_the_sweep_comes_round(  # type: ignore[no-untyped-def]
    tmp_path: Path, monkeypatch
) -> None:
    """Nothing polls: queueing a signature wakes the worker there and then."""
    factory, settings = _installation(tmp_path, worker_poll_seconds=60)
    _in_process(monkeypatch, settings, factory)

    from signur.main import create_app

    with TestClient(create_app()):
        # The first attempt settles, so the worker has certainly emptied the
        # queue and settled down to wait, with the sweep a minute away.
        assert _settled(factory, _enqueue(factory), within=5)
        time.sleep(0.3)

        second = _enqueue(factory)
        settled = _settled(factory, second, within=5)

    assert settled, "la firma ha aspettato la spazzata invece di partire subito"
