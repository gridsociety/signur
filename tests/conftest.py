import os
from collections.abc import Generator
from pathlib import Path

os.environ.update(
    {
        "SIGNUR_ENVIRONMENT": "test",
        "SIGNUR_AUTO_MIGRATE": "false",
        "SIGNUR_AUTH_MODE": "forward_auth",
        "SIGNUR_DATABASE_URL": "sqlite+pysqlite:///:memory:",
        "SIGNUR_STORAGE_ROOT": "/tmp/signur-tests-default",
        "SIGNUR_IDENTITY_AUTHORITY": "https://auth.test/application/o/signur/",
        "SIGNUR_FORWARD_AUTH_SHARED_SECRET": "test-forward-secret",
        "SIGNUR_ALLOWED_ORIGINS": "https://signur.test",
    }
)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from signur.config import Settings, get_settings
from signur.database import Base, get_session
from signur.main import create_app
from signur.models import BootstrapState


@pytest.fixture
def client(tmp_path: Path) -> Generator[TestClient]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    with session_factory.begin() as session:
        session.add(BootstrapState(id=1, completed=False))

    settings = Settings(
        environment="test",
        auth_mode="forward_auth",
        auto_migrate=False,
        database_url="sqlite+pysqlite:///:memory:",
        storage_root=tmp_path / "blobs",
        identity_authority="https://auth.test/application/o/signur/",
        forward_auth_shared_secret="test-forward-secret",
        allowed_origins=("https://signur.test",),
        pin_encryption_key="test-pin-encryption-key-with-at-least-32-characters",
    )

    def session_override() -> Generator[Session]:
        with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()


@pytest.fixture
def auth_headers():  # type: ignore[no-untyped-def]
    def build(uid: str, *, name: str | None = None, email: str | None = None) -> dict[str, str]:
        return {
            "X-Signur-Auth": "test-forward-secret",
            "X-Auth-Uid": uid,
            "X-Auth-Username": uid,
            "X-Auth-Name": name or uid.title(),
            "X-Auth-Email": email or f"{uid}@test.invalid",
        }

    return build


@pytest.fixture
def mutation_headers(auth_headers):  # type: ignore[no-untyped-def]
    def build(uid: str, **kwargs: str) -> dict[str, str]:
        return {**auth_headers(uid, **kwargs), "Origin": "https://signur.test"}

    return build
