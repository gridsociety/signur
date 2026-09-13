from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.websockets import WebSocketDisconnect

from signur.auth import ensure_bootstrap_admin
from signur.config import Settings, get_settings
from signur.database import Base, get_session
from signur.main import create_app
from signur.models import BootstrapState
from signur.passwords import hash_password, verify_password

# The shared test environment configures an allowed origin, and the CSRF-style
# origin check in the middleware reads it straight from the process settings.
ORIGIN = {"Origin": "https://signur.test"}
GOOD_PASSWORD = "correct-horse-battery"
LOOPBACK = ("127.0.0.1", 40000)
REMOTE = ("192.168.1.50", 40000)


def _build(tmp_path: Path, **options: object) -> tuple[object, Settings, object]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory.begin() as session:
        session.add(BootstrapState(id=1, completed=False))

    settings = Settings(
        environment="test",
        auth_mode="local",
        auto_migrate=False,
        database_url="sqlite+pysqlite:///:memory:",
        storage_root=tmp_path / "blobs",
        pin_encryption_key="test-pin-encryption-key-with-at-least-32-characters",
        **options,
    )
    with factory() as session:
        ensure_bootstrap_admin(session, settings)

    def override() -> Generator[Session]:
        with factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_session] = override
    app.dependency_overrides[get_settings] = lambda: settings
    return app, settings, engine


@pytest.fixture
def local_client(tmp_path: Path) -> Generator[TestClient]:
    app, _settings, engine = _build(tmp_path)
    with TestClient(app, client=LOOPBACK, headers=ORIGIN) as client:
        yield client
    engine.dispose()


@pytest.fixture
def single_machine_client(tmp_path: Path) -> Generator[TestClient]:
    """The install that configures nothing: no list of origins to compare against."""
    app, _settings, engine = _build(tmp_path, allowed_origins=())
    with TestClient(app, client=LOOPBACK) as client:
        yield client
    engine.dispose()


@pytest.fixture
def remote_client(tmp_path: Path) -> Generator[TestClient]:
    app, _settings, engine = _build(tmp_path)
    with TestClient(app, client=REMOTE, headers=ORIGIN) as client:
        yield client
    engine.dispose()


def test_first_run_admin_is_usable_from_localhost(local_client: TestClient) -> None:
    status = local_client.get("/api/v1/auth/status").json()
    assert status["auth_mode"] == "local"
    assert status["authenticated"] is True
    assert status["password_set"] is False
    assert local_client.get("/api/v1/me").status_code == 200


def test_passwordless_admin_is_unreachable_from_another_host(remote_client: TestClient) -> None:
    assert remote_client.get("/api/v1/me").status_code == 401
    response = remote_client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": ""}
    )
    assert response.status_code == 401


def test_setting_a_password_ends_the_passwordless_phase(local_client: TestClient) -> None:
    response = local_client.post(
        "/api/v1/auth/password",
        json={"current_password": "", "new_password": GOOD_PASSWORD},
    )
    assert response.status_code == 200
    assert local_client.get("/api/v1/auth/status").json()["password_set"] is True

    local_client.cookies.clear()
    assert local_client.get("/api/v1/me").status_code == 401
    assert (
        local_client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": ""}
        ).status_code
        == 401
    )
    assert (
        local_client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": GOOD_PASSWORD}
        ).status_code
        == 200
    )
    assert local_client.get("/api/v1/me").status_code == 200


def test_empty_and_short_passwords_are_refused(local_client: TestClient) -> None:
    for candidate in ("", "short"):
        response = local_client.post(
            "/api/v1/auth/password",
            json={"current_password": "", "new_password": candidate},
        )
        assert response.status_code == 422, candidate


def test_changing_password_revokes_other_sessions(local_client: TestClient, tmp_path: Path) -> None:
    local_client.post(
        "/api/v1/auth/password",
        json={"current_password": "", "new_password": GOOD_PASSWORD},
    )
    stale = dict(local_client.cookies)
    local_client.post(
        "/api/v1/auth/password",
        json={"current_password": GOOD_PASSWORD, "new_password": "second-good-password"},
    )
    fresh = TestClient(local_client.app, client=LOOPBACK, headers=ORIGIN)
    fresh.cookies.update(stale)
    assert fresh.get("/api/v1/me").status_code == 401


def test_wrong_current_password_is_refused(local_client: TestClient) -> None:
    local_client.post(
        "/api/v1/auth/password",
        json={"current_password": "", "new_password": GOOD_PASSWORD},
    )
    response = local_client.post(
        "/api/v1/auth/password",
        json={"current_password": "not-it", "new_password": "another-good-password"},
    )
    assert response.status_code == 403


def test_admin_creates_users_who_can_log_in(local_client: TestClient) -> None:
    created = local_client.post(
        "/api/v1/admin/users",
        json={
            "username": "laura",
            "display_name": "Laura",
            "role": "user",
            "password": "another-good-password",
        },
    )
    assert created.status_code == 201
    assert created.json()["username"] == "laura"

    duplicate = local_client.post(
        "/api/v1/admin/users",
        json={
            "username": "laura",
            "display_name": "Laura B",
            "role": "user",
            "password": "another-good-password",
        },
    )
    assert duplicate.status_code == 409

    local_client.post("/api/v1/auth/logout")
    assert (
        local_client.post(
            "/api/v1/auth/login",
            json={"username": "laura", "password": "another-good-password"},
        ).status_code
        == 200
    )


def test_created_users_cannot_have_an_empty_password(local_client: TestClient) -> None:
    response = local_client.post(
        "/api/v1/admin/users",
        json={"username": "vuoto", "display_name": "Vuoto", "role": "user", "password": ""},
    )
    assert response.status_code == 422


def test_logout_revokes_the_session(local_client: TestClient) -> None:
    local_client.post(
        "/api/v1/auth/password",
        json={"current_password": "", "new_password": GOOD_PASSWORD},
    )
    assert local_client.post("/api/v1/auth/logout").status_code == 204
    assert local_client.get("/api/v1/me").status_code == 401


def test_password_hashing_roundtrip() -> None:
    encoded = hash_password(GOOD_PASSWORD)
    assert encoded.startswith("scrypt$")
    assert verify_password(GOOD_PASSWORD, encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password(GOOD_PASSWORD, None)
    assert not verify_password(GOOD_PASSWORD, "garbage")


def test_admin_edits_an_existing_user(local_client: TestClient) -> None:
    created = local_client.post(
        "/api/v1/admin/users",
        json={
            "username": "laura",
            "display_name": "Laura",
            "role": "user",
            "password": "another-good-password",
        },
    ).json()

    updated = local_client.patch(
        f"/api/v1/admin/users/{created['id']}",
        json={
            "username": "laura.bianchi",
            "display_name": "Laura Bianchi",
            "email": "laura@example.org",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["username"] == "laura.bianchi"
    assert updated.json()["display_name"] == "Laura Bianchi"
    assert updated.json()["email"] == "laura@example.org"

    local_client.post("/api/v1/auth/logout")
    assert (
        local_client.post(
            "/api/v1/auth/login",
            json={"username": "laura.bianchi", "password": "another-good-password"},
        ).status_code
        == 200
    )


def test_editing_cannot_steal_another_username(local_client: TestClient) -> None:
    created = local_client.post(
        "/api/v1/admin/users",
        json={
            "username": "laura",
            "display_name": "Laura",
            "role": "user",
            "password": "another-good-password",
        },
    ).json()
    response = local_client.patch(
        f"/api/v1/admin/users/{created['id']}", json={"username": "admin"}
    )
    assert response.status_code == 409


def test_admin_can_reset_a_password_and_that_ends_old_sessions(local_client: TestClient) -> None:
    # End the passwordless phase first: while it lasts, any loopback request
    # without a session resolves to the admin account by design.
    local_client.post(
        "/api/v1/auth/password",
        json={"current_password": "", "new_password": GOOD_PASSWORD},
    )
    created = local_client.post(
        "/api/v1/admin/users",
        json={
            "username": "laura",
            "display_name": "Laura",
            "role": "user",
            "password": "another-good-password",
        },
    ).json()

    laura = TestClient(local_client.app, client=LOOPBACK, headers=ORIGIN)
    laura.post(
        "/api/v1/auth/login",
        json={"username": "laura", "password": "another-good-password"},
    )
    assert laura.get("/api/v1/me").json()["username"] == "laura"

    reset = local_client.put(
        f"/api/v1/admin/users/{created['id']}/password",
        json={"new_password": "a-brand-new-password"},
    )
    assert reset.status_code == 200
    assert laura.get("/api/v1/me").status_code == 401


SAME_SITE = {"Origin": "http://testserver"}
ANOTHER_SITE = {"Origin": "https://malizia.test"}


def test_a_page_from_another_site_cannot_open_the_event_stream(
    single_machine_client: TestClient,
) -> None:
    """Without a configured list, the only origin that makes sense is our own."""
    with (
        pytest.raises(WebSocketDisconnect) as refused,
        single_machine_client.websocket_connect("/api/v1/events", headers=ANOTHER_SITE),
    ):
        pass

    assert refused.value.code == 4403


def test_the_interface_opens_the_event_stream_from_its_own_address(
    single_machine_client: TestClient,
) -> None:
    with single_machine_client.websocket_connect("/api/v1/events", headers=SAME_SITE) as stream:
        assert stream.receive_json()["type"] == "snapshot"


def test_a_client_that_is_not_a_browser_opens_the_event_stream(
    single_machine_client: TestClient,
) -> None:
    """A script carries no session of its own to be used against its owner."""
    with single_machine_client.websocket_connect("/api/v1/events") as stream:
        assert stream.receive_json()["type"] == "snapshot"


def test_the_event_stream_ends_when_the_session_is_revoked(local_client: TestClient) -> None:
    local_client.post(
        "/api/v1/auth/password",
        json={"current_password": "", "new_password": GOOD_PASSWORD},
    )
    with (
        pytest.raises(WebSocketDisconnect) as closed,
        local_client.websocket_connect("/api/v1/events", headers=ORIGIN) as stream,
    ):
        assert stream.receive_json()["type"] == "snapshot"
        # Somewhere else, the account signs out of everything.
        other = TestClient(local_client.app, client=LOOPBACK, headers=ORIGIN)
        other.cookies.update(dict(local_client.cookies))
        assert other.post("/api/v1/auth/logout").status_code == 204
        stream.receive_json()

    assert (closed.value.code, closed.value.reason) == (4401, "Sessione non più valida.")


def test_the_first_run_admin_keeps_its_stream_without_a_session(
    single_machine_client: TestClient,
) -> None:
    """Nobody has signed in yet: the stream must not close on itself."""
    with single_machine_client.websocket_connect("/api/v1/events", headers=SAME_SITE) as stream:
        assert stream.receive_json()["type"] == "snapshot"
        single_machine_client.post(
            "/api/v1/documents",
            files={"file": ("prova.txt", b"contenuto", "text/plain")},
            headers=ORIGIN,
        )
        assert stream.receive_json()["documents"][0]["state"] == "to_sign"


def test_a_page_from_another_site_cannot_act_on_the_api(
    single_machine_client: TestClient, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """The same rule as the event stream: a foreign page cannot use the session."""
    monkeypatch.setattr(
        "signur.main.get_settings", lambda: Settings(environment="test", allowed_origins=())
    )

    refused = single_machine_client.post(
        "/api/v1/documents",
        files={"file": ("prova.txt", b"contenuto", "text/plain")},
        headers=ANOTHER_SITE,
    )
    accepted = single_machine_client.post(
        "/api/v1/documents",
        files={"file": ("prova.txt", b"contenuto", "text/plain")},
        headers=SAME_SITE,
    )

    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "origin_forbidden"
    assert accepted.status_code == 201, accepted.text
