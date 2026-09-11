import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fake_card import authentication_key_usage, signing_key_usage
from sqlalchemy import select

from signur.database import get_session
from signur.local_pkcs11 import DiscoveredCertificate
from signur.models import SignatureJob
from signur.signing_proxy import SigningIdentity


def _identity(key_size: int = 2048, key_usage: x509.KeyUsage | None = None) -> SigningIdentity:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certificato locale")])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    certificate = builder.sign(key, hashes.SHA256())
    der = certificate.public_bytes(serialization.Encoding.DER)
    return SigningIdentity(der, hashlib.sha256(der).hexdigest(), certificate, key_size // 8)


def test_admin_manages_internal_signing_proxies(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    created = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("admin"),
        json={
            "name": "Carta locale",
            "backend": "pkcs11_web_proxy",
            "base_url": "http://127.0.0.1:9123",
        },
    )
    assert created.status_code == 201, created.text
    proxy = created.json()
    assert proxy["version"] == 1

    updated = client.patch(
        f"/api/v1/admin/signing-proxies/{proxy['id']}",
        headers=mutation_headers("admin"),
        json={"active": False, "name": "Carta sospesa"},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert updated.json()["active"] is False

    listing = client.get("/api/v1/admin/signing-proxies", headers=auth_headers("admin"))
    assert listing.status_code == 200
    assert listing.json()["items"][0]["base_url"] == "http://127.0.0.1:9123"


def test_proxy_url_rejects_public_and_metadata_destinations(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    for url in ("https://example.com", "http://169.254.169.254"):
        response = client.post(
            "/api/v1/admin/signing-proxies",
            headers=mutation_headers("admin"),
            json={"name": url, "backend": "pkcs11_web_proxy", "base_url": url},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "proxy_address_forbidden"


def test_ordinary_user_cannot_manage_proxies(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    admin = client.get("/api/v1/me", headers=auth_headers("admin")).json()
    user = client.get("/api/v1/me", headers=auth_headers("user")).json()
    client.patch(
        f"/api/v1/admin/users/{user['id']}/role",
        headers=mutation_headers("admin"),
        json={"role": "user"},
    )
    response = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("user"),
        json={
            "name": "Vietato",
            "backend": "pkcs11_web_proxy",
            "base_url": "http://127.0.0.1:9124",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "admin_required"
    assert admin["role"] == "admin"


def test_local_pkcs11_certificate_and_pin_lifecycle(
    client, auth_headers, mutation_headers, monkeypatch, tmp_path
):  # type: ignore[no-untyped-def]
    identity = _identity()
    discovered = DiscoveredCertificate("Token stabile", "Certificato firma", identity)

    class FakeLocalClient:
        def __init__(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            pass

        def close(self) -> None:
            pass

        def get_identity(self) -> SigningIdentity:
            return identity

    monkeypatch.setattr("signur.api.proxies.discover_certificates", lambda _path: [discovered])
    monkeypatch.setattr("signur.api.proxies.LocalPkcs11SigningClient", FakeLocalClient)
    client.get("/api/v1/me", headers=auth_headers("admin"))

    middleware = tmp_path / "middleware.so"
    middleware.touch()
    status = client.post(
        "/api/v1/admin/signing-proxies/local/library-status",
        headers=mutation_headers("admin"),
        json={"library_path": str(middleware)},
    )
    assert status.status_code == 200
    assert status.json() == {"exists": True}

    discovery = client.post(
        "/api/v1/admin/signing-proxies/local/discover",
        headers=mutation_headers("admin"),
        json={"library_path": "/middleware/pkcs11.so"},
    )
    assert discovery.status_code == 200
    assert discovery.json()["items"][0]["certificate_label"] == "Certificato firma"

    created = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("admin"),
        json={
            "name": "Carta locale",
            "backend": "local",
            "pkcs11_library_path": "/middleware/pkcs11.so",
            "pkcs11_token_label": "Token stabile",
            "pkcs11_certificate_label": "Certificato firma",
            "save_pin": True,
            "pin": "654321",
        },
    )
    assert created.status_code == 201, created.text
    configuration = created.json()
    assert configuration["backend"] == "local"
    assert configuration["pin_saved"] is True
    assert "pin" not in configuration
    assert "saved_pin_ciphertext" not in configuration

    replaced = client.patch(
        f"/api/v1/admin/signing-proxies/{configuration['id']}",
        headers=mutation_headers("admin"),
        json={"saved_pin_action": "replace", "pin": "111111"},
    )
    assert replaced.status_code == 200
    assert replaced.json()["pin_saved"] is True

    removed = client.patch(
        f"/api/v1/admin/signing-proxies/{configuration['id']}",
        headers=mutation_headers("admin"),
        json={"saved_pin_action": "remove"},
    )
    assert removed.status_code == 200
    assert removed.json()["pin_saved"] is False

    available = client.get("/api/v1/signing-proxies", headers=auth_headers("admin"))
    local = next(item for item in available.json()["items"] if item["id"] == configuration["id"])
    assert local["available"] is True
    assert local["requires_pin"] is True

    document = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("testo.txt", b"contenuto", "text/plain")},
    ).json()
    missing_pin = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("admin"),
        json={"mode": "cades", "signing_proxy_id": configuration["id"]},
    )
    assert missing_pin.status_code == 422
    assert missing_pin.json()["error"]["code"] == "pin_required"

    queued = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("admin"),
        json={
            "mode": "cades",
            "signing_proxy_id": configuration["id"],
            "pin": "654321",
        },
    )
    assert queued.status_code == 202, queued.text
    assert "pin" not in queued.json()
    session_generator = client.app.dependency_overrides[get_session]()
    session = next(session_generator)
    try:
        job = session.scalar(
            select(SignatureJob).where(SignatureJob.id == UUID(queued.json()["id"]))
        )
        assert job is not None
        assert job.signing_pin_ciphertext is not None
        assert b"654321" not in job.signing_pin_ciphertext
    finally:
        session_generator.close()


def test_omitting_the_backend_means_the_local_middleware(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    """The typical install signs with a card on the same machine."""
    client.get("/api/v1/me", headers=auth_headers("admin"))
    response = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("admin"),
        json={"name": "Senza backend", "base_url": "http://127.0.0.1:9125"},
    )
    # A web proxy URL alone is no longer enough: the local backend wants a
    # middleware and the labels that identify the certificate on the card.
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "pkcs11_selection_required"


def _web_proxy(client, mutation_headers, name: str, port: int) -> dict:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("admin"),
        json={
            "name": name,
            "backend": "pkcs11_web_proxy",
            "base_url": f"http://127.0.0.1:{port}",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_admin_reorders_the_signing_proxies(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    first = _web_proxy(client, mutation_headers, "Anna", 9201)
    second = _web_proxy(client, mutation_headers, "Bruno", 9202)
    third = _web_proxy(client, mutation_headers, "Carla", 9203)

    # New certificates queue up behind the ones already configured.
    listing = client.get("/api/v1/admin/signing-proxies", headers=auth_headers("admin")).json()
    assert [item["name"] for item in listing["items"]] == ["Anna", "Bruno", "Carla"]
    assert [item["sort_order"] for item in listing["items"]] == [0, 1, 2]

    reordered = client.put(
        "/api/v1/admin/signing-proxies/order",
        headers=mutation_headers("admin"),
        json={"ids": [third["id"], first["id"], second["id"]]},
    )
    assert reordered.status_code == 200, reordered.text
    assert [item["name"] for item in reordered.json()["items"]] == ["Carla", "Anna", "Bruno"]
    assert [item["sort_order"] for item in reordered.json()["items"]] == [0, 1, 2]

    listing = client.get("/api/v1/admin/signing-proxies", headers=auth_headers("admin")).json()
    assert [item["name"] for item in listing["items"]] == ["Carla", "Anna", "Bruno"]

    # The order an admin chose is the order everybody signing sees.
    available = client.get("/api/v1/signing-proxies", headers=auth_headers("admin")).json()
    assert [item["name"] for item in available["items"]] == ["Carla", "Anna", "Bruno"]


def test_reordering_wants_every_certificate_exactly_once(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    first = _web_proxy(client, mutation_headers, "Anna", 9211)
    _web_proxy(client, mutation_headers, "Bruno", 9212)

    for ids in ([first["id"]], [first["id"], first["id"]]):
        response = client.put(
            "/api/v1/admin/signing-proxies/order",
            headers=mutation_headers("admin"),
            json={"ids": ids},
        )
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "incomplete_certificate_order"

    listing = client.get("/api/v1/admin/signing-proxies", headers=auth_headers("admin")).json()
    assert [item["name"] for item in listing["items"]] == ["Anna", "Bruno"]


def test_ordinary_user_cannot_reorder_proxies(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    user = client.get("/api/v1/me", headers=auth_headers("user")).json()
    client.patch(
        f"/api/v1/admin/users/{user['id']}/role",
        headers=mutation_headers("admin"),
        json={"role": "user"},
    )
    proxy = _web_proxy(client, mutation_headers, "Anna", 9221)
    response = client.put(
        "/api/v1/admin/signing-proxies/order",
        headers=mutation_headers("user"),
        json={"ids": [proxy["id"]]},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "admin_required"


def test_signing_without_a_chosen_certificate_takes_the_first_one(
    client, auth_headers, mutation_headers
):  # type: ignore[no-untyped-def]
    """The top of the configured list is the default everywhere."""
    client.get("/api/v1/me", headers=auth_headers("admin"))
    first = _web_proxy(client, mutation_headers, "Anna", 9231)
    second = _web_proxy(client, mutation_headers, "Bruno", 9232)
    client.put(
        "/api/v1/admin/signing-proxies/order",
        headers=mutation_headers("admin"),
        json={"ids": [second["id"], first["id"]]},
    )

    document = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("testo.txt", b"contenuto", "text/plain")},
    ).json()
    queued = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("admin"),
        json={"mode": "cades"},
    )
    assert queued.status_code == 202, queued.text

    session_generator = client.app.dependency_overrides[get_session]()
    session = next(session_generator)
    try:
        job = session.scalar(
            select(SignatureJob).where(SignatureJob.id == UUID(queued.json()["id"]))
        )
        assert job is not None
        assert job.signing_proxy_name == "Bruno"
    finally:
        session_generator.close()


def test_the_identity_reports_the_key_length(client, auth_headers, mutation_headers, monkeypatch):  # type: ignore[no-untyped-def]
    """A 1024 bit card may sign, but the interface has to be able to say so."""
    short = _identity(key_size=1024)

    class FakeLocalClient:
        def __init__(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            pass

        def close(self) -> None:
            pass

        def get_identity(self) -> SigningIdentity:
            return short

    monkeypatch.setattr(
        "signur.api.proxies.discover_certificates",
        lambda _path: [DiscoveredCertificate("Token", "CNS", short)],
    )
    monkeypatch.setattr("signur.api.proxies.LocalPkcs11SigningClient", FakeLocalClient)
    client.get("/api/v1/me", headers=auth_headers("admin"))

    discovery = client.post(
        "/api/v1/admin/signing-proxies/local/discover",
        headers=mutation_headers("admin"),
        json={"library_path": "/middleware/pkcs11.so"},
    )

    assert discovery.status_code == 200
    assert discovery.json()["items"][0]["identity"]["key_bits"] == 1024


def test_the_identity_says_what_the_certificate_is_for(
    client, auth_headers, mutation_headers, monkeypatch
):  # type: ignore[no-untyped-def]
    """A card often carries both: one certificate signs, the other authenticates."""
    firma = _identity(key_usage=signing_key_usage())
    autenticazione = _identity(key_usage=authentication_key_usage())

    monkeypatch.setattr(
        "signur.api.proxies.discover_certificates",
        lambda _path: [
            DiscoveredCertificate("Token", "Firma", firma),
            DiscoveredCertificate("Token", "CNS", autenticazione),
        ],
    )
    client.get("/api/v1/me", headers=auth_headers("admin"))

    discovery = client.post(
        "/api/v1/admin/signing-proxies/local/discover",
        headers=mutation_headers("admin"),
        json={"library_path": "/middleware/pkcs11.so"},
    )

    assert discovery.status_code == 200
    usi = [item["identity"]["intended_use"] for item in discovery.json()["items"]]
    assert usi == ["signature", "authentication"]


def _finish_job(client, job_id: str) -> None:  # type: ignore[no-untyped-def]
    """Close the attempt, as the worker would, without reaching a card."""
    from uuid import UUID

    from signur.database import get_session
    from signur.models import SignatureJob, SignatureJobStatus

    generator = client.app.dependency_overrides[get_session]()
    session = next(generator)
    try:
        job = session.get(SignatureJob, UUID(job_id))
        assert job is not None
        job.status = SignatureJobStatus.FAILED
        session.commit()
    finally:
        generator.close()


def test_a_certificate_can_be_deleted_after_confirmation(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    created = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("admin"),
        json={
            "name": "Da rimuovere",
            "backend": "pkcs11_web_proxy",
            "base_url": "http://127.0.0.1:9021",
        },
    ).json()

    removed = client.delete(
        f"/api/v1/admin/signing-proxies/{created['id']}", headers=mutation_headers("admin")
    )

    assert removed.status_code == 204, removed.text
    listing = client.get("/api/v1/admin/signing-proxies", headers=auth_headers("admin")).json()
    assert [item["name"] for item in listing["items"]] == []


def test_deleting_a_certificate_leaves_the_signatures_it_made(  # type: ignore[no-untyped-def]
    client, auth_headers, mutation_headers
):
    """History must keep saying which certificate signed, even once it is gone."""
    from test_graphics import _pdf

    client.get("/api/v1/me", headers=auth_headers("admin"))
    proxy = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("admin"),
        json={
            "name": "Carta storica",
            "backend": "pkcs11_web_proxy",
            "base_url": "http://127.0.0.1:9022",
        },
    ).json()
    document = client.post(
        "/api/v1/documents",
        headers=mutation_headers("admin"),
        files={"file": ("documento.pdf", _pdf(), "application/pdf")},
    ).json()
    job = client.post(
        f"/api/v1/documents/{document['id']}/signatures",
        headers=mutation_headers("admin"),
        json={"mode": "cades", "signing_proxy_id": proxy["id"]},
    )
    assert job.status_code == 202, job.text

    # While that attempt is in flight the certificate stays put.
    in_flight = client.delete(
        f"/api/v1/admin/signing-proxies/{proxy['id']}", headers=mutation_headers("admin")
    )
    assert in_flight.status_code == 409
    assert in_flight.json()["error"]["code"] == "signing_proxy_in_use"
    _finish_job(client, job.json()["id"])

    removed = client.delete(
        f"/api/v1/admin/signing-proxies/{proxy['id']}", headers=mutation_headers("admin")
    )

    assert removed.status_code == 204, removed.text
    stored = client.get(f"/api/v1/signature-jobs/{job.json()['id']}", headers=auth_headers("admin"))
    assert stored.status_code == 200
    assert stored.json()["signing_proxy_name"] == "Carta storica"
