import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from signur.database import get_session
from signur.local_pkcs11 import DiscoveredCertificate
from signur.models import SignatureJob
from signur.signing_proxy import SigningIdentity


def _identity() -> SigningIdentity:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certificato locale")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    return SigningIdentity(der, hashlib.sha256(der).hexdigest(), certificate, 256)


def test_admin_manages_internal_signing_proxies(client, auth_headers, mutation_headers):  # type: ignore[no-untyped-def]
    client.get("/api/v1/me", headers=auth_headers("admin"))
    created = client.post(
        "/api/v1/admin/signing-proxies",
        headers=mutation_headers("admin"),
        json={"name": "Carta locale", "base_url": "http://127.0.0.1:9123"},
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
            json={"name": url, "base_url": url},
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
        json={"name": "Vietato", "base_url": "http://127.0.0.1:9124"},
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
