import base64
import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

from signur.signing_proxy import ProxySigningError, SigningProxyClient


def _identity():  # type: ignore[no-untyped-def]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Signur test")])
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
    body = {
        "version": 1,
        "certificate_der_base64": base64.b64encode(der).decode(),
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "digest_algorithm": "SHA-256",
        "signature_algorithm": "RSASSA-PKCS1-v1_5",
        "signature_length": 256,
    }
    return key, body


def test_identity_and_binary_digest_signature_are_verified():
    key, identity_body = _identity()
    digest = hashlib.sha256(b"signed attributes").digest()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/identity"):
            return httpx.Response(200, json=identity_body)
        signature = key.sign(request.content, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return httpx.Response(
            200,
            content=signature,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Digest-Algorithm": "SHA-256",
                "X-Signature-Algorithm": "RSASSA-PKCS1-v1_5",
            },
        )

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as http_client:
        client = SigningProxyClient("http://127.0.0.1:9021", 1, http_client)
        identity = client.get_identity()
        signature = client.sign_digest(digest, identity)

    identity.certificate.public_key().verify(
        signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    signing_request = requests[-1]
    assert signing_request.content == digest
    assert signing_request.headers["x-pkcs11-sign-request"] == "1"


@pytest.mark.parametrize("status", [400, 403, 500])
def test_proxy_failure_is_reported_without_internal_retry(status: int):
    _key, identity_body = _identity()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.url.path.endswith("/identity"):
            return httpx.Response(200, json=identity_body)
        return httpx.Response(status, text="proxy detail must not escape")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = SigningProxyClient("http://proxy", 1, http_client)
        identity = client.get_identity()
        with pytest.raises(ProxySigningError):
            client.sign_digest(bytes(32), identity)
    assert calls == 3


def test_invalid_signature_is_reported_as_failure():
    _key, identity_body = _identity()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/identity"):
            return httpx.Response(200, json=identity_body)
        return httpx.Response(
            200,
            content=bytes(256),
            headers={
                "Content-Type": "application/octet-stream",
                "X-Digest-Algorithm": "SHA-256",
                "X-Signature-Algorithm": "RSASSA-PKCS1-v1_5",
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = SigningProxyClient("http://proxy", 1, http_client)
        identity = client.get_identity()
        with pytest.raises(ProxySigningError):
            client.sign_digest(bytes(32), identity)
