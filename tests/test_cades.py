import base64
import hashlib
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from asn1crypto import cms  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

from signur.cades import build_cades_b_b, build_cades_parallel_b_b, verify_cades_b_b
from signur.signing_proxy import SigningIdentity, SigningProxyClient


class _DirectSigningClient:
    def __init__(self, common_name: str) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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

    def sign_digest(self, digest: bytes, _expected: SigningIdentity) -> bytes:
        return self.key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


def test_attached_cades_b_b_is_independently_verifiable(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Signur CAdES test")])
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
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    identity_body = {
        "version": 1,
        "certificate_der_base64": base64.b64encode(certificate_der).decode(),
        "certificate_sha256": hashlib.sha256(certificate_der).hexdigest(),
        "digest_algorithm": "SHA-256",
        "signature_algorithm": "RSASSA-PKCS1-v1_5",
        "signature_length": 256,
    }

    def handler(request: httpx.Request) -> httpx.Response:
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

    original = b"contenuto originale\x00immutabile\n"
    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = SigningProxyClient("http://proxy", 1, http_client)
        identity = client.get_identity()
        container = build_cades_b_b(original, client, identity)

    verify_cades_b_b(container, original)
    input_path = tmp_path / "signed.p7m"
    output_path = tmp_path / "verified.bin"
    input_path.write_bytes(container)
    subprocess.run(
        [
            "openssl",
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-binary",
            "-noverify",
            "-in",
            str(input_path),
            "-out",
            str(output_path),
        ],
        check=True,
        capture_output=True,
    )
    assert output_path.read_bytes() == original


def test_parallel_cades_preserves_content_and_existing_signer(tmp_path: Path):
    original = b"contenuto condiviso tra i firmatari\x00"
    first_client = _DirectSigningClient("Primo firmatario")
    second_client = _DirectSigningClient("Secondo firmatario")
    initial = build_cades_b_b(
        original,
        first_client,
        first_client.identity,  # type: ignore[arg-type]
    )

    parallel = build_cades_parallel_b_b(
        initial,
        second_client,
        second_client.identity,  # type: ignore[arg-type]
    )

    initial_data = cms.ContentInfo.load(initial, strict=True)["content"]
    parallel_data = cms.ContentInfo.load(parallel, strict=True)["content"]
    assert parallel_data["encap_content_info"]["content"].native == original
    assert len(initial_data["signer_infos"]) == 1
    assert len(parallel_data["signer_infos"]) == 2
    assert initial_data["signer_infos"][0].dump() in {
        signer.dump() for signer in parallel_data["signer_infos"]
    }

    input_path = tmp_path / "parallel.p7m"
    output_path = tmp_path / "parallel-content.bin"
    input_path.write_bytes(parallel)
    subprocess.run(
        [
            "openssl",
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-binary",
            "-noverify",
            "-in",
            str(input_path),
            "-out",
            str(output_path),
        ],
        check=True,
        capture_output=True,
    )
    assert output_path.read_bytes() == original
