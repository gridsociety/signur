import hashlib
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

from signur.signing_proxy import SigningIdentity


class DirectSigningClient:
    """A signing client that signs digests locally, like the card does remotely."""

    def __init__(
        self,
        common_name: str,
        key_usage: x509.KeyUsage | None = None,
        key_size: int = 2048,
    ) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
        )
        if key_usage is not None:
            builder = builder.add_extension(key_usage, critical=True)
        self.certificate = builder.sign(self.key, hashes.SHA256())
        certificate_der = self.certificate.public_bytes(serialization.Encoding.DER)
        self.identity = SigningIdentity(
            certificate_der=certificate_der,
            certificate_sha256=hashlib.sha256(certificate_der).hexdigest(),
            certificate=self.certificate,
            signature_length=key_size // 8,
        )

    def get_identity(self) -> SigningIdentity:
        return self.identity

    def sign_digest(self, digest: bytes, _expected: SigningIdentity) -> bytes:
        return self.key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


def authentication_key_usage() -> x509.KeyUsage:
    """What a CNS/CRS card certificate carries: digital signature, no non-repudiation."""
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def signing_key_usage() -> x509.KeyUsage:
    """What a document signing certificate carries: non-repudiation."""
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=True,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
