import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, ConfigDict, ValidationError


class ProxySigningError(Exception):
    pass


class SigningClient(Protocol):
    def close(self) -> None: ...

    def get_identity(self) -> "SigningIdentity": ...

    def sign_digest(self, digest: bytes, expected_identity: "SigningIdentity") -> bytes: ...


class _IdentityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    certificate_der_base64: str
    certificate_sha256: str
    digest_algorithm: str
    signature_algorithm: str
    signature_length: int


@dataclass(frozen=True)
class SigningIdentity:
    certificate_der: bytes
    certificate_sha256: str
    certificate: x509.Certificate
    signature_length: int

    @property
    def display_name(self) -> str:
        common_names = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_names:
            return str(common_names[0].value)
        return self.certificate.subject.rfc4514_string()

    @property
    def intended_use(self) -> str | None:
        """What the certificate declares it is for: "signature", "authentication", or nothing.

        A card usually carries both kinds. Signing with the authentication one is
        allowed, but worth telling the operator about.
        """
        try:
            usage = self.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return None
        if usage.content_commitment:
            return "signature"
        if usage.digital_signature:
            return "authentication"
        return None

    @property
    def key_bits(self) -> int:
        """How long the signing key is. Under 2048 the signature is weak but legal."""
        public_key = self.certificate.public_key()
        return int(getattr(public_key, "key_size", 0))

    @property
    def subject(self) -> str:
        return self.certificate.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        return self.certificate.issuer.rfc4514_string()

    @property
    def serial_number(self) -> str:
        return format(self.certificate.serial_number, "X")


class SigningProxyClient:
    def __init__(self, base_url: str, timeout_seconds: float, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False)

    def close(self) -> None:
        self._client.close()

    def get_identity(self) -> SigningIdentity:
        try:
            response = self._client.get(f"{self.base_url}/api/v1/signing/identity")
            response.raise_for_status()
            body = _IdentityResponse.model_validate(response.json())
            certificate_der = base64.b64decode(body.certificate_der_base64, validate=True)
            certificate = x509.load_der_x509_certificate(certificate_der)
        except (
            httpx.HTTPError,
            ValueError,
            TypeError,
            ValidationError,
            binascii.Error,
        ) as exc:
            raise ProxySigningError(
                "Impossibile leggere un'identità di firma valida dal proxy."
            ) from exc

        fingerprint = hashlib.sha256(certificate_der).hexdigest()
        public_key = certificate.public_key()
        if (
            body.version != 1
            or body.digest_algorithm != "SHA-256"
            or body.signature_algorithm != "RSASSA-PKCS1-v1_5"
            or body.certificate_sha256.lower() != fingerprint
            or not isinstance(public_key, rsa.RSAPublicKey)
            or body.signature_length != public_key.key_size // 8
            or certificate.not_valid_before_utc > datetime.now(UTC)
            or certificate.not_valid_after_utc <= datetime.now(UTC)
        ):
            raise ProxySigningError("Il proxy espone capacità o certificato non coerenti.")
        return SigningIdentity(certificate_der, fingerprint, certificate, body.signature_length)

    def sign_digest(self, digest: bytes, expected_identity: SigningIdentity) -> bytes:
        if len(digest) != hashes.SHA256.digest_size:
            raise ValueError("SHA-256 digest must be exactly 32 bytes")

        observed = self.get_identity()
        if observed.certificate_sha256 != expected_identity.certificate_sha256:
            raise ProxySigningError("L'identità di firma del proxy è cambiata.")

        try:
            response = self._client.post(
                f"{self.base_url}/api/v1/signing/sign-digest",
                content=digest,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-PKCS11-Sign-Request": "1",
                },
            )
        except httpx.HTTPError as exc:
            raise ProxySigningError("Errore di comunicazione durante la firma.") from exc

        if response.status_code != 200:
            raise ProxySigningError("Il proxy ha rifiutato la firma del digest.")
        signature = response.content
        if (
            response.headers.get("content-type", "").split(";", 1)[0] != "application/octet-stream"
            or response.headers.get("x-digest-algorithm") != "SHA-256"
            or response.headers.get("x-signature-algorithm") != "RSASSA-PKCS1-v1_5"
            or len(signature) != expected_identity.signature_length
        ):
            raise ProxySigningError("La risposta di firma del proxy non è valida.")

        public_key = expected_identity.certificate.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        try:
            public_key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
        except InvalidSignature as exc:
            raise ProxySigningError(
                "La firma restituita dal proxy non supera la verifica."
            ) from exc
        return signature
