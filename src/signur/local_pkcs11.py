import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pkcs11
from asn1crypto import algos  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from signur.signing_proxy import ProxySigningError, SigningIdentity


class LocalPkcs11Error(Exception):
    pass


class LocalPkcs11SigningError(ProxySigningError):
    def __init__(self, code: str, user_message: str) -> None:
        self.code = code
        self.user_message = user_message
        super().__init__(user_message)


def _signing_error(exc: Exception) -> LocalPkcs11SigningError:
    if isinstance(exc, (pkcs11.PinIncorrect, pkcs11.PinInvalid)):
        return LocalPkcs11SigningError(
            "pkcs11_pin_incorrect",
            "Il PIN della smart card non è corretto.",
        )
    if isinstance(exc, pkcs11.PinLocked):
        return LocalPkcs11SigningError(
            "pkcs11_pin_locked",
            "Il PIN della smart card è bloccato.",
        )
    if isinstance(exc, pkcs11.PinExpired):
        return LocalPkcs11SigningError(
            "pkcs11_pin_expired",
            "Il PIN della smart card è scaduto e deve essere sostituito.",
        )
    if isinstance(exc, pkcs11.UserPinNotInitialized):
        return LocalPkcs11SigningError(
            "pkcs11_pin_not_initialized",
            "Il PIN utente della smart card non è inizializzato.",
        )
    if isinstance(
        exc,
        (
            pkcs11.TokenNotPresent,
            pkcs11.TokenNotRecognised,
            pkcs11.NoSuchToken,
            pkcs11.DeviceRemoved,
        ),
    ):
        return LocalPkcs11SigningError(
            "pkcs11_token_unavailable",
            "La smart card o il token configurato non è disponibile.",
        )
    if isinstance(exc, (pkcs11.NoSuchKey, pkcs11.KeyHandleInvalid)):
        return LocalPkcs11SigningError(
            "pkcs11_private_key_unavailable",
            "La chiave privata del certificato non è disponibile sulla smart card.",
        )
    if isinstance(exc, InvalidSignature):
        return LocalPkcs11SigningError(
            "pkcs11_signature_invalid",
            "La firma restituita dalla smart card non supera la verifica.",
        )
    if isinstance(exc, LocalPkcs11Error):
        return LocalPkcs11SigningError(
            "pkcs11_configuration_failed",
            str(exc),
        )
    return LocalPkcs11SigningError(
        "pkcs11_signing_failed",
        "La smart card locale non ha completato la firma.",
    )


@dataclass(frozen=True)
class DiscoveredCertificate:
    token_label: str
    certificate_label: str
    identity: SigningIdentity


def known_library_paths() -> list[str]:
    candidates: list[Path]
    if sys.platform == "win32":
        windows = Path(os.environ.get("SYSTEMROOT", "C:/Windows"))
        candidates = [
            windows / "System32/bit4xpki.dll",
            windows / "System32/libbit4xpki.dll",
            windows / "System32/bit4ipki.dll",
            windows / "SysWOW64/bit4xpki.dll",
            windows / "SysWOW64/libbit4xpki.dll",
            windows / "System32/opensc-pkcs11.dll",
        ]
    elif sys.platform == "darwin":
        candidates = [
            Path("/Library/bit4id/pkcs11/libbit4xpki.dylib"),
            Path("/Library/OpenSC/lib/opensc-pkcs11.so"),
            Path("/opt/homebrew/lib/opensc-pkcs11.so"),
            Path("/usr/local/lib/opensc-pkcs11.so"),
        ]
    else:
        candidates = [
            Path("/lib/bit4id/libbit4xpki.so"),
            Path("/usr/lib/bit4id/libbit4xpki.so"),
            Path("/usr/local/lib/bit4id/libbit4xpki.so"),
            Path("/usr/lib/libbit4xpki.so"),
            Path("/usr/local/lib/libbit4xpki.so"),
            Path("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            Path("/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so"),
            Path("/usr/lib/opensc-pkcs11.so"),
        ]
    return [str(path.resolve()) for path in candidates if path.is_file()]


def _library(path: str) -> Any:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute() or not candidate.is_file():
        raise LocalPkcs11Error("La libreria PKCS#11 non esiste o non è un percorso assoluto.")
    try:
        return pkcs11.lib(str(candidate.resolve()))
    except Exception as exc:
        raise LocalPkcs11Error("La libreria PKCS#11 non può essere caricata.") from exc


def _identity(certificate_der: bytes) -> SigningIdentity:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise LocalPkcs11Error("Il token contiene un certificato X.509 non valido.") from exc
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise LocalPkcs11Error("Signur supporta attualmente solo certificati RSA.")
    return SigningIdentity(
        certificate_der=certificate_der,
        certificate_sha256=hashlib.sha256(certificate_der).hexdigest(),
        certificate=certificate,
        signature_length=public_key.key_size // 8,
    )


def discover_certificates(library_path: str) -> list[DiscoveredCertificate]:
    library = _library(library_path)
    discovered = []
    try:
        tokens = list(library.get_tokens())
        for token in tokens:
            token_label = token.label.strip()
            if not token_label:
                continue
            with token.open() as session:
                objects = session.get_objects(
                    {pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE}
                )
                for certificate in objects:
                    certificate_label = str(certificate[pkcs11.Attribute.LABEL]).strip()
                    if not certificate_label:
                        continue
                    certificate_der = bytes(certificate[pkcs11.Attribute.VALUE])
                    try:
                        identity = _identity(certificate_der)
                    except LocalPkcs11Error:
                        continue
                    discovered.append(
                        DiscoveredCertificate(token_label, certificate_label, identity)
                    )
    except Exception as exc:
        raise LocalPkcs11Error("Non è possibile leggere i certificati PKCS#11.") from exc
    return discovered


class LocalPkcs11SigningClient:
    def __init__(
        self,
        library_path: str,
        token_label: str,
        certificate_label: str,
        pin: str | None,
    ) -> None:
        self.library_path = library_path
        self.token_label = token_label
        self.certificate_label = certificate_label
        self.pin = pin

    def close(self) -> None:
        self.pin = None

    def _certificate(self) -> tuple[Any, Any, SigningIdentity]:
        library = _library(self.library_path)
        try:
            token = library.get_token(token_label=self.token_label)
            with token.open() as session:
                matches = list(
                    session.get_objects(
                        {
                            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                            pkcs11.Attribute.LABEL: self.certificate_label,
                        }
                    )
                )
                if len(matches) != 1:
                    raise LocalPkcs11Error("Il certificato configurato non è univoco o è assente.")
                certificate = matches[0]
                identity = _identity(bytes(certificate[pkcs11.Attribute.VALUE]))
            return library, token, identity
        except (LocalPkcs11Error, pkcs11.PKCS11Error):
            raise
        except Exception as exc:
            raise LocalPkcs11Error("Il token PKCS#11 configurato non è disponibile.") from exc

    def get_identity(self) -> SigningIdentity:
        try:
            return self._certificate()[2]
        except Exception as exc:
            raise _signing_error(exc) from exc

    def sign_digest(self, digest: bytes, expected_identity: SigningIdentity) -> bytes:
        if len(digest) != hashes.SHA256.digest_size:
            raise ValueError("SHA-256 digest must be exactly 32 bytes")
        if not self.pin:
            raise LocalPkcs11SigningError(
                "pkcs11_pin_required",
                "Il PIN della smart card è richiesto.",
            )
        try:
            library, token, identity = self._certificate()
            if identity.certificate_sha256 != expected_identity.certificate_sha256:
                raise LocalPkcs11Error("Il certificato PKCS#11 è cambiato.")
            del library
            with token.open(user_pin=self.pin) as session:
                certificates = list(
                    session.get_objects(
                        {
                            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                            pkcs11.Attribute.LABEL: self.certificate_label,
                        }
                    )
                )
                if len(certificates) != 1:
                    raise LocalPkcs11Error("Il certificato configurato non è disponibile.")
                certificate_id = bytes(certificates[0][pkcs11.Attribute.ID])
                private_key = session.get_key(
                    object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                    id=certificate_id,
                )
                digest_info = algos.DigestInfo(
                    {"digest_algorithm": {"algorithm": "sha256"}, "digest": digest}
                ).dump()
                signature = bytes(
                    private_key.sign(digest_info, mechanism=pkcs11.Mechanism.RSA_PKCS)
                )
            public_key = identity.certificate.public_key()
            assert isinstance(public_key, rsa.RSAPublicKey)
            public_key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
            return signature
        except Exception as exc:
            raise _signing_error(exc) from exc
