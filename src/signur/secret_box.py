"""Storage of smart card PINs.

A PIN is encrypted with a deployment secret when one is configured. Without it
the PIN is stored as-is, so that a single-machine installation can sign without
any setup; the stored value records which of the two happened, and the
interface warns whenever encryption is off.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr

ENCRYPTED_PREFIX = b"enc:"
PLAINTEXT_PREFIX = b"raw:"
MINIMUM_KEY_LENGTH = 32


class SecretBoxError(Exception):
    pass


def encryption_available(key: SecretStr) -> bool:
    return len(key.get_secret_value()) >= MINIMUM_KEY_LENGTH


def _fernet(key: SecretStr) -> Fernet:
    value = key.get_secret_value()
    if len(value) < MINIMUM_KEY_LENGTH:
        raise SecretBoxError("La chiave di cifratura dei PIN non è configurata.")
    derived = hashlib.sha256(b"signur-pkcs11-pin-v1\x00" + value.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def seal_pin(pin: str, key: SecretStr) -> bytes:
    """Return the storable form of ``pin``, encrypted when a key is configured."""
    if not pin:
        raise SecretBoxError("Il PIN è vuoto.")
    if not encryption_available(key):
        return PLAINTEXT_PREFIX + pin.encode()
    return ENCRYPTED_PREFIX + _fernet(key).encrypt(pin.encode())


def unseal_pin(stored: bytes, key: SecretStr) -> str:
    if stored.startswith(PLAINTEXT_PREFIX):
        return stored[len(PLAINTEXT_PREFIX) :].decode()
    # Values written before this prefix existed are always Fernet tokens.
    token = stored[len(ENCRYPTED_PREFIX) :] if stored.startswith(ENCRYPTED_PREFIX) else stored
    try:
        return _fernet(key).decrypt(token).decode()
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise SecretBoxError("Il PIN salvato non può essere decifrato.") from exc


def stored_pin_is_encrypted(stored: bytes) -> bool:
    return not stored.startswith(PLAINTEXT_PREFIX)
