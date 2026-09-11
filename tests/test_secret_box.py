import pytest
from pydantic import SecretStr

from signur.secret_box import (
    SecretBoxError,
    seal_pin,
    stored_pin_is_encrypted,
    unseal_pin,
)


def test_pin_is_encrypted_and_bound_to_configured_key():
    first_key = SecretStr("first-encryption-key-with-at-least-32-characters")
    second_key = SecretStr("second-encryption-key-with-at-least-32-characters")

    encrypted = seal_pin("test-only-pin", first_key)

    assert b"test-only-pin" not in encrypted
    assert unseal_pin(encrypted, first_key) == "test-only-pin"
    with pytest.raises(SecretBoxError):
        unseal_pin(encrypted, second_key)


def test_pin_is_stored_in_clear_when_no_key_is_configured():
    """Without a deployment secret the PIN is kept as-is, and says so."""
    no_key = SecretStr("")

    stored = seal_pin("test-only-pin", no_key)

    assert stored_pin_is_encrypted(stored) is False
    assert unseal_pin(stored, no_key) == "test-only-pin"


def test_a_configured_key_marks_the_pin_as_encrypted():
    key = SecretStr("first-encryption-key-with-at-least-32-characters")

    stored = seal_pin("test-only-pin", key)

    assert stored_pin_is_encrypted(stored) is True
    assert b"test-only-pin" not in stored


def test_a_key_shorter_than_32_characters_does_not_encrypt():
    stored = seal_pin("test-only-pin", SecretStr("too-short"))

    assert stored_pin_is_encrypted(stored) is False


def test_pins_encrypted_before_the_prefix_existed_are_still_readable():
    """Rows written by earlier versions carry a bare Fernet token."""
    import base64
    import hashlib

    from cryptography.fernet import Fernet

    key = SecretStr("first-encryption-key-with-at-least-32-characters")
    derived = hashlib.sha256(b"signur-pkcs11-pin-v1\x00" + key.get_secret_value().encode()).digest()
    legacy = Fernet(base64.urlsafe_b64encode(derived)).encrypt(b"test-only-pin")

    assert unseal_pin(legacy, key) == "test-only-pin"


def test_reading_an_encrypted_pin_without_the_key_fails_loudly():
    key = SecretStr("first-encryption-key-with-at-least-32-characters")
    stored = seal_pin("test-only-pin", key)

    with pytest.raises(SecretBoxError):
        unseal_pin(stored, SecretStr(""))
