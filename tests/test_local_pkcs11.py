import pkcs11
import pytest

from signur.local_pkcs11 import _signing_error
from signur.signature_service import _failure_details


@pytest.mark.parametrize(
    ("exception", "code", "message_fragment"),
    [
        (pkcs11.PinIncorrect(), "pkcs11_pin_incorrect", "non è corretto"),
        (pkcs11.PinLocked(), "pkcs11_pin_locked", "bloccato"),
        (pkcs11.PinExpired(), "pkcs11_pin_expired", "scaduto"),
        (pkcs11.UserPinNotInitialized(), "pkcs11_pin_not_initialized", "inizializzato"),
        (pkcs11.TokenNotPresent(), "pkcs11_token_unavailable", "non è disponibile"),
        (pkcs11.NoSuchKey(), "pkcs11_private_key_unavailable", "chiave privata"),
    ],
)
def test_local_pkcs11_errors_are_safe_and_actionable(
    exception: Exception, code: str, message_fragment: str
) -> None:
    classified = _signing_error(exception)
    assert classified.code == code
    assert message_fragment in classified.user_message
    assert _failure_details(classified) == (code, classified.user_message)
