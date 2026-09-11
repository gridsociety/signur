import base64
import binascii
import sys
from contextlib import suppress

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

SERVICE = "signur-cli"
TOKEN_KEY = "oauth-token"
SESSION_KEY = "session-token"
BASE64_PREFIX = "go-keyring-base64:"


def _decode(value: str) -> str:
    value = value.strip()
    if not value.startswith(BASE64_PREFIX):
        return value
    try:
        return base64.b64decode(value.removeprefix(BASE64_PREFIX)).decode()
    except (binascii.Error, UnicodeDecodeError):
        return ""


def load_token(key: str = TOKEN_KEY) -> str:
    try:
        value = keyring.get_password(SERVICE, key)
    except KeyringError:
        return ""
    return _decode(value) if value else ""


def save_token(value: str, key: str = TOKEN_KEY) -> None:
    if sys.platform == "darwin":
        value = BASE64_PREFIX + base64.b64encode(value.encode()).decode()
    try:
        keyring.set_password(SERVICE, key, value)
    except KeyringError as exc:
        raise RuntimeError("Il portachiavi di sistema non è disponibile.") from exc


def delete_token(key: str = TOKEN_KEY) -> None:
    with suppress(KeyringError, PasswordDeleteError):
        keyring.delete_password(SERVICE, key)


def load_session() -> str:
    return load_token(SESSION_KEY)


def save_session(value: str) -> None:
    save_token(value, SESSION_KEY)


def delete_session() -> None:
    delete_token(SESSION_KEY)
