"""Password hashing for the local authentication mode.

Uses hashlib.scrypt so the service keeps working on Windows, macOS and Linux
without a compiled extension.
"""

import hashlib
import hmac
import secrets

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32
PREFIX = "scrypt"
# OpenSSL caps scrypt at 32 MiB unless a limit is given, which these
# parameters exceed; derive the bound from the parameters themselves.


def _maxmem(n: int, r: int, p: int) -> int:
    return 128 * n * r * p * 2


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_BYTES,
        maxmem=_maxmem(SCRYPT_N, SCRYPT_R, SCRYPT_P),
    )
    return f"{PREFIX}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        prefix, n_raw, r_raw, p_raw, salt_hex, digest_hex = encoded.split("$")
        if prefix != PREFIX:
            return False
        n, r, p = int(n_raw), int(r_raw), int(p_raw)
        derived = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=n,
            r=r,
            p=p,
            dklen=len(bytes.fromhex(digest_hex)),
            maxmem=_maxmem(n, r, p),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, bytes.fromhex(digest_hex))
