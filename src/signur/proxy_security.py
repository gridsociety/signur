import ipaddress
import socket
from urllib.parse import urlsplit

from signur.errors import ApiError


def validate_proxy_url(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ApiError(422, "invalid_proxy_url", "L'URL del proxy non è ammesso.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise ApiError(422, "invalid_proxy_url", "L'host del proxy non è risolvibile.") from exc
    if not addresses or any(
        not (address.is_private or address.is_loopback)
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        for address in addresses
    ):
        raise ApiError(
            422, "proxy_address_forbidden", "Il proxy deve risolvere soltanto a indirizzi interni."
        )
    return value
