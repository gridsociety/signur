import json
import time
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from signur_cli import config, keychain

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class OAuthError(Exception):
    pass


@dataclass
class Token:
    access_token: str
    refresh_token: str = ""
    token_type: str = "bearer"
    expires_at: int = 0

    def expired(self) -> bool:
        return bool(self.expires_at and time.time() >= self.expires_at - 45)


def _discovery() -> dict[str, Any]:
    issuer = config.value("oauth_issuer").rstrip("/") + "/"
    try:
        response = httpx.get(
            issuer + ".well-known/openid-configuration",
            timeout=10,
            follow_redirects=False,
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise OAuthError("La discovery OIDC non contiene un oggetto JSON.")
        return body
    except (httpx.HTTPError, ValueError) as exc:
        raise OAuthError("Discovery OIDC di Signur non disponibile.") from exc


def _token_from_body(body: dict[str, Any], previous: Token | None = None) -> Token:
    access_token = str(body.get("access_token", ""))
    if not access_token:
        raise OAuthError("La risposta OAuth non contiene un access token.")
    expires_in = int(body.get("expires_in", 0))
    return Token(
        access_token=access_token,
        refresh_token=str(
            body.get("refresh_token") or (previous.refresh_token if previous else "")
        ),
        token_type=str(body.get("token_type", "bearer")).lower(),
        expires_at=int(time.time()) + expires_in if expires_in else 0,
    )


def load_token() -> Token | None:
    raw = keychain.load_token()
    if not raw:
        return None
    try:
        body = json.loads(raw)
        return Token(**body)
    except (json.JSONDecodeError, TypeError):
        return None


def save_token(token: Token) -> None:
    keychain.save_token(json.dumps(asdict(token)))


def request_device_code() -> dict[str, Any]:
    discovery = _discovery()
    endpoint = str(discovery.get("device_authorization_endpoint", ""))
    if not endpoint:
        raise OAuthError("Il provider non pubblica il device authorization endpoint.")
    try:
        response = httpx.post(
            endpoint,
            data={
                "client_id": config.value("oauth_client_id"),
                "scope": "openid email profile offline_access",
            },
            timeout=30,
        )
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OAuthError("Impossibile avviare il device flow.") from exc
    if not isinstance(body, dict) or not body.get("device_code"):
        raise OAuthError("Risposta device flow non valida.")
    return body


def poll_device_token(device: dict[str, Any]) -> Token:
    endpoint = str(_discovery().get("token_endpoint", ""))
    deadline = time.monotonic() + int(device.get("expires_in", 300))
    interval = max(1, int(device.get("interval", 5)))
    while time.monotonic() < deadline:
        try:
            response = httpx.post(
                endpoint,
                data={
                    "grant_type": DEVICE_GRANT,
                    "device_code": str(device["device_code"]),
                    "client_id": config.value("oauth_client_id"),
                },
                timeout=30,
            )
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OAuthError("Errore durante l'attesa dell'autenticazione.") from exc
        if response.is_success and isinstance(body, dict):
            return _token_from_body(body)
        code = body.get("error") if isinstance(body, dict) else ""
        if code == "slow_down":
            interval += 5
        elif code not in {"authorization_pending", "slow_down"}:
            raise OAuthError(str(body.get("error_description") or code or "Login rifiutato."))
        time.sleep(interval)
    raise OAuthError("Il codice di autenticazione è scaduto.")


def fresh_access_token() -> str:
    token = load_token()
    if token is None:
        return ""
    if not token.expired():
        return token.access_token
    if not token.refresh_token:
        return ""
    endpoint = str(_discovery().get("token_endpoint", ""))
    try:
        response = httpx.post(
            endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": token.refresh_token,
                "client_id": config.value("oauth_client_id"),
            },
            timeout=30,
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise OAuthError("Risposta refresh non valida.")
        token = _token_from_body(body, token)
        save_token(token)
        return token.access_token
    except (httpx.HTTPError, ValueError) as exc:
        raise OAuthError("Il rinnovo dell'autenticazione è fallito.") from exc
