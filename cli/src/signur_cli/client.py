import base64
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from signur_cli import config, keychain, oauth


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, request_id: str = "") -> None:
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        super().__init__(message)


class Client:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or config.value("api_base_url")).rstrip("/")

    def _headers(self) -> dict[str, str]:
        parsed = urlsplit(self.base_url)
        headers = {
            "Accept": "application/json",
            "Origin": f"{parsed.scheme}://{parsed.netloc}",
            "X-Request-ID": f"cli-{uuid.uuid4()}",
        }
        session_token = keychain.load_session()
        if session_token:
            headers["Cookie"] = f"{config.value('session_cookie_name')}={session_token}"
            return headers
        api_token = os.environ.get("SIGNUR_API_TOKEN", "")
        if api_token:
            basic_user = config.value("api_token_basic_user")
            if basic_user:
                value = base64.b64encode(f"{basic_user}:{api_token}".encode()).decode()
                headers["Authorization"] = f"Basic {value}"
            else:
                headers["Authorization"] = f"Bearer {api_token}"
        else:
            token = oauth.fresh_access_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        files: Any = None,
        output: Path | None = None,
    ) -> Any:
        try:
            with httpx.Client(timeout=120, follow_redirects=False) as client:
                response = client.request(
                    method,
                    self.base_url + path,
                    headers=self._headers(),
                    json=json,
                    files=files,
                )
        except httpx.HTTPError as exc:
            raise ApiError(0, "network_error", str(exc)) from exc
        if not response.is_success:
            try:
                error = response.json().get("error", {})
            except ValueError:
                error = {}
            raise ApiError(
                response.status_code,
                str(error.get("code", "http_error")),
                str(error.get("message", response.text or "Richiesta fallita.")),
                str(error.get("request_id", response.headers.get("x-request-id", ""))),
            )
        if output is not None:
            output.write_bytes(response.content)
            return {"path": str(output), "size_bytes": len(response.content)}
        if response.status_code == 204:
            return None
        return response.json()
