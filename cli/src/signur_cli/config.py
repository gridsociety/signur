import os
import tomllib
from pathlib import Path
from typing import Any

DEFAULTS = {
    # Matches a server started locally with its defaults. Point the CLI at your
    # own deployment with `signur auth login --api-url https://.../api/v1`.
    "api_base_url": "http://127.0.0.1:8000/api/v1",
    # Only needed when the server sits behind an OAuth2 gateway.
    "oauth_issuer": "",
    "oauth_client_id": "",
    # Gateways that expect Basic auth put the token in the password field;
    # set this to the username they require. Empty means send a Bearer token.
    "api_token_basic_user": "",
    "session_cookie_name": "signur_session",
}


def config_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".config" / "signur"


def load() -> dict[str, Any]:
    try:
        with (config_dir() / "config.toml").open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def value(name: str) -> str:
    environment = os.environ.get(f"SIGNUR_{name.upper()}")
    if environment is not None:
        return environment
    return str(load().get(name, DEFAULTS.get(name, "")))


def save(values: dict[str, str]) -> Path:
    """Merge ``values`` into the stored configuration and return its path."""
    current = load()
    current.update({key: value for key, value in values.items() if value})
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "config.toml"
    lines = [f'{key} = "{value!s}"' for key, value in sorted(current.items())]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
