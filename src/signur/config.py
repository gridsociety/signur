import ipaddress
import os
import sys
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def default_data_dir() -> Path:
    """Return the per-user directory where Signur keeps its data."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "signur"


def sqlite_url(path: PurePath) -> str:
    return f"sqlite+pysqlite:///{path.as_posix()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # A plain file next to the data, not a dotfile in whatever directory the
        # service happened to start from. A local .env still wins, for development.
        env_file=(default_data_dir() / "signur.env", ".env"),
        env_prefix="SIGNUR_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Signur"
    environment: str = "production"
    auth_mode: Literal["local", "forward_auth"] = "local"
    data_dir: Path = Field(default_factory=default_data_dir)
    database_url: str = Field(
        default_factory=lambda data: sqlite_url(data["data_dir"] / "signur.db")
    )
    auto_migrate: bool = True
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8000, ge=1, le=65535)
    storage_root: Path = Field(default_factory=lambda data: data["data_dir"] / "blobs")
    identity_authority: str = ""
    forward_auth_shared_secret: SecretStr = SecretStr("")
    allowed_origins: Annotated[tuple[str, ...], NoDecode] = ()
    trusted_gateway_ips: Annotated[tuple[str, ...], NoDecode] = ()
    max_upload_bytes: int = Field(default=32 * 1024 * 1024, ge=1)
    max_graphic_bytes: int = Field(default=5 * 1024 * 1024, ge=1)
    max_graphic_dimension: int = Field(default=4096, ge=1)
    signing_proxy_url: str = "http://127.0.0.1:9021"
    signing_proxy_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    pin_encryption_key: SecretStr = SecretStr("")
    # Whoever queues a signature wakes the worker, so this is only how often
    # the queue is swept anyway, in case that word never arrived.
    worker_poll_seconds: float = Field(default=30.0, gt=0, le=3600)
    identity_uid_header: str = "X-Auth-Uid"
    identity_username_header: str = "X-Auth-Username"
    identity_name_header: str = "X-Auth-Name"
    identity_email_header: str = "X-Auth-Email"
    identity_secret_header: str = "X-Signur-Auth"
    session_cookie_name: str = "signur_session"
    session_lifetime_hours: float = Field(default=12.0, gt=0, le=24 * 30)
    persistent_session_days: float = Field(default=365.0, gt=0, le=3650)
    session_cookie_secure: bool = False

    @field_validator("data_dir", mode="after")
    @classmethod
    def expand_data_dir(cls, value: Path) -> Path:
        return value.expanduser()

    @field_validator("allowed_origins", "trusted_gateway_ips", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip().rstrip("/") for part in value.split(",") if part.strip())
        return value

    @field_validator("trusted_gateway_ips")
    @classmethod
    def validate_gateway_ips(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for address in value:
            ipaddress.ip_address(address)
        return value

    @property
    def local_auth(self) -> bool:
        return self.auth_mode == "local"

    @property
    def pin_encryption_enabled(self) -> bool:
        return len(self.pin_encryption_key.get_secret_value()) >= 32

    def validate_security(self) -> None:
        if self.environment == "test" or self.local_auth:
            return
        if not self.identity_authority:
            raise ValueError("SIGNUR_IDENTITY_AUTHORITY is required")
        if not self.allowed_origins:
            raise ValueError("SIGNUR_ALLOWED_ORIGINS is required")


@lru_cache
def get_settings() -> Settings:
    return Settings()
