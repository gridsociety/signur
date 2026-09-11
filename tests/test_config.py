import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from signur.config import Settings, default_data_dir, sqlite_url

DATA_ENVIRONMENT = ("APPDATA", "XDG_CONFIG_HOME", "SIGNUR_DATA_DIR")


@pytest.fixture
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*DATA_ENVIRONMENT, "SIGNUR_DATABASE_URL", "SIGNUR_STORAGE_ROOT"):
        monkeypatch.delenv(name, raising=False)


def test_windows_uses_appdata(monkeypatch: pytest.MonkeyPatch, clean_environment: None) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", r"C:\Users\ada\AppData\Roaming")

    assert default_data_dir() == Path(r"C:\Users\ada\AppData\Roaming") / "signur"


def test_windows_without_appdata_falls_back_to_the_home_directory(
    monkeypatch: pytest.MonkeyPatch, clean_environment: None
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("HOME", "/home/ada")

    assert default_data_dir() == Path("/home/ada/AppData/Roaming/signur")


def test_other_platforms_use_the_config_directory(
    monkeypatch: pytest.MonkeyPatch, clean_environment: None
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("HOME", "/home/ada")

    assert default_data_dir() == Path("/home/ada/.config/signur")


def test_xdg_config_home_wins_on_other_platforms(
    monkeypatch: pytest.MonkeyPatch, clean_environment: None
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/home/ada/elsewhere")

    assert default_data_dir() == Path("/home/ada/elsewhere/signur")


def test_database_and_storage_live_in_the_data_directory(clean_environment: None) -> None:
    settings = Settings(_env_file=None, data_dir=Path("/data/signur"))

    assert settings.database_url == "sqlite+pysqlite:////data/signur/signur.db"
    assert settings.storage_root == Path("/data/signur/blobs")


def test_a_windows_path_makes_a_usable_sqlite_url() -> None:
    path = PureWindowsPath(r"C:\Users\ada\AppData\Roaming\signur\signur.db")

    assert sqlite_url(path) == "sqlite+pysqlite:///C:/Users/ada/AppData/Roaming/signur/signur.db"


def test_a_posix_path_keeps_its_leading_slash_in_the_sqlite_url() -> None:
    path = PurePosixPath("/home/ada/.config/signur/signur.db")

    assert sqlite_url(path) == "sqlite+pysqlite:////home/ada/.config/signur/signur.db"


def test_the_data_directory_expands_a_home_relative_path(
    monkeypatch: pytest.MonkeyPatch, clean_environment: None
) -> None:
    monkeypatch.setenv("SIGNUR_DATA_DIR", "~/signur-data")
    monkeypatch.setenv("HOME", "/home/ada")

    settings = Settings(_env_file=None)

    assert settings.data_dir == Path("/home/ada/signur-data")
    assert settings.storage_root == Path("/home/ada/signur-data/blobs")


def test_explicit_settings_win_over_the_data_directory(
    monkeypatch: pytest.MonkeyPatch, clean_environment: None
) -> None:
    monkeypatch.setenv("SIGNUR_DATA_DIR", "/data/signur")
    monkeypatch.setenv("SIGNUR_DATABASE_URL", "postgresql+psycopg://signur@127.0.0.1/signur")
    monkeypatch.setenv("SIGNUR_STORAGE_ROOT", "/srv/blobs")

    settings = Settings(_env_file=None)

    assert settings.database_url == "postgresql+psycopg://signur@127.0.0.1/signur"
    assert settings.storage_root == Path("/srv/blobs")


def test_the_configuration_file_is_visible_in_the_config_folder() -> None:
    """Not a dotfile buried in the working directory: a plain file where the data lives."""
    files = Settings.model_config["env_file"]

    assert files[0] == default_data_dir() / "signur.env"
