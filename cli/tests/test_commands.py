import base64
import json
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from signur_cli.client import Client
from signur_cli.main import root


def test_graphic_signature_serializes_explicit_placement(monkeypatch):  # type: ignore[no-untyped-def]
    captured: dict[str, Any] = {}

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, str]:
        captured.update(method=method, path=path, **kwargs)
        return {"id": "job-id"}

    monkeypatch.setattr(Client, "request", request)
    result = CliRunner().invoke(
        root,
        [
            "--json",
            "signatures",
            "create",
            "document-id",
            "--mode",
            "graphic",
            "--placement",
            "graphic-version-id",
            "2",
            "0.10",
            "0.20",
            "0.30",
            "0.40",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["path"] == "/documents/document-id/signatures"
    assert captured["json"]["placements"] == [
        {
            "graphic_signature_version_id": "graphic-version-id",
            "page": 2,
            "x": 0.1,
            "y": 0.2,
            "width": 0.3,
            "height": 0.4,
            "order": 0,
        }
    ]
    assert json.loads(result.output)["id"] == "job-id"


def test_graphic_signature_rejects_out_of_page_placement() -> None:
    result = CliRunner().invoke(
        root,
        [
            "signatures",
            "create",
            "document-id",
            "--mode",
            "graphic",
            "--placement",
            "version-id",
            "1",
            "0.8",
            "0.2",
            "0.3",
            "0.4",
        ],
    )
    assert result.exit_code == 2
    assert "rettangolo 0..1" in result.output


def test_admin_graphic_upload_and_user_role_are_exposed(monkeypatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, str]:
        calls.append((method, path, kwargs))
        return {"id": "resource-id"}

    monkeypatch.setattr(Client, "request", request)
    image = tmp_path / "signature.png"
    image.write_bytes(b"png")
    runner = CliRunner()

    created = runner.invoke(
        root,
        ["graphics", "create", "--name", "Firma", "--image", str(image)],
    )
    role = runner.invoke(root, ["users", "set-role", "user-id", "admin"])

    assert created.exit_code == 0, created.output
    assert role.exit_code == 0, role.output
    assert calls[0][0:2] == ("POST", "/admin/graphic-signatures")
    assert calls[1] == (
        "PATCH",
        "/admin/users/user-id/role",
        {"json": {"role": "admin"}},
    )


def test_admin_can_transfer_document_ownership(monkeypatch):  # type: ignore[no-untyped-def]
    captured: dict[str, Any] = {}

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update(method=method, path=path, **kwargs)
        return {"owner": {"display_name": "Nuovo proprietario"}}

    monkeypatch.setattr(Client, "request", request)
    result = CliRunner().invoke(root, ["documents", "set-owner", "document-id", "user-id"])

    assert result.exit_code == 0, result.output
    assert captured == {
        "method": "PATCH",
        "path": "/admin/documents/document-id/owner",
        "json": {"owner_user_id": "user-id"},
    }
    assert "Nuovo proprietario" in result.output


def test_api_client_sets_public_origin_for_mutations(monkeypatch):  # type: ignore[no-untyped-def]
    # A session stored by whoever runs the tests would be used first: this is
    # about the token, so the keychain is taken out of the picture.
    monkeypatch.setattr("signur_cli.client.keychain.load_session", lambda: None)
    monkeypatch.setenv("SIGNUR_API_TOKEN", "secret")
    headers = Client("https://signur.example.org/api/v1")._headers()
    assert headers["Origin"] == "https://signur.example.org"
    assert headers["Authorization"] == "Bearer secret"


def test_api_token_uses_basic_auth_when_the_gateway_requires_a_username(monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr("signur_cli.client.keychain.load_session", lambda: None)
    monkeypatch.setenv("SIGNUR_API_TOKEN", "secret")
    monkeypatch.setenv("SIGNUR_API_TOKEN_BASIC_USER", "gateway-user")
    headers = Client("https://signur.example.org/api/v1")._headers()
    assert headers["Authorization"] == "Basic " + base64.b64encode(
        b"gateway-user:secret"
    ).decode()


def test_local_signature_reads_pin_from_environment_without_echo(monkeypatch):  # type: ignore[no-untyped-def]
    captured: dict[str, Any] = {}

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, str]:
        captured.update(method=method, path=path, **kwargs)
        return {"id": "job-id"}

    monkeypatch.setattr(Client, "request", request)
    monkeypatch.setenv("TEST_CARD_PIN", "654321")
    result = CliRunner().invoke(
        root,
        [
            "signatures",
            "create",
            "document-id",
            "--mode",
            "cades",
            "--proxy-id",
            "certificate-id",
            "--pin-env",
            "TEST_CARD_PIN",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["json"]["pin"] == "654321"
    assert "654321" not in result.output


def test_admin_local_certificate_commands_are_exposed(monkeypatch):  # type: ignore[no-untyped-def]
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((method, path, kwargs))
        return {"items": []}

    monkeypatch.setattr(Client, "request", request)
    runner = CliRunner()
    discovery = runner.invoke(root, ["certificates", "discover", "/middleware/pkcs11.so"])
    created = runner.invoke(
        root,
        [
            "certificates",
            "create-local",
            "--name",
            "Carta",
            "--library-path",
            "/middleware/pkcs11.so",
            "--token-label",
            "Token stabile",
            "--certificate-label",
            "Certificato firma",
        ],
    )

    assert discovery.exit_code == 0, discovery.output
    assert created.exit_code == 0, created.output
    assert calls[0] == (
        "POST",
        "/admin/signing-proxies/local/discover",
        {"json": {"library_path": "/middleware/pkcs11.so"}},
    )
    assert calls[1][2]["json"]["backend"] == "local"
    assert calls[1][2]["json"]["save_pin"] is False


def test_login_uses_username_and_password_when_auth_is_local(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    from signur_cli import config, keychain
    from signur_cli import main as cli_main

    saved: dict[str, Any] = {}
    stored: dict[str, str] = {}
    monkeypatch.setattr(config, "save", lambda values: saved.update(values))
    monkeypatch.setattr(
        config,
        "value",
        lambda name: {"api_base_url": "http://server/api/v1"}.get(name, ""),
    )
    monkeypatch.setattr(keychain, "load_session", lambda: "")
    monkeypatch.setattr(keychain, "delete_session", lambda: None)
    monkeypatch.setattr(keychain, "save_session", lambda token: stored.update(token=token))

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if path == "/auth/status":
            return {"auth_mode": "local"}
        assert path == "/auth/login"
        assert kwargs["json"]["persistent"] is True
        assert kwargs["json"]["username"] == "laura"
        assert kwargs["json"]["password"] == "secret-password"
        return {"session_token": "a-session-token", "username": "laura"}

    monkeypatch.setattr(Client, "request", request)
    result = CliRunner().invoke(
        cli_main.root, ["auth", "login"], input="http://server/api/v1\nlaura\nsecret-password\n"
    )
    assert result.exit_code == 0, result.output
    assert stored["token"] == "a-session-token"
    assert saved["api_base_url"] == "http://server/api/v1"


def test_login_falls_back_to_oauth_when_the_server_uses_a_gateway(monkeypatch):  # type: ignore[no-untyped-def]
    from signur_cli import config, keychain, oauth
    from signur_cli import main as cli_main

    monkeypatch.setattr(config, "save", lambda values: None)
    monkeypatch.setattr(
        config,
        "value",
        lambda name: "http://server/api/v1" if name == "api_base_url" else "https://issuer/",
    )
    monkeypatch.setattr(keychain, "load_session", lambda: "")
    monkeypatch.setattr(
        Client,
        "request",
        lambda self, method, path, **kw: {"auth_mode": "forward_auth"},
    )
    monkeypatch.setattr(oauth, "load_token", lambda: object())
    result = CliRunner().invoke(cli_main.root, ["auth", "login"], input="http://server/api/v1\n")
    assert result.exit_code == 0, result.output
    assert "già presente" in result.output


def test_every_command_says_what_it_does() -> None:
    """A command with no line of its own is invisible in the listing above it."""
    import click

    from signur_cli.main import root

    def muti(comando: click.Command, percorso: str = "") -> list[str]:
        nome = f"{percorso} {comando.name}".strip()
        senza = [] if (comando.help or "").strip() else [nome]
        if isinstance(comando, click.Group):
            for sotto in comando.commands.values():
                senza += muti(sotto, nome)
        return senza

    assert muti(root) == []
