import json
import os
import platform
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any, NoReturn

import click

from signur_cli import config, keychain, oauth
from signur_cli.client import ApiError, Client


class Context:
    def __init__(self, api_url: str | None, json_output: bool) -> None:
        self.client = Client(api_url)
        self.json_output = json_output


pass_context = click.make_pass_decorator(Context)


def emit(ctx: Context, value: Any, human: str | None = None) -> None:
    if ctx.json_output or human is None:
        click.echo(json.dumps(value, ensure_ascii=False, indent=2, default=str))
    else:
        click.echo(human)


def fail(ctx: Context, error: Exception) -> NoReturn:
    if isinstance(error, ApiError):
        message = error.message
        payload = {
            "ok": False,
            "error": {
                "code": error.code,
                "message": error.message,
                "status": error.status,
                "request_id": error.request_id or None,
            },
        }
        exit_code = 4 if error.status == 403 else 3 if error.status == 401 else 1
    else:
        message = str(error)
        payload = {"ok": False, "error": {"code": "cli_error", "message": str(error)}}
        exit_code = 1
    if ctx.json_output:
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2), err=True)
    else:
        click.echo(f"Errore: {message}", err=True)
    raise click.exceptions.Exit(exit_code)


def call(ctx: Context, method: str, path: str, **kwargs: Any) -> Any:
    try:
        return ctx.client.request(method, path, **kwargs)
    except (ApiError, oauth.OAuthError, OSError) as exc:
        fail(ctx, exc)


def read_pin(pin_env: str | None, prompt_pin: bool) -> str | None:
    if pin_env and prompt_pin:
        raise click.UsageError("Usa soltanto una fra --pin-env e --prompt-pin.")
    if pin_env:
        pin = os.environ.get(pin_env)
        if not pin:
            raise click.UsageError(f"La variabile {pin_env} è assente o vuota.")
        return pin
    if prompt_pin:
        return str(click.prompt("PIN", hide_input=True, confirmation_prompt=False))
    return None


@click.group()
@click.option("--api-url", envvar="SIGNUR_API_BASE_URL", help="URL base delle API Signur.")
@click.option("--json", "json_output", is_flag=True, help="Emette solo JSON machine-readable.")
@click.version_option(package_name="signur-cli")
@click.pass_context
def root(click_ctx: click.Context, api_url: str | None, json_output: bool) -> None:
    """Gestisce documenti e firme in Signur."""
    click_ctx.obj = Context(api_url, json_output)


@root.group()
def auth() -> None:
    """Autenticazione OAuth2."""


@auth.command("login")
@click.option("--api-url", default="", help="URL base del servizio, ad esempio https://signur.example.org/api/v1.")
@click.option("--no-browser", is_flag=True, help="Non apre automaticamente il browser.")
@click.option("--reauth", is_flag=True, help="Sostituisce le credenziali esistenti.")
@pass_context
def auth_login(ctx: Context, api_url: str, no_browser: bool, reauth: bool) -> None:
    api_url = api_url.strip() or click.prompt(
        "URL del servizio Signur", default=config.value("api_base_url"), show_default=True
    )
    config.save({"api_base_url": api_url.rstrip("/")})

    # Ask the server which kind of authentication it uses, then follow that path.
    try:
        status = Client().request("GET", "/auth/status")
    except ApiError as exc:
        fail(ctx, exc)
    mode = str(status.get("auth_mode", "local"))

    if mode == "local":
        if keychain.load_session() and not reauth:
            emit(ctx, {"authenticated": True}, "Autenticazione già presente; usa --reauth.")
            return
        keychain.delete_session()
        username = click.prompt("Nome utente")
        password = click.prompt("Password", hide_input=True, default="", show_default=False)
        try:
            result = Client().request(
                "POST",
                "/auth/login",
                json={"username": username, "password": password, "persistent": True},
            )
        except ApiError as exc:
            fail(ctx, exc)
        token = str(result.get("session_token") or "")
        if not token:
            fail(ctx, RuntimeError("Il server non ha restituito una sessione."))
        keychain.save_session(token)
        emit(
            ctx,
            {"authenticated": True, "user": result.get("username")},
            "Autenticazione completata.",
        )
        return

    if oauth.load_token() is not None and not reauth:
        emit(ctx, {"authenticated": True}, "Autenticazione già presente; usa --reauth.")
        return
    if reauth:
        keychain.delete_token()
    try:
        device = oauth.request_device_code()
        url = str(device.get("verification_uri_complete") or device.get("verification_uri"))
        click.echo(f"Apri questo indirizzo per autenticarti:\n{url}", err=True)
        if not no_browser:
            command = (
                ["open", url]
                if platform.system() == "Darwin"
                else ["rundll32", "url.dll,FileProtocolHandler", url]
                if platform.system() == "Windows"
                else ["xdg-open", url]
            )
            with suppress(OSError):
                subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        token_obj = oauth.poll_device_token(device)
        oauth.save_token(token_obj)
    except (oauth.OAuthError, RuntimeError) as exc:
        fail(ctx, exc)
    emit(ctx, {"authenticated": True}, "Autenticazione completata.")


@auth.command("logout")
@pass_context
def auth_logout(ctx: Context) -> None:
    if keychain.load_session():
        with suppress(ApiError):
            Client().request("POST", "/auth/logout")
    keychain.delete_session()
    keychain.delete_token()
    emit(ctx, {"authenticated": False}, "Credenziali eliminate.")


@auth.command("status")
@pass_context
def auth_status(ctx: Context) -> None:
    profile = call(ctx, "GET", "/me")
    emit(ctx, profile, f"{profile['display_name']} — {profile['role']}")


@root.command("me")
@pass_context
def me(ctx: Context) -> None:
    """Mostra identità e ruolo correnti."""
    emit(ctx, call(ctx, "GET", "/me"))


@root.group()
def documents() -> None:
    """Caricamento e gestione documenti."""


@documents.command("list")
@click.option("--limit", default=100, type=click.IntRange(1, 100))
@click.option("--offset", default=0, type=click.IntRange(0))
@pass_context
def documents_list(ctx: Context, limit: int, offset: int) -> None:
    emit(ctx, call(ctx, "GET", f"/documents?limit={limit}&offset={offset}"))


@documents.command("show")
@click.argument("document_id")
@pass_context
def documents_show(ctx: Context, document_id: str) -> None:
    emit(ctx, call(ctx, "GET", f"/documents/{document_id}"))


@documents.command("upload")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@pass_context
def documents_upload(ctx: Context, path: Path) -> None:
    result = call(
        ctx,
        "POST",
        "/documents",
        files={"file": (path.name, path.read_bytes(), "application/octet-stream")},
    )
    emit(ctx, result, f"Caricato {result['original_name']} ({result['id']}).")


def _download(ctx: Context, document_id: str, kind: str, output: Path) -> None:
    result = call(ctx, "GET", f"/documents/{document_id}/{kind}", output=output)
    emit(ctx, result, str(output))


@documents.command("download-original")
@click.argument("document_id")
@click.argument("output", type=click.Path(dir_okay=False, path_type=Path))
@pass_context
def documents_download_original(ctx: Context, document_id: str, output: Path) -> None:
    _download(ctx, document_id, "original", output)


@documents.command("download-result")
@click.argument("document_id")
@click.argument("output", type=click.Path(dir_okay=False, path_type=Path))
@pass_context
def documents_download_result(ctx: Context, document_id: str, output: Path) -> None:
    _download(ctx, document_id, "result", output)


@documents.command("delete")
@click.argument("document_id")
@pass_context
def documents_delete(ctx: Context, document_id: str) -> None:
    call(ctx, "DELETE", f"/documents/{document_id}")
    emit(ctx, {"deleted": True, "document_id": document_id}, "Documento eliminato.")


@documents.command("set-owner")
@click.argument("document_id")
@click.argument("user_id")
@pass_context
def documents_set_owner(ctx: Context, document_id: str, user_id: str) -> None:
    """Riassegna un documento a un utente abilitato (solo amministratori)."""
    result = call(
        ctx,
        "PATCH",
        f"/admin/documents/{document_id}/owner",
        json={"owner_user_id": user_id},
    )
    emit(
        ctx,
        result,
        f"Documento assegnato a {result['owner']['display_name']}.",
    )


@documents.command("analysis")
@click.argument("document_id")
@pass_context
def documents_analysis(ctx: Context, document_id: str) -> None:
    emit(ctx, call(ctx, "GET", f"/documents/{document_id}/analysis"))


@documents.command("existing-signatures")
@click.argument("document_id")
@pass_context
def documents_existing_signatures(ctx: Context, document_id: str) -> None:
    emit(ctx, call(ctx, "GET", f"/documents/{document_id}/existing-signatures"))


@documents.command("preview")
@click.argument("document_id")
@click.argument("output", type=click.Path(dir_okay=False, path_type=Path))
@pass_context
def documents_preview(ctx: Context, document_id: str, output: Path) -> None:
    emit(ctx, call(ctx, "GET", f"/documents/{document_id}/preview", output=output))


@documents.command("follow-up")
@click.argument("document_id")
@pass_context
def documents_follow_up(ctx: Context, document_id: str) -> None:
    emit(ctx, call(ctx, "POST", f"/documents/{document_id}/follow-up"))


@documents.group("draft")
def documents_draft() -> None:
    """Legge o sostituisce la bozza di firma."""


@documents_draft.command("show")
@click.argument("document_id")
@pass_context
def documents_draft_show(ctx: Context, document_id: str) -> None:
    emit(ctx, call(ctx, "GET", f"/documents/{document_id}/draft"))


@documents_draft.command("set")
@click.argument("document_id")
@click.argument("plan", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@pass_context
def documents_draft_set(ctx: Context, document_id: str, plan: Path) -> None:
    try:
        body = json.loads(plan.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(ctx, exc)
    emit(ctx, call(ctx, "PUT", f"/documents/{document_id}/draft", json=body))


@root.group()
def signatures() -> None:
    """Creazione e controllo delle firme."""


PLACEMENT = click.Tuple([str, click.IntRange(1), float, float, float, float])


@signatures.command("create")
@click.argument("document_id")
@click.option(
    "--mode",
    type=click.Choice(["graphic", "cades", "pades", "xades"]),
    required=True,
)
@click.option(
    "--placement",
    type=PLACEMENT,
    multiple=True,
    metavar="VERSION PAGE X Y WIDTH HEIGHT",
    help="Posizionamento grafico normalizzato; opzione ripetibile.",
)
@click.option("--xades-packaging", type=click.Choice(["enveloped", "enveloping"]))
@click.option("--cades-strategy", type=click.Choice(["nested", "parallel"]))
@click.option("--proxy-id", help="Configurazione del certificato da usare.")
@click.option(
    "--pin-env", metavar="VARIABLE", help="Legge il PIN locale da una variabile d'ambiente."
)
@click.option("--prompt-pin", is_flag=True, help="Chiede il PIN locale senza mostrarlo.")
@pass_context
def signatures_create(
    ctx: Context,
    document_id: str,
    mode: str,
    placement: tuple[tuple[str, int, float, float, float, float], ...],
    xades_packaging: str | None,
    cades_strategy: str | None,
    proxy_id: str | None,
    pin_env: str | None,
    prompt_pin: bool,
) -> None:
    for _, _, x, y, width, height in placement:
        if not (
            0 <= x < 1
            and 0 <= y < 1
            and width > 0
            and height > 0
            and x + width <= 1
            and y + height <= 1
        ):
            raise click.UsageError("Ogni posizionamento deve rientrare nel rettangolo 0..1.")
    placements = [
        {
            "graphic_signature_version_id": version,
            "page": page,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "order": order,
        }
        for order, (version, page, x, y, width, height) in enumerate(placement)
    ]
    if mode in {"graphic", "pades"} and mode == "graphic" and not placements:
        raise click.UsageError("La modalità graphic richiede almeno un --placement.")
    body: dict[str, Any] = {"mode": mode, "placements": placements}
    if xades_packaging:
        body["xades_packaging"] = xades_packaging
    if cades_strategy:
        body["cades_strategy"] = cades_strategy
    if proxy_id:
        body["signing_proxy_id"] = proxy_id
    pin = read_pin(pin_env, prompt_pin)
    if pin is not None:
        body["pin"] = pin
    result = call(ctx, "POST", f"/documents/{document_id}/signatures", json=body)
    emit(ctx, result, f"Tentativo di firma accodato: {result['id']}.")


@signatures.command("status")
@click.argument("job_id")
@pass_context
def signatures_status(ctx: Context, job_id: str) -> None:
    emit(ctx, call(ctx, "GET", f"/signature-jobs/{job_id}"))


@signatures.command("signer")
@pass_context
def signatures_signer(ctx: Context) -> None:
    emit(ctx, call(ctx, "GET", "/signing-identity"))


@root.group("graphics")
def graphics() -> None:
    """Catalogo degli artefatti grafici."""


@graphics.command("list")
@pass_context
def graphics_list(ctx: Context) -> None:
    emit(ctx, call(ctx, "GET", "/graphic-signatures"))


@graphics.command("download")
@click.argument("graphic_id")
@click.argument("version", type=click.IntRange(1))
@click.argument("output", type=click.Path(dir_okay=False, path_type=Path))
@pass_context
def graphics_download(ctx: Context, graphic_id: str, version: int, output: Path) -> None:
    result = call(
        ctx,
        "GET",
        f"/graphic-signatures/{graphic_id}/versions/{version}/image",
        output=output,
    )
    emit(ctx, result, str(output))


@graphics.command("create")
@click.option("--name", required=True)
@click.option("--description", default="")
@click.option(
    "--image", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@pass_context
def graphics_create(ctx: Context, name: str, description: str, image: Path) -> None:
    result = call(
        ctx,
        "POST",
        "/admin/graphic-signatures",
        files={
            "image": (image.name, image.read_bytes(), "image/png"),
            "name": (None, name),
            "description": (None, description),
        },
    )
    emit(ctx, result)


@graphics.command("set-active")
@click.argument("graphic_id")
@click.argument("active", type=click.BOOL)
@pass_context
def graphics_set_active(ctx: Context, graphic_id: str, active: bool) -> None:
    emit(
        ctx, call(ctx, "PATCH", f"/admin/graphic-signatures/{graphic_id}", json={"active": active})
    )


@graphics.command("update")
@click.argument("graphic_id")
@click.option("--name")
@click.option("--description")
@click.option("--active", type=click.BOOL)
@pass_context
def graphics_update(
    ctx: Context,
    graphic_id: str,
    name: str | None,
    description: str | None,
    active: bool | None,
) -> None:
    body = {
        key: value
        for key, value in {"name": name, "description": description, "active": active}.items()
        if value is not None
    }
    if not body:
        raise click.UsageError("Specifica almeno una modifica.")
    emit(ctx, call(ctx, "PATCH", f"/admin/graphic-signatures/{graphic_id}", json=body))


@graphics.command("upload-version")
@click.argument("graphic_id")
@click.argument("image", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@pass_context
def graphics_upload_version(ctx: Context, graphic_id: str, image: Path) -> None:
    emit(
        ctx,
        call(
            ctx,
            "POST",
            f"/admin/graphic-signatures/{graphic_id}/versions",
            files={"image": (image.name, image.read_bytes(), "image/png")},
        ),
    )


@graphics.command("delete-version")
@click.argument("graphic_id")
@click.argument("version", type=click.IntRange(1))
@pass_context
def graphics_delete_version(ctx: Context, graphic_id: str, version: int) -> None:
    call(ctx, "DELETE", f"/admin/graphic-signatures/{graphic_id}/versions/{version}")
    emit(ctx, {"deleted": True, "graphic_id": graphic_id, "version": version})


@root.group()
def users() -> None:
    """Amministrazione degli utenti."""


@users.command("list")
@click.option("--limit", default=100, type=click.IntRange(1, 100))
@click.option("--offset", default=0, type=click.IntRange(0))
@pass_context
def users_list(ctx: Context, limit: int, offset: int) -> None:
    emit(ctx, call(ctx, "GET", f"/admin/users?limit={limit}&offset={offset}"))


@users.command("set-role")
@click.argument("user_id")
@click.argument("role", type=click.Choice(["no_access", "user", "admin"]))
@pass_context
def users_set_role(ctx: Context, user_id: str, role: str) -> None:
    emit(ctx, call(ctx, "PATCH", f"/admin/users/{user_id}/role", json={"role": role}))


@root.group("certificates")
def certificates() -> None:
    """Amministrazione dei certificati di firma."""


@certificates.command("available")
@pass_context
def certificates_available(ctx: Context) -> None:
    """Elenca i certificati disponibili agli utenti abilitati."""
    emit(ctx, call(ctx, "GET", "/signing-proxies"))


@certificates.command("list")
@pass_context
def certificates_list(ctx: Context) -> None:
    emit(ctx, call(ctx, "GET", "/admin/signing-proxies"))


@certificates.command("create-web-proxy")
@click.option("--name", required=True)
@click.option("--url", required=True)
@pass_context
def certificates_create_web_proxy(ctx: Context, name: str, url: str) -> None:
    """Crea una configurazione PKCS11 Web Proxy (`create` e' il nome storico)."""
    emit(
        ctx,
        call(
            ctx,
            "POST",
            "/admin/signing-proxies",
            # Dichiarato esplicitamente: il valore predefinito del server e'
            # il middleware locale, che e' il caso tipico.
            json={"name": name, "backend": "pkcs11_web_proxy", "base_url": url},
        ),
    )


# Nome storico del comando, mantenuto perche' non si rompano gli script.
certificates.add_command(certificates_create_web_proxy, "create")


@certificates.command("create-local")
@click.option("--name", required=True)
@click.option("--library-path", required=True, type=click.Path(dir_okay=False))
@click.option("--token-label", required=True)
@click.option("--certificate-label", required=True)
@click.option("--pin-env", metavar="VARIABLE", help="Salva il PIN letto dalla variabile indicata.")
@click.option("--prompt-pin", is_flag=True, help="Chiede e salva il PIN senza mostrarlo.")
@pass_context
def certificates_create_local(
    ctx: Context,
    name: str,
    library_path: str,
    token_label: str,
    certificate_label: str,
    pin_env: str | None,
    prompt_pin: bool,
) -> None:
    """Crea una configurazione con il middleware PKCS#11 locale."""
    pin = read_pin(pin_env, prompt_pin)
    body: dict[str, Any] = {
        "name": name,
        "backend": "local",
        "pkcs11_library_path": library_path,
        "pkcs11_token_label": token_label,
        "pkcs11_certificate_label": certificate_label,
        "save_pin": pin is not None,
    }
    if pin is not None:
        body["pin"] = pin
    emit(ctx, call(ctx, "POST", "/admin/signing-proxies", json=body))


@certificates.command("libraries")
@pass_context
def certificates_libraries(ctx: Context) -> None:
    """Elenca i middleware PKCS#11 noti presenti sull'host del servizio."""
    emit(ctx, call(ctx, "GET", "/admin/signing-proxies/local/libraries"))


@certificates.command("discover")
@click.argument("library_path")
@pass_context
def certificates_discover(ctx: Context, library_path: str) -> None:
    """Rileva token e certificati nel middleware indicato."""
    emit(
        ctx,
        call(
            ctx,
            "POST",
            "/admin/signing-proxies/local/discover",
            json={"library_path": library_path},
        ),
    )


@certificates.command("set-active")
@click.argument("proxy_id")
@click.argument("active", type=click.BOOL)
@pass_context
def certificates_set_active(ctx: Context, proxy_id: str, active: bool) -> None:
    emit(ctx, call(ctx, "PATCH", f"/admin/signing-proxies/{proxy_id}", json={"active": active}))


@certificates.command("update")
@click.argument("proxy_id")
@click.option("--name")
@click.option("--url")
@click.option("--library-path")
@click.option("--token-label")
@click.option("--certificate-label")
@click.option("--active", type=click.BOOL)
@pass_context
def certificates_update(
    ctx: Context,
    proxy_id: str,
    name: str | None,
    url: str | None,
    library_path: str | None,
    token_label: str | None,
    certificate_label: str | None,
    active: bool | None,
) -> None:
    body = {
        key: value
        for key, value in {
            "name": name,
            "base_url": url,
            "pkcs11_library_path": library_path,
            "pkcs11_token_label": token_label,
            "pkcs11_certificate_label": certificate_label,
            "active": active,
        }.items()
        if value is not None
    }
    if not body:
        raise click.UsageError("Specifica almeno una modifica.")
    emit(ctx, call(ctx, "PATCH", f"/admin/signing-proxies/{proxy_id}", json=body))


@certificates.command("save-pin")
@click.argument("certificate_id")
@click.option("--pin-env", metavar="VARIABLE", help="Legge il PIN dalla variabile indicata.")
@click.option("--prompt-pin", is_flag=True, help="Chiede il PIN senza mostrarlo.")
@pass_context
def certificates_save_pin(
    ctx: Context, certificate_id: str, pin_env: str | None, prompt_pin: bool
) -> None:
    pin = read_pin(pin_env, prompt_pin)
    if pin is None:
        raise click.UsageError("Specifica --pin-env oppure --prompt-pin.")
    emit(
        ctx,
        call(
            ctx,
            "PATCH",
            f"/admin/signing-proxies/{certificate_id}",
            json={"saved_pin_action": "replace", "pin": pin},
        ),
    )


@certificates.command("remove-pin")
@click.argument("certificate_id")
@pass_context
def certificates_remove_pin(ctx: Context, certificate_id: str) -> None:
    emit(
        ctx,
        call(
            ctx,
            "PATCH",
            f"/admin/signing-proxies/{certificate_id}",
            json={"saved_pin_action": "remove"},
        ),
    )


@certificates.command("check")
@click.argument("proxy_id")
@pass_context
def certificates_check(ctx: Context, proxy_id: str) -> None:
    emit(ctx, call(ctx, "POST", f"/admin/signing-proxies/{proxy_id}/check"))


# Keep the original command name for existing scripts while the UI and docs use
# the more accurate "certificates" terminology.
root.add_command(certificates, "proxies")


def main() -> None:
    root()


if __name__ == "__main__":
    main()
