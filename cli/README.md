# Signur CLI

Client autenticato per persone, automazioni e agenti.

```shell
uv tool install "git+https://github.com/gridsociety/signur.git#subdirectory=cli"
signur auth login --api-url https://signur.example.org/api/v1
signur --json me
```

`auth login` chiede l'URL del servizio se non lo passi con `--api-url` e lo
salva in `~/.config/signur/config.toml`. Poi si adatta al server:

- con l'autenticazione interna chiede nome utente e password e conserva una
  sessione di lunga durata nel portachiavi di sistema;
- dietro un proxy con OAuth2 esegue il Device Authorization Grant.

Per ambienti non interattivi si può usare un token API:

```shell
export SIGNUR_API_TOKEN='…'
signur --json documents list
```

Il token viene inviato come `Authorization: Bearer`. Se il gateway davanti a
Signur si aspetta invece una Basic auth con il token nel campo password,
imposta il nome utente che richiede:

```shell
export SIGNUR_API_TOKEN_BASIC_USER='nome-utente-del-gateway'
```

Una firma grafica specifica ogni posizionamento in coordinate normalizzate, con pagina numerata
da 1 e origine in alto a sinistra:

```shell
signur signatures create DOCUMENT_ID --mode graphic \
  --placement GRAPHIC_VERSION_ID 1 0.10 0.70 0.25 0.12
```

`--placement` è ripetibile. I suoi sei valori sono: versione dell'artefatto grafico, pagina,
coordinata X, coordinata Y, larghezza e altezza.

Gli amministratori possono elencare gli account e trasferire un documento a un Utente o
Amministratore abilitato:

```shell
signur users list
signur documents set-owner DOCUMENT_ID USER_ID
```

Le configurazioni di firma sono esposte come `certificates` (`proxies` resta un alias). Per un
middleware locale si può prima fare discovery e poi salvare le etichette restituite:

```shell
signur certificates libraries
signur certificates discover /Library/bit4id/pkcs11/libbit4xpki.dylib
signur certificates create-local --name "Carta locale" \
  --library-path /Library/bit4id/pkcs11/libbit4xpki.dylib \
  --token-label CNS --certificate-label "DS User Certificate3"
```

Il PIN non va passato come argomento visibile nella command line. Usare un prompt nascosto oppure
il nome di una variabile d'ambiente:

```shell
signur certificates save-pin CERTIFICATE_ID --prompt-pin
SIGNUR_SMARTCARD_PIN='…' signur signatures create DOCUMENT_ID --mode cades \
  --proxy-id CERTIFICATE_ID --pin-env SIGNUR_SMARTCARD_PIN
signur certificates remove-pin CERTIFICATE_ID
```
