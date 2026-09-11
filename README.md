# Signur

Signur è un servizio self-hosted per firmare documenti. Carichi un file di
qualsiasi formato, se è un PDF puoi applicarvi una firma grafica, e ottieni una
firma digitale reale prodotta da una smart card: CAdES (`.p7m`), PAdES (`.pdf`)
o XAdES (`.xml`), scelta in base al contenuto.

La chiave privata non lascia mai la carta. Signur calcola l'impronta, chiede
alla carta di firmarla tramite PKCS#11 e costruisce da sé il documento firmato.

## Cosa fa

- **Qualsiasi formato in ingresso.** Carica quello che vuoi: Signur sceglie il
  contenitore di firma adatto al contenuto e lascia intatto il file originale.
- **Firme grafiche sui PDF.** Trascina e ridimensiona un PNG trasparente sulla
  pagina, con zoom fino al 300%. L'anteprima usa una copia locale di Mozilla
  PDF.js: non serve una CDN né il visualizzatore PDF del browser.
- **Documenti già firmati.** Per i P7M attached il contenuto viene estratto ai
  soli fini dell'anteprima. Rifirmando un P7M puoi scegliere la strategia
  matrioska (predefinita) oppure parallela.
- **Smart card in due modi.** Un middleware PKCS#11 caricato sullo stesso host
  di Signur, oppure un PKCS11 Web Proxy remoto.
- **Più utenti e ruoli.** Gli amministratori creano gli account, ne modificano i
  dati, assegnano i ruoli e possono riassegnare la proprietà dei documenti.
- **Audit.** Ogni azione significativa viene registrata. PIN, token di sessione
  e chiavi private non finiscono mai nei log né nell'audit.

## Installazione

Serve **Python 3.12 o successivo**. Il modo più semplice su ogni piattaforma è
[uv](https://docs.astral.sh/uv/), che installa anche Python per te.

### Windows

Apri PowerShell ed esegui:

```powershell
irm https://astral.sh/uv/install.ps1 | iex
uv tool install signur --from git+https://github.com/gridsociety/signur.git
signur
```

### macOS

Apri il Terminale ed esegui:

```shell
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install signur --from git+https://github.com/gridsociety/signur.git
signur
```

Con Homebrew puoi sostituire la prima riga con `brew install uv`.

### Linux

```shell
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install signur --from git+https://github.com/gridsociety/signur.git
signur
```

## Primo avvio

`signur` stampa l'indirizzo su cui è in ascolto:

```
Signur: http://127.0.0.1:8000
```

Aprilo nel browser. Non c'è nulla da configurare: Signur crea un database
SQLite e una cartella privata per i propri dati — `%APPDATA%\signur` su Windows,
`~/.config/signur` altrove — applica da sé le migrazioni e crea l'account
`admin`.

**Quell'account `admin` iniziale non ha password.** Finché resta così Signur ti
autentica da solo, ma soltanto da un browser sullo stesso computer: una
richiesta da un'altra macchina viene rifiutata. L'interfaccia mostra un avviso
finché non imposti una password; fallo prima di usare Signur dalla rete. Una
volta impostata, la fase senza password è chiusa per sempre e ogni account
creato in seguito richiede una password di almeno 8 caratteri.

## Usare una smart card

Serve il middleware PKCS#11 fornito da chi ha emesso la carta. Dopo averlo
installato, apri **Certificati** nell'interfaccia, scegli **Locale** e seleziona
il middleware fra quelli effettivamente presenti sulla macchina, oppure indica
un percorso assoluto con **Altro…**. Signur legge i certificati sulla carta e ti
fa scegliere quello da usare.

Una carta porta spesso **più di un certificato**: uno destinato alla firma dei
documenti e uno all'autenticazione. Signur mostra a cosa serve quello scelto e,
se è di autenticazione oppure ha una chiave più corta di 2048 bit, lo dice prima
della firma senza impedirla: la decisione resta di chi firma.

Percorsi tipici dei middleware:

| Sistema | Esempio di percorso |
|---|---|
| Windows | `C:\Windows\System32\<fornitore>.dll` |
| macOS | `/Library/<fornitore>/pkcs11/<fornitore>.dylib` |
| Linux | `/usr/lib/x86_64-linux-gnu/<fornitore>.so` |

Il PIN della carta può essere richiesto a ogni firma oppure salvato sul
certificato. In entrambi i casi finisce nel database, perché la firma la esegue
un worker asincrono: anche il PIN digitato per una singola firma resta nel job
finché non viene consumato.

Per impostazione predefinita quel PIN è **conservato in chiaro**, e
l'interfaccia lo dice esplicitamente quando stai per salvarlo. Per cifrarlo
imposta un segreto dedicato di almeno 32 caratteri:

```shell
SIGNUR_PIN_ENCRYPTION_KEY='un-segreto-lungo-e-casuale-per-questo-deployment'
```

Impostandolo, i PIN salvati da quel momento sono cifrati; quelli già presenti
restano come sono finché non vengono sostituiti. Un PIN salvato può essere
sostituito o rimosso dall'interfaccia, mai riletto.

Se invece il segreto non è impostato, all'avvio Signur lo segnala nel log e
l'interfaccia mostra un avviso ogni volta che si sta per salvare un PIN.

## Configurazione

Ogni impostazione ha un valore predefinito funzionante: si configura qualcosa
solo se serve. Tutte le variabili usano il prefisso `SIGNUR_`.

Le impostazioni si scrivono in **`signur.env`**, un normale file di testo dentro
la cartella dei dati:

| Sistema | Dove |
|---|---|
| Windows | `%APPDATA%\signur\signur.env` |
| macOS e Linux | `~/.config/signur/signur.env` |

All'avvio Signur stampa il percorso esatto di quella cartella, così non serve
cercarlo. Se non esiste, creala insieme al file: una riga per impostazione, per
esempio

```
SIGNUR_BIND_HOST=0.0.0.0
SIGNUR_PIN_ENCRYPTION_KEY=un-segreto-lungo-e-casuale-per-questo-deployment
```

È accettato anche un `.env` nella cartella da cui avvii Signur: vedi
`.env.example`. Fra le tre fonti vincono le variabili d'ambiente, poi il `.env`
della cartella corrente, infine `signur.env`.

`SIGNUR_DATA_DIR` sposta in un colpo solo database e documenti; dove non è
impostata, fuori da Windows viene rispettata `XDG_CONFIG_HOME`. `SIGNUR_DATABASE_URL`
e `SIGNUR_STORAGE_ROOT` restano indipendenti: dichiararle vince sulla cartella
dei dati.

| Variabile | Predefinito | A cosa serve |
|---|---|---|
| `SIGNUR_DATA_DIR` | `%APPDATA%\signur` su Windows, `~/.config/signur` altrove | Cartella dei dati: da qui derivano i due valori qui sotto |
| `SIGNUR_DATABASE_URL` | `signur.db` nella cartella dei dati | SQLite di default; PostgreSQL per installazioni più grandi |
| `SIGNUR_STORAGE_ROOT` | `blobs` nella cartella dei dati | Dove vengono conservati originali e documenti firmati |
| `SIGNUR_BIND_HOST` / `SIGNUR_BIND_PORT` | `127.0.0.1` / `8000` | Indirizzo di ascolto |
| `SIGNUR_AUTH_MODE` | `local` | `local` per gli account interni, `forward_auth` dietro un proxy che autentica |
| `SIGNUR_AUTO_MIGRATE` | `true` | Applica le migrazioni all'avvio |
| `SIGNUR_MAX_UPLOAD_BYTES` | `33554432` | Dimensione massima dei caricamenti |
| `SIGNUR_PIN_ENCRYPTION_KEY` | vuoto | Cifra i PIN delle smart card; senza, vengono salvati in chiaro |

Per usare PostgreSQL al posto di SQLite:

```shell
SIGNUR_DATABASE_URL='postgresql+psycopg://signur:password@127.0.0.1:5432/signur'
```

### Dietro un proxy che autentica

Imposta `SIGNUR_AUTH_MODE=forward_auth` quando l'autenticazione è svolta da un
reverse proxy davanti a Signur, che inoltra l'identità in header HTTP. In questa
modalità la schermata di accesso interna sparisce e gli account vengono creati
dall'identità inoltrata al primo accesso.

È sicuro solo se il backend non è raggiungibile se non attraverso quel proxy,
perché gli header d'identità vengono considerati attendibili. Restringi
l'ingresso con `SIGNUR_TRUSTED_GATEWAY_IPS` e, se vuoi, richiedi un segreto
condiviso con `SIGNUR_FORWARD_AUTH_SHARED_SECRET`. I nomi degli header sono
configurabili (`SIGNUR_IDENTITY_UID_HEADER` e simili) perché cambiano da un
proxy all'altro; in questa modalità `SIGNUR_IDENTITY_AUTHORITY` e
`SIGNUR_ALLOWED_ORIGINS` sono obbligatorie.

## Riga di comando

Sul computer che esegue Signur puoi recuperare l'accesso amministrativo e
cambiare i ruoli:

```shell
signur-admin users list
signur-admin users set-role NOME_UTENTE_O_EMAIL_O_UUID admin
```

Esiste inoltre un client autenticato separato, per persone, automazioni e
agenti:

```shell
uv tool install "git+https://github.com/gridsociety/signur.git#subdirectory=cli"
signur auth login --api-url http://127.0.0.1:8000/api/v1
signur --json documents list
```

L'elenco completo dei comandi è in [cli/README.md](cli/README.md).

## Eseguire da un clone

```shell
git clone https://github.com/gridsociety/signur.git
cd signur
uv sync --extra dev
uv run signur
```

Il worker che esegue le firme gira nello stesso processo del server, in un
thread separato: le firme non bloccano l'interfaccia.

Verifiche:

```shell
uv run pytest
uv run ruff check .
uv run mypy src
```

## Architettura

Un'applicazione FastAPI serve sia l'API sia l'interfaccia web. Documenti, job di
firma e audit stanno nel database; i file veri e propri stanno in una cartella
privata fuori dalla radice web. Un worker prende i job in coda, costruisce il
PDF, il CMS o l'XML e chiede alla carta l'unica primitiva crittografica che
serve. Un WebSocket aggiorna documenti e tentativi senza ricaricare la pagina.

I tentativi di firma non vengono mai ripetuti automaticamente: qualsiasi errore
porta il documento in **Firma fallita** e lascia all'utente l'azione
**Riprova**, così una carta non firma mai due volte senza una decisione
esplicita.
