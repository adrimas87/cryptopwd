# CryptoPwd

Gestore di password personale, utilizzabile da qualsiasi dispositivo (telefono, tablet, PC) come app installabile (PWA).

- **Cifratura sul dispositivo**: AES-256-GCM con chiave derivata dalla password principale (PBKDF2-SHA256, 600.000 iterazioni). Google, il server che ospita l'app e chiunque altro vedono solo dati cifrati.
- **Database sul tuo Google Drive**: un unico file cifrato, `cryptopwd-vault.json`.
- **Copia locale su ogni dispositivo**: le password si leggono anche senza campo.
- **Sincronizzazione automatica**: allo sblocco, dopo ogni modifica, quando torna la rete e quando riapri l'app. Se nulla è cambiato basta una sola richiesta leggera, senza scaricare il file. Le modifiche fatte offline su più dispositivi vengono unite voce per voce (vince la più recente) e le eliminazioni si propagano.

```
 Telefono                         Google Drive                       PC
┌──────────────────┐            ┌──────────────────────┐            ┌──────────────────┐
│ copia locale     │  ⇄ sync ⇄  │ cryptopwd-vault.json │  ⇄ sync ⇄  │ copia locale     │
│ (cifrata)        │            │ (cifrato)            │            │ (cifrata)        │
└──────────────────┘            └──────────────────────┘            └──────────────────┘
        ↑ la decifratura avviene solo qui, con la tua password principale
```

## Funzioni

- **Soggetti e categorie**: ogni password appartiene a un *soggetto* (te, un familiare, la tua azienda…) e a una delle sue *categorie* (Banca, Email, PEC…). Ogni soggetto ha le proprie categorie. Si filtra con i chip in alto e si gestiscono con ✎ (rinomina ed elimina; un soggetto o una categoria che contiene ancora password non si può eliminare).
- **Modalità riservata** (pulsante 🛡), per quando qualcuno potrebbe vedere lo schermo (es. desktop remoto collegato): utenti, password e note coperti e visibili solo tenendo premuto, contenuto nascosto quando la finestra perde il focus, avviso prima di copiare (gli strumenti di desktop remoto possono trasmettere gli appunti). **Doppio Esc** blocca subito l'app. Non impedisce la cattura dello schermo: riduce ciò che si vede.
- **Allegati**: a ogni password puoi allegare file (max 10 MB ciascuno). Le foto vengono ridotte automaticamente (lato lungo 1600 px, JPEG) e perdono i metadati EXIF come la posizione GPS: una foto da 2-5 MB diventa di solito qualche centinaio di kB. Sono cifrati con una chiave propria, salvati su Drive come file separati (`cryptopwd-att-….bin`) e disponibili anche offline.
- **Sblocco con impronta o volto** (Impostazioni → Sicurezza): sul telefono sblocchi l'app con il sensore biometrico invece di scrivere la password principale. Usa una passkey con l'estensione WebAuthn PRF: la password principale viene cifrata sul dispositivo con una chiave che l'autenticatore rilascia solo dopo la verifica biometrica. Richiede Chrome su Android aggiornato o iOS 18+; se il browser non supporta PRF l'opzione viene rifiutata. Vale per un solo dispositivo; se cambi la password principale, l'app chiede di riconfermare con l'impronta.
- **Cestino**: le password eliminate si possono ripristinare; "Svuota cestino" richiede di scrivere SVUOTA.
- Elenco con ricerca, copia rapida della password (gli appunti si svuotano dopo 30 secondi)
- Generatore di password robuste
- Blocco automatico dopo un periodo di inattività configurabile
- Cambio della password principale (si propaga a tutti i dispositivi)
- Export di un backup cifrato, import da backup o da CSV (Chrome, Firefox, Bitwarden…)

---

## 1. Configura Google (una volta sola, circa 10 minuti)

1. Vai su <https://console.cloud.google.com/> e crea un **nuovo progetto** (es. "CryptoPwd").
2. **API e servizi → Libreria** → cerca **Google Drive API** → **Abilita**.
3. **API e servizi → Schermata consenso OAuth** (o "Google Auth Platform"):
   - Tipo utente: **Esterno**
   - Nome app: CryptoPwd, con la tua email come email di assistenza e di contatto
   - Accesso ai dati / Ambiti: aggiungi `.../auth/drive.file`
   - Pubblico / Utenti di test: **aggiungi la tua email Google**
   (Puoi lasciare l'app in modalità "Test": la usi solo tu.)
4. **API e servizi → Credenziali → Crea credenziali → ID client OAuth**:
   - Tipo: **Applicazione web**
   - **Origini JavaScript autorizzate**: aggiungi l'indirizzo dove pubblicherai l'app, ad esempio
     - `https://TUO-UTENTE.github.io`
     - `http://localhost:8765` (per provarla sul PC)
   - URI di reindirizzamento: lascia vuoto
5. Copia l'**ID client** (finisce con `.apps.googleusercontent.com`) e incollalo in [js/config.js](js/config.js):

   ```js
   export const GOOGLE_CLIENT_ID = '1234567890-abc...apps.googleusercontent.com';
   ```

   L'ID client non è un segreto e può stare in un repository pubblico.

> **Permessi richiesti:** lo scope `drive.file` consente all'app di vedere **solo i file creati da lei**. Non può leggere né modificare il resto del tuo Drive.

## 2. Pubblica l'app (serve HTTPS)

Una PWA richiede HTTPS. Il modo più semplice e gratuito è **GitHub Pages**:

1. Crea un repository su GitHub (es. `cryptopwd`) e carica il contenuto di questa cartella.
2. **Settings → Pages → Source: Deploy from a branch → `main` / root** → Save.
3. Dopo un minuto l'app è su `https://TUO-UTENTE.github.io/cryptopwd/`.
4. Verifica che `https://TUO-UTENTE.github.io` sia tra le origini autorizzate (passo 1.4).

Vanno bene anche Netlify, Cloudflare Pages o qualsiasi hosting statico con HTTPS.

> ⚠️ **Proteggi l'account dell'hosting** (GitHub) con l'autenticazione a due fattori: chi può modificare il codice dell'app potrebbe alterarlo per rubare la password principale al prossimo sblocco.

### Prova in locale

```bash
python -m http.server 8765
```

Poi apri <http://localhost:8765>.

## 3. Installa sui dispositivi

| Dispositivo | Come |
|---|---|
| Android (Chrome) | apri l'indirizzo → menu ⋮ → **Installa app** |
| iPhone/iPad (Safari) | apri l'indirizzo → Condividi → **Aggiungi alla schermata Home** |
| PC (Chrome/Edge) | icona di installazione nella barra degli indirizzi |

**Primo dispositivo:** "Crea un nuovo archivio", scegli la password principale e lascia attivo "Sincronizza con Google Drive".
**Altri dispositivi:** "Ripristina da Google Drive", accedi con lo stesso account Google e inserisci la password principale.

> Su iPhone installa l'app sulla schermata Home: Safari può cancellare i dati dei siti non visitati da tempo, mentre quelli delle app installate restano. In ogni caso il vault resta su Drive e si ripristina in un attimo.

## Sicurezza: come funziona

| Elemento | Dettaglio |
|---|---|
| Derivazione della chiave | PBKDF2-SHA256, 600.000 iterazioni, salt casuale di 128 bit |
| Cifratura | AES-256-GCM, IV casuale di 96 bit a ogni salvataggio, dati autenticati (le manomissioni vengono rilevate) |
| Dove vive la chiave | solo in memoria, come `CryptoKey` non esportabile; viene cancellata al blocco |
| Cosa c'è su Drive e sul dispositivo | solo il blob cifrato più i parametri pubblici (salt, iterazioni) |
| Pagina | Content-Security-Policy restrittiva, nessuna libreria esterna, nessun `innerHTML` con dati utente |

**La password principale non è recuperabile.** Se la dimentichi, i dati sono persi: scrivila su carta e conservala in un posto sicuro. Ogni tanto esporta anche un backup cifrato (Impostazioni → Esporta backup cifrato).

### Casi particolari della sincronizzazione

- **Modifiche offline su più dispositivi**: vengono unite. Se la stessa voce è stata modificata su due dispositivi, vince la modifica più recente.
- **Cambio della password principale**: gli altri dispositivi, alla sincronizzazione successiva, chiedono la nuova password e da quel momento usano quella.
- **Token Google**: dura circa un'ora. Se è scaduto, l'indicatore mostra "Tocca per accedere a Drive" e basta un tocco. Lo sblocco dell'app lo rinnova da solo quando c'è rete.

## Aggiornare l'app

Dopo aver modificato i file, aumenta `VERSION` in [sw.js](sw.js) (es. `cryptopwd-v2`) così i dispositivi scaricano la nuova versione.

## Test

- [tests/test.html](tests/test.html): test di cifratura, unione e CSV. Apri `http://localhost:8765/tests/test.html`.
- [tests/e2e.html](tests/e2e.html): test end-to-end con Google Drive simulato (creazione, ripristino su un altro dispositivo, unione offline, cambio password, lettura offline, eliminazione). Prima di avviarlo imposta un `GOOGLE_CLIENT_ID` qualsiasi, diverso dal segnaposto, in `js/config.js`.

## Struttura

```
index.html            interfaccia
css/style.css         stile (chiaro/scuro automatico)
js/app.js             logica dell'interfaccia e della sincronizzazione
js/crypto.js          cifratura (WebCrypto)
js/biometric.js       sblocco con impronta/volto (WebAuthn PRF)
js/vault.js           modello dati e unione tra copie
js/drive.js           Google Identity Services + Drive API
js/storage.js         copia locale (IndexedDB)
js/csv.js             importazione CSV
js/config.js          configurazione (Client ID)
sw.js                 service worker (funzionamento offline)
manifest.webmanifest  installazione come app
```
