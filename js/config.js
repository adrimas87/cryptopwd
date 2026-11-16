// Configurazione. Vedi README.md per come ottenere il Client ID.
// Il Client ID NON è un segreto: identifica l'app presso Google, non dà accesso ai tuoi dati.

export const GOOGLE_CLIENT_ID = 'INSERISCI_QUI_IL_TUO_CLIENT_ID.apps.googleusercontent.com';

// Nome del file cifrato su Google Drive.
export const DRIVE_FILE_NAME = 'cryptopwd-vault.json';

// Blocco automatico dopo N minuti di inattività (modificabile anche dalle Impostazioni).
export const DEFAULT_AUTOLOCK_MIN = 5;

// Dopo quanti secondi svuotare gli appunti dopo una copia.
export const CLIPBOARD_CLEAR_SEC = 30;
