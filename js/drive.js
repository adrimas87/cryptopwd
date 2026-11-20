// Integrazione Google Drive (Google Identity Services + Drive API v3).
// Scope "drive.file": l'app vede SOLO i file che ha creato lei, non il resto del tuo Drive.

import { GOOGLE_CLIENT_ID, DRIVE_FILE_NAME } from './config.js';

const SCOPE = 'https://www.googleapis.com/auth/drive.file';
const API = 'https://www.googleapis.com/drive/v3';
const UPLOAD = 'https://www.googleapis.com/upload/drive/v3';

let gisPromise = null;
let tokenClient = null;
let token = null;
let tokenExp = 0;

export const isConfigured = () => !!GOOGLE_CLIENT_ID && !GOOGLE_CLIENT_ID.startsWith('INSERISCI');
export const hasValidToken = () => !!token && Date.now() < tokenExp - 60_000;

export class AuthRequiredError extends Error {
  constructor(msg = 'Accesso a Google Drive richiesto') { super(msg); this.name = 'AuthRequiredError'; }
}

function loadGis() {
  if (window.google?.accounts?.oauth2) return Promise.resolve();
  if (!gisPromise) {
    gisPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://accounts.google.com/gsi/client';
      s.async = true;
      s.onload = () => resolve();
      s.onerror = () => { gisPromise = null; reject(new Error('Impossibile caricare Google Identity Services (sei offline?)')); };
      document.head.appendChild(s);
    });
  }
  return gisPromise;
}

// Da chiamare in anticipo (es. all'avvio quando si è online) così il popup
// può aprirsi subito dentro il gesto dell'utente.
export async function preload() {
  if (!isConfigured() || !navigator.onLine) return;
  try { await loadGis(); } catch { /* offline */ }
}

// Ottiene un access token. Deve essere invocata durante un click dell'utente,
// altrimenti il browser può bloccare il popup.
export async function authorize({ hint } = {}) {
  if (!isConfigured()) throw new Error('Client ID Google non configurato (js/config.js)');
  if (hasValidToken()) return token;
  await loadGis();
  if (pending) pending.reject(new AuthRequiredError('Richiesta sostituita'));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => settle(null, new AuthRequiredError('Accesso a Google non completato')), 120_000);
    const settle = (value, err) => {
      clearTimeout(timer);
      if (pending?.id !== id) return;
      pending = null;
      err ? reject(err) : resolve(value);
    };
    const id = Math.random();
    pending = { id, resolve: (v) => settle(v), reject: (e) => settle(null, e) };
    if (!tokenClient) {
      tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: GOOGLE_CLIENT_ID,
        scope: SCOPE,
        callback: (resp) => {
          if (resp.error) return pending?.reject(new AuthRequiredError(resp.error_description || resp.error));
          if (!google.accounts.oauth2.hasGrantedAllScopes(resp, SCOPE)) return pending?.reject(new AuthRequiredError('Permesso su Drive non concesso'));
          token = resp.access_token;
          tokenExp = Date.now() + Number(resp.expires_in || 3600) * 1000;
          pending?.resolve(token);
        },
        error_callback: (err) => pending?.reject(new AuthRequiredError(err?.type === 'popup_closed' ? 'Accesso annullato' : err?.message || 'Accesso non riuscito')),
      });
    }
    tokenClient.requestAccessToken({ prompt: '', ...(hint ? { login_hint: hint } : {}) });
  });
}

let pending = null;

export function signOut() {
  if (token && window.google?.accounts?.oauth2) google.accounts.oauth2.revoke(token, () => {});
  token = null;
  tokenExp = 0;
}

async function call(url, opts = {}) {
  if (!hasValidToken()) throw new AuthRequiredError();
  const res = await fetch(url, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${token}` } });
  if (res.status === 401) { token = null; throw new AuthRequiredError('Sessione Google scaduta'); }
  if (!res.ok) throw new Error(`Errore Drive ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res;
}

// Cerca il file del vault. Restituisce { id, modifiedTime } o null.
export async function findFile(knownId) {
  if (knownId) {
    try {
      const r = await call(`${API}/files/${encodeURIComponent(knownId)}?fields=id,modifiedTime,trashed`);
      const f = await r.json();
      if (!f.trashed) return f;
    } catch (e) {
      if (e instanceof AuthRequiredError) throw e;
      /* file rimosso: cerca per nome */
    }
  }
  const q = encodeURIComponent(`name='${DRIVE_FILE_NAME}' and trashed=false`);
  const r = await call(`${API}/files?q=${q}&spaces=drive&orderBy=modifiedTime desc&fields=files(id,modifiedTime)`);
  const { files } = await r.json();
  return files?.[0] || null;
}

export async function download(id) {
  const r = await call(`${API}/files/${encodeURIComponent(id)}?alt=media`, { cache: 'no-store' });
  return r.json();
}

// ---- Allegati: un file binario cifrato per allegato ----
export const ATT_PREFIX = 'cryptopwd-att-';

// Elenca tutti i file allegato creati dall'app: [{ id, name, modifiedTime }]
export async function listAttachments() {
  const out = [];
  let pageToken = '';
  do {
    const q = encodeURIComponent(`name contains '${ATT_PREFIX}' and trashed=false`);
    const r = await call(`${API}/files?q=${q}&spaces=drive&pageSize=1000&fields=nextPageToken,files(id,name,modifiedTime)${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`);
    const j = await r.json();
    out.push(...(j.files || []).filter((f) => f.name.startsWith(ATT_PREFIX)));
    pageToken = j.nextPageToken || '';
  } while (pageToken);
  return out;
}

export async function uploadAttachment(attId, bytes) {
  // 1) crea il file (solo metadati) 2) carica il contenuto binario
  const r = await call(`${API}/files?fields=id`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `${ATT_PREFIX}${attId}.bin`, mimeType: 'application/octet-stream', description: 'Allegato cifrato CryptoPwd. Non modificare.' }),
  });
  const { id } = await r.json();
  await call(`${UPLOAD}/files/${encodeURIComponent(id)}?uploadType=media&fields=id`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: bytes,
  });
  return id;
}

export async function downloadBinary(id) {
  const r = await call(`${API}/files/${encodeURIComponent(id)}?alt=media`, { cache: 'no-store' });
  return new Uint8Array(await r.arrayBuffer());
}

export async function deleteFile(id) {
  if (!hasValidToken()) throw new AuthRequiredError();
  const res = await fetch(`${API}/files/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 401) { token = null; throw new AuthRequiredError('Sessione Google scaduta'); }
  if (!res.ok && res.status !== 404) throw new Error(`Errore Drive ${res.status}`);
}

export async function upload(blob, id) {
  const body = JSON.stringify(blob);
  if (id) {
    const r = await call(`${UPLOAD}/files/${encodeURIComponent(id)}?uploadType=media&fields=id,modifiedTime`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    return r.json();
  }
  const boundary = 'cryptopwd' + Math.random().toString(36).slice(2);
  const meta = { name: DRIVE_FILE_NAME, mimeType: 'application/json', description: 'Vault cifrato CryptoPwd (AES-256-GCM). Non modificare.' };
  const multipart =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n` +
    `--${boundary}\r\nContent-Type: application/json\r\n\r\n${body}\r\n--${boundary}--`;
  const r = await call(`${UPLOAD}/files?uploadType=multipart&fields=id,modifiedTime`, {
    method: 'POST',
    headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
    body: multipart,
  });
  return r.json();
}
