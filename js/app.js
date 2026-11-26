import * as C from './crypto.js';
import * as V from './vault.js';
import * as store from './storage.js';
import * as drive from './drive.js';
import * as bio from './biometric.js';
import { parseCsvEntries } from './csv.js';
import { DEFAULT_AUTOLOCK_MIN, CLIPBOARD_CLEAR_SEC } from './config.js';

const $ = (id) => document.getElementById(id);

// ---- Stato in memoria (azzerato al blocco) ----
const S = {
  key: null,      // CryptoKey AES-GCM (non estraibile)
  kdf: null,      // parametri KDF del vault corrente
  data: null,     // vault in chiaro
  meta: {},       // metadati locali non sensibili
  lastActivity: Date.now(),
  hiddenAt: 0,
  syncState: 'idle',
};
// Sblocco biometrico: { credId, salt, iv, ct } (password principale cifrata con la chiave della passkey)
let bioRec = null;

// =====================================================================
// Utilità UI
// =====================================================================
function show(screenId) {
  for (const s of document.querySelectorAll('.screen')) s.hidden = s.id !== screenId;
}

let toastTimer;
function toast(msg, ms = 2500) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), ms);
}

function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k === 'dataset') Object.assign(n.dataset, v);
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n[k] = v;
  }
  for (const c of children) n.append(c);
  return n;
}

function fmtDate(ts) {
  if (!ts) return 'mai';
  return new Date(ts).toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
}

// Solo http/https: evita link "javascript:" o simili.
function safeUrl(raw) {
  if (!raw) return null;
  const s = raw.trim();
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(s) ? s : `https://${s}`);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch { return null; }
}

function strength(pwd) {
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;
  const bits = pwd.length * Math.log2(pool || 1);
  return Math.min(100, Math.round((bits / 90) * 100));
}

function bindMeter(input, bar) {
  input.addEventListener('input', () => {
    const v = strength(input.value);
    bar.style.width = `${v}%`;
    bar.dataset.level = v < 40 ? 'low' : v < 70 ? 'mid' : 'high';
  });
}

function openDialog(d) {
  if (!d.open) d.showModal();
}
function closeAllDialogs() {
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
}
document.addEventListener('click', (e) => {
  const c = e.target.closest('[data-close]');
  if (!c) return;
  const dlg = c.closest('dialog');
  if (dlg.id === 'dlg-edit') closeEditSafely(); else dlg.close();
});

function askPassword(title, msg, validate) {
  return askInput({ title, msg, validate });
}

function askInput({ title, msg = '', validate, type = 'password', value = '', placeholder = '', suggestions = [] }) {
  return new Promise((resolve) => {
    const d = $('dlg-prompt');
    $('p-title').textContent = title;
    $('p-msg').textContent = msg;
    $('p-msg').hidden = !msg;
    $('p-input').type = type;
    $('p-input').autocomplete = type === 'password' ? 'current-password' : 'off';
    $('p-input').placeholder = placeholder;
    $('p-input').maxLength = type === 'password' ? 1000 : 100;
    $('p-input').value = value;
    $('p-suggest').replaceChildren(...suggestions.map((s) => el('option', { value: s })));
    $('p-error').hidden = true;
    const form = $('form-prompt');
    let settled = false;
    const done = (v) => {
      if (settled) return;
      settled = true;
      form.onsubmit = null;
      $('p-cancel').onclick = null;
      d.onclose = null;
      if (d.open) d.close();
      $('p-input').value = '';
      resolve(v);
    };
    d.onclose = () => done(null); // anche se chiuso dal blocco automatico
    form.onsubmit = async (e) => {
      e.preventDefault();
      const v = $('p-input').value;
      if (validate) {
        const btn = form.querySelector('[type=submit]');
        btn.disabled = true;
        const err = await validate(v).catch((x) => x.message || String(x));
        btn.disabled = false;
        if (err) { $('p-error').textContent = err; $('p-error').hidden = false; return; }
      }
      done(v);
    };
    $('p-cancel').onclick = () => done(null);
    openDialog(d);
    $('p-input').focus();
    $('p-input').select();
  });
}

function confirmBox(title, msg, okLabel = 'Conferma') {
  return new Promise((resolve) => {
    const d = $('dlg-confirm');
    $('cf-title').textContent = title;
    $('cf-msg').textContent = msg;
    $('cf-ok').textContent = okLabel;
    let settled = false;
    const done = (v) => {
      if (settled) return;
      settled = true;
      $('form-confirm').onsubmit = null;
      d.onclose = null;
      if (d.open) d.close();
      resolve(v);
    };
    $('form-confirm').onsubmit = (e) => { e.preventDefault(); done(true); };
    $('cf-cancel').onclick = () => done(false);
    d.onclose = () => done(false);
    openDialog(d);
  });
}

// Pulsante "tieni premuto": l'azione parte solo dopo HOLD_MS di pressione continua
// (dito, mouse, oppure Invio/Spazio da tastiera). Rilasciando prima non succede nulla.
const HOLD_MS = 2000;
function bindHold(btn, onDone) {
  let timer = 0;
  const stop = () => { clearTimeout(timer); timer = 0; btn.classList.remove('holding'); };
  const start = () => {
    if (btn.disabled || timer) return;
    btn.classList.add('holding');
    timer = setTimeout(() => { stop(); navigator.vibrate?.(40); onDone(); }, HOLD_MS);
  };
  btn.addEventListener('pointerdown', (ev) => {
    if (ev.button > 0) return;
    ev.preventDefault();
    try { btn.setPointerCapture(ev.pointerId); } catch { /* non supportato */ }
    start();
  });
  for (const t of ['pointerup', 'pointercancel', 'lostpointercapture']) btn.addEventListener(t, () => {
    if (timer) toastOnce('Tieni premuto per 2 secondi');
    stop();
  });
  btn.addEventListener('keydown', (ev) => { if ((ev.key === 'Enter' || ev.key === ' ') && !ev.repeat) { ev.preventDefault(); start(); } });
  btn.addEventListener('keyup', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') stop(); });
  btn.addEventListener('blur', stop);
  btn.addEventListener('contextmenu', (ev) => ev.preventDefault()); // niente menu del tocco prolungato
  btn.addEventListener('click', (ev) => ev.preventDefault());
  return stop;
}

let holdResolve = null;
const holdStop = bindHold($('hd-ok'), () => holdResolve?.(true));
// Come confirmBox, ma si conferma tenendo premuto il pulsante per 2 secondi.
function holdBox(title, msg, okLabel) {
  return new Promise((resolve) => {
    const d = $('dlg-hold');
    $('hd-title').textContent = title;
    $('hd-msg').textContent = msg;
    $('hd-ok').querySelector('.hold-label').textContent = okLabel;
    let settled = false;
    const done = (v) => {
      if (settled) return;
      settled = true;
      holdResolve = null;
      holdStop();
      d.onclose = null;
      if (d.open) d.close();
      resolve(v);
    };
    holdResolve = done;
    $('hd-cancel').onclick = () => done(false);
    d.onclose = () => done(false);
    openDialog(d);
  });
}

let clipTimer;
async function copy(text, label) {
  if (!text) return;
  if (isPrivate() && !(await confirmBox(
    `Copiare ${label.toLowerCase()}?`,
    'Se è collegato un desktop remoto (TeamViewer, AnyDesk, Desktop remoto…) gli appunti possono essere inviati anche al computer remoto, che potrebbe quindi leggerli.',
    'Copia comunque'
  ))) return;
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} copiato · gli appunti verranno svuotati tra ${CLIPBOARD_CLEAR_SEC}s`);
    clearTimeout(clipTimer);
    clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), CLIPBOARD_CLEAR_SEC * 1000);
  } catch {
    toast('Impossibile copiare negli appunti');
  }
}

// =====================================================================
// Persistenza locale
// =====================================================================
async function persistLocal({ dirty = true } = {}) {
  const blob = await C.seal(S.key, S.kdf, S.data);
  await store.set('vault', blob);
  if (dirty) S.meta = await store.patchMeta({ dirty: true });
}

// =====================================================================
// Sincronizzazione con Google Drive
// =====================================================================
const SYNC_LABELS = {
  idle: ['Drive non collegato', 'off'],
  ok: ['Sincronizzato', 'ok'],
  syncing: ['Sincronizzo…', 'busy'],
  offline: ['Offline · copia locale', 'warn'],
  auth: ['Tocca per accedere a Drive', 'warn'],
  pending: ['Modifiche da sincronizzare', 'warn'],
  error: ['Errore di sincronizzazione', 'err'],
};

function setSync(state, detail) {
  S.syncState = state;
  const [label, cls] = SYNC_LABELS[state] || SYNC_LABELS.idle;
  $('sync-label').textContent = label;
  $('sync-dot').dataset.state = cls;
  $('btn-sync').title = detail || label;
  if (detail && state === 'error') console.warn('Sync:', detail);
  renderSettingsDrive();
}

function refreshSyncIdle() {
  if (!drive.isConfigured() || !S.meta.driveLinked) return setSync('idle');
  if (!navigator.onLine) return setSync('offline');
  if (S.meta.dirty) return setSync('pending');
  if (!drive.hasValidToken()) return setSync('auth');
  setSync('ok');
}

let syncChain = Promise.resolve();
function sync(opts = {}) {
  syncChain = syncChain.then(() => doSync(opts)).catch((e) => console.error(e));
  return syncChain;
}

async function doSync({ password, force = false, interactive = false } = {}) {
  if (!S.key || !drive.isConfigured() || !S.meta.driveLinked) return refreshSyncIdle();
  if (!navigator.onLine) return setSync('offline');
  try {
    if (!drive.hasValidToken()) {
      if (!interactive) return setSync('auth');
      await drive.authorize();
    }
    setSync('syncing');

    const file = await drive.findFile(S.meta.fileId);

    // Niente da fare se il file su Drive non è cambiato dall'ultima sincronizzazione
    // e qui non ci sono modifiche: basta una sola richiesta leggera (metadati).
    if (file && !force && !S.meta.dirty && !S.meta.attPending && !(S.meta.attDelete || []).length && file.modifiedTime && file.modifiedTime === S.meta.remoteModified) {
      S.meta = await store.patchMeta({ fileId: file.id, lastSync: Date.now() });
      return setSync('ok');
    }

    let remoteBlob = null;
    let remoteData = null;
    let remoteKey = null;
    let remotePwd = null;

    if (file) {
      remoteBlob = await drive.download(file.id);
      if (C.sameKdf(remoteBlob.kdf, S.kdf)) {
        remoteKey = S.key;
        remoteData = V.normalize(await C.unseal(remoteKey, remoteBlob));
      } else {
        // Il vault su Drive ha una password diversa (cambiata altrove o creato separatamente).
        const tryPwd = async (pw) => {
          const k = await C.deriveKey(pw, remoteBlob.kdf);
          remoteData = await C.unseal(k, remoteBlob);
          remoteKey = k;
        };
        let ok = false;
        if (password) {
          try { await tryPwd(password); ok = true; remotePwd = password; } catch (e) { if (!(e instanceof C.WrongPasswordError)) throw e; }
        }
        if (!ok) {
          remotePwd = await askPassword(
            'Password del vault su Drive',
            'Il vault su Google Drive è protetto da una password principale diversa (forse l\'hai cambiata su un altro dispositivo). Inseriscila per unire i dati.',
            async (v) => { try { await tryPwd(v); return null; } catch (e) { if (e instanceof C.WrongPasswordError) return 'Password errata'; throw e; } }
          );
          if (remotePwd === null) return setSync('error', 'Sincronizzazione annullata: password del vault su Drive non inserita');
        }
      }
    }

    // Quale chiave tenere: quella cambiata più di recente (a parità vince Drive).
    let key = S.key;
    let kdf = S.kdf;
    if (remoteBlob && !C.sameKdf(remoteBlob.kdf, S.kdf)) {
      if ((remoteData.keyChangedAt || 0) >= (S.data.keyChangedAt || 0)) { key = remoteKey; kdf = remoteBlob.kdf; }
    }
    const adoptedRemotePwd = key !== S.key ? remotePwd : null;

    const merged = remoteData ? V.merge(S.data, remoteData) : S.data;
    const localChanged = V.fingerprint(merged) !== V.fingerprint(S.data) || !C.sameKdf(kdf, S.kdf);
    const remoteChanged = !file || force || V.fingerprint(merged) !== V.fingerprint(remoteData) || !C.sameKdf(kdf, remoteBlob.kdf);

    if (!S.key) return; // bloccato durante la sincronizzazione
    S.key = key;
    S.kdf = kdf;
    S.data = merged;
    if (localChanged) { await persistLocal({ dirty: false }); renderList(); }
    if (adoptedRemotePwd) offerBioUpdate(adoptedRemotePwd); // password cambiata su un altro dispositivo

    // Allegati: si caricano PRIMA del vault, così gli altri dispositivi li trovano già su Drive.
    S.meta = await store.patchMeta({ attPending: true });
    const driveAtts = await drive.listAttachments();
    await uploadMissingAttachments(driveAtts);

    let fileId = file?.id;
    let remoteModified = file?.modifiedTime;
    if (remoteChanged) {
      const blob = await C.seal(S.key, S.kdf, S.data);
      const f = await drive.upload(blob, fileId);
      fileId = f.id;
      remoteModified = f.modifiedTime;
    }
    S.meta = await store.patchMeta({ fileId, remoteModified, lastSync: Date.now(), dirty: false });

    await downloadMissingAttachments(driveAtts);
    await deleteQueuedAttachments(driveAtts);
    await gcAttachments(driveAtts);
    S.meta = await store.patchMeta({ attPending: false });
    setSync('ok');
  } catch (e) {
    if (e instanceof drive.AuthRequiredError) setSync('auth', e.message);
    else if (!navigator.onLine) setSync('offline');
    else setSync('error', e.message);
  }
}

// =====================================================================
// Allegati: sincronizzazione e pulizia
// =====================================================================
const MAX_ATT_BYTES = 10 * 1024 * 1024;
const ATT_GRACE_MS = 60 * 60 * 1000; // file "orfani" rimossi solo dopo 1 ora (evita conflitti tra dispositivi)
let editAttachments = []; // allegati nel modulo di modifica (non ancora salvati)

const attIdOf = (f) => f.name.slice(drive.ATT_PREFIX.length).replace(/\.bin$/, '');

async function uploadMissingAttachments(driveAtts) {
  const onDrive = new Set(driveAtts.map(attIdOf));
  for (const id of V.referencedAttachments(S.data).keys()) {
    if (onDrive.has(id)) continue;
    const local = await store.getAtt(id);
    if (!local) continue;
    const fid = await drive.uploadAttachment(id, local.data);
    driveAtts.push({ id: fid, name: `${drive.ATT_PREFIX}${id}.bin`, modifiedTime: new Date().toISOString() });
  }
}

async function downloadMissingAttachments(driveAtts) {
  const byId = new Map(driveAtts.map((f) => [attIdOf(f), f]));
  for (const id of V.referencedAttachments(S.data).keys()) {
    if (await store.getAtt(id)) continue;
    const f = byId.get(id);
    if (f) await store.putAtt(id, await drive.downloadBinary(f.id));
  }
}

// Allegati rimossi esplicitamente (rimozione dalla voce, eliminazione definitiva, svuota cestino).
async function queueAttDelete(ids) {
  if (!ids.length) return;
  for (const id of ids) await store.delAtt(id);
  if (S.meta.driveLinked) S.meta = await store.patchMeta({ attDelete: [...new Set([...(S.meta.attDelete || []), ...ids])] });
}

async function deleteQueuedAttachments(driveAtts) {
  const queue = new Set(S.meta.attDelete || []);
  if (!queue.size) return;
  const used = V.referencedAttachments(S.data);
  for (const f of driveAtts) {
    const id = attIdOf(f);
    if (queue.has(id) && !used.has(id)) await drive.deleteFile(f.id);
  }
  S.meta = await store.patchMeta({ attDelete: [] });
}

async function gcAttachments(driveAtts) {
  const used = V.referencedAttachments(S.data);
  const pending = new Set(editAttachments.map((a) => a.id));
  const now = Date.now();
  for (const f of driveAtts) {
    const id = attIdOf(f);
    if (!used.has(id) && !pending.has(id) && now - Date.parse(f.modifiedTime) > ATT_GRACE_MS) await drive.deleteFile(f.id);
  }
  for (const id of await store.attIds()) {
    if (used.has(id) || pending.has(id)) continue;
    const rec = await store.getAtt(id);
    if (now - (rec?.addedAt || 0) > ATT_GRACE_MS) await store.delAtt(id);
  }
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

async function attachmentBlob(a) {
  const rec = await store.getAtt(a.id);
  if (!rec) throw new Error('Allegato non ancora scaricato su questo dispositivo: collegati a internet e sincronizza.');
  return new Blob([await C.decryptBytes(a.key, rec.data)], { type: a.type || 'application/octet-stream' });
}

async function openAttachment(a, mode) {
  // la finestra va aperta subito, dentro il clic, altrimenti il browser la blocca
  const win = mode === 'open' ? window.open('', '_blank') : null;
  try {
    const url = URL.createObjectURL(await attachmentBlob(a));
    if (win) win.location.href = url;
    else {
      const link = el('a', { href: url, download: a.name || 'allegato' });
      document.body.append(link);
      link.click();
      link.remove();
    }
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  } catch (err) {
    win?.close();
    toast(err.message, 4000);
  }
}

function attRow(a, actions) {
  return el('li', { class: 'att' },
    el('span', { class: 'att-name', textContent: `📄 ${a.name}` }),
    el('span', { class: 'muted small', textContent: fmtSize(a.size || 0) }),
    ...actions);
}

let syncDebounce;
function scheduleSync() {
  clearTimeout(syncDebounce);
  if (S.meta.driveLinked) setSync('pending');
  syncDebounce = setTimeout(() => sync(), 1500);
}

// =====================================================================
// Schermate: setup, sblocco, blocco
// =====================================================================
async function boot() {
  store.requestPersistence();
  S.meta = await store.getMeta();
  applyPrivacy();
  drive.preload();
  const blob = await store.get('vault');
  if (!blob) {
    $('drive-unconfigured').hidden = drive.isConfigured();
    $('btn-restore').disabled = !drive.isConfigured();
    $('create-drive').disabled = !drive.isConfigured();
    $('create-drive').checked = drive.isConfigured();
    show('screen-setup');
  } else {
    bioRec = (await store.get('bio')) || null;
    showLock();
    if (bioRec) unlockWithBio({ auto: true }); // propone subito impronta/volto
  }
}

function showLock() {
  $('unlock-pwd').value = '';
  $('unlock-error').hidden = true;
  const parts = [];
  if (S.meta.driveLinked) parts.push(`Ultima sincronizzazione: ${fmtDate(S.meta.lastSync)}`);
  if (!navigator.onLine) parts.push('Offline: verrà usata la copia locale');
  $('lock-info').textContent = parts.join(' · ');
  $('btn-bio').hidden = !bioRec;
  show('screen-lock');
  if (!bioRec) setTimeout(() => $('unlock-pwd').focus(), 50);
}

bindMeter($('create-pwd'), $('create-meter'));
bindMeter($('c-new'), $('c-meter'));

$('form-create').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pwd = $('create-pwd').value;
  if (pwd !== $('create-pwd2').value) return toast('Le password non coincidono');
  if (pwd.length < 10) return toast('Usa almeno 10 caratteri');
  const wantDrive = $('create-drive').checked && drive.isConfigured();
  // il popup Google va aperto subito, dentro il click
  const auth = wantDrive ? drive.authorize().then(() => true, (err) => { toast(err.message); return false; }) : Promise.resolve(false);

  const btn = e.submitter || $('form-create').querySelector('[type=submit]');
  btn.disabled = true;
  try {
    S.kdf = C.newKdf();
    S.key = await C.deriveKey(pwd, S.kdf);
    S.data = V.emptyVault();
    await persistLocal({ dirty: false });
    $('form-create').reset();
    const linked = await auth;
    S.meta = await store.patchMeta({ driveLinked: linked });
    enterMain();
    if (linked) sync({ password: pwd });
  } finally {
    btn.disabled = false;
  }
});

$('btn-restore').addEventListener('click', async () => {
  try {
    await drive.authorize();
    toast('Cerco il vault su Google Drive…');
    const file = await drive.findFile();
    if (!file) return toast('Nessun vault CryptoPwd trovato su questo Google Drive', 4000);
    const blob = await drive.download(file.id);
    let opened = null;
    const pw = await askPassword('Password principale', 'Inserisci la password principale del vault salvato su Google Drive.', async (v) => {
      try { opened = await C.openWithPassword(v, blob); return null; } catch (e) { if (e instanceof C.WrongPasswordError) return 'Password errata'; throw e; }
    });
    if (pw === null) return;
    Object.assign(S, { key: opened.key, kdf: opened.kdf, data: V.normalize(opened.data) });
    await store.set('vault', blob);
    // attPending: la prima sincronizzazione deve scaricare anche gli allegati
    S.meta = await store.patchMeta({ driveLinked: true, fileId: file.id, remoteModified: file.modifiedTime, lastSync: Date.now(), dirty: false, attPending: true });
    enterMain();
    toast('Vault ripristinato');
    sync();
  } catch (e) {
    toast(e.message, 4000);
  }
});

function unlockError(msg) {
  $('unlock-error').textContent = msg;
  $('unlock-error').hidden = false;
}

// Apre il vault locale con la password principale. Il token Google va richiesto subito,
// nel gesto dell'utente (popup): per questo parte prima della derivazione della chiave.
async function openVault(pwd) {
  const wantSync = S.meta.driveLinked && drive.isConfigured() && navigator.onLine && !drive.hasValidToken();
  const auth = wantSync ? drive.authorize().catch(() => null) : Promise.resolve(null);
  const blob = await store.get('vault');
  const { key, kdf, data } = await C.openWithPassword(pwd, blob);
  Object.assign(S, { key, kdf, data: V.normalize(data) });
  $('unlock-pwd').value = '';
  enterMain();
  await auth;
  sync({ password: pwd });
}

$('form-unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('btn-unlock');
  btn.disabled = true;
  btn.textContent = 'Sblocco…';
  $('unlock-error').hidden = true;
  try {
    await openVault($('unlock-pwd').value);
  } catch (err) {
    unlockError(err instanceof C.WrongPasswordError ? 'Password errata' : err.message);
    $('unlock-pwd').select();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sblocca';
  }
});

// Sblocco con impronta digitale o volto (vedi js/biometric.js)
let bioBusy = false;
async function unlockWithBio({ auto = false } = {}) {
  if (!bioRec || bioBusy || S.key) return;
  bioBusy = true;
  const btn = $('btn-bio');
  btn.disabled = true;
  $('unlock-error').hidden = true;
  try {
    const pwd = await bio.unlock(bioRec);
    try {
      await openVault(pwd);
    } catch (err) {
      if (!(err instanceof C.WrongPasswordError)) throw err;
      // La password principale è stata cambiata (es. su un altro dispositivo): quella salvata non vale più.
      await disableBio();
      $('btn-bio').hidden = true;
      unlockError('La password principale è cambiata: inseriscila qui. Poi potrai riattivare impronta o volto nelle Impostazioni.');
      $('unlock-pwd').focus();
    }
  } catch (err) {
    // all'avvio alcuni browser rifiutano la richiesta senza un tocco: resta il pulsante
    if (!auto && !(err instanceof bio.BioCancelledError)) unlockError(err.message);
  } finally {
    bioBusy = false;
    btn.disabled = false;
  }
}
$('btn-bio').addEventListener('click', () => unlockWithBio());

function enterMain() {
  S.lastActivity = Date.now();
  $('search').value = '';
  renderList();
  refreshSyncIdle();
  show('screen-main');
}

function lock() {
  if (!S.key) return;
  S.key = null;
  S.kdf = null;
  S.data = null;
  closeAllDialogs();
  $('list').replaceChildren();
  $('subj-chips').replaceChildren();
  $('cat-chips').replaceChildren();
  $('m-tree').replaceChildren();
  $('t-list').replaceChildren();
  $('d-att-list').replaceChildren();
  $('e-att-list').replaceChildren();
  editAttachments = [];
  $('form-edit').reset();
  for (const id of ['d-pwd', 'd-user', 'd-notes', 'd-title', 'd-path']) $(id).textContent = '';
  $('d-cards').replaceChildren();
  $('e-cards').replaceChildren();
  document.body.classList.remove('peek');
  setShield(false);
  showLock();
}

// Blocco automatico
for (const ev of ['pointerdown', 'keydown', 'scroll', 'touchstart']) {
  document.addEventListener(ev, () => (S.lastActivity = Date.now()), { passive: true, capture: true });
}
function autolockMs() {
  return (Number(S.meta.autolockMin) || DEFAULT_AUTOLOCK_MIN) * 60_000;
}
setInterval(() => {
  if (S.key && Date.now() - S.lastActivity > autolockMs()) lock();
}, 10_000);

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    S.hiddenAt = Date.now();
  } else if (S.key) {
    if (Date.now() - Math.max(S.hiddenAt, S.lastActivity) > autolockMs()) lock();
    else sync();
  }
});
window.addEventListener('online', () => { if (S.key) sync(); });
window.addEventListener('offline', () => { if (S.key && S.meta.driveLinked) setSync('offline'); });

$('btn-lock').addEventListener('click', lock);

// =====================================================================
// Modalità riservata (schermo osservato, es. desktop remoto collegato)
// =====================================================================
const MASK = '••••••••';
function isPrivate() { return !!S.meta.privacy; }

function applyPrivacy() {
  const on = isPrivate();
  document.body.classList.toggle('privacy', on);
  $('btn-privacy').setAttribute('aria-pressed', String(on));
  $('btn-privacy').title = on ? 'Modalità riservata attiva (tocca per disattivare)' : 'Attiva modalità riservata';
  $('s-privacy').checked = on;
  if (!on) setShield(false);
  if (S.data) renderList();
  if ($('dlg-detail').open) maskDetail();
  if ($('dlg-edit').open) for (const n of $('form-edit').querySelectorAll('#e-pwd, .c-cvc, .c-pin')) n.type = 'password';
}
async function setPrivacy(on) {
  S.meta = await store.patchMeta({ privacy: on });
  applyPrivacy();
  toast(on ? '🛡 Modalità riservata attiva' : 'Modalità riservata disattivata');
}
$('btn-privacy').addEventListener('click', () => setPrivacy(!isPrivate()));
$('s-privacy').addEventListener('change', () => setPrivacy($('s-privacy').checked));

let toastOnceAt = 0;
function toastOnce(msg) {
  if (Date.now() - toastOnceAt > 3000) { toastOnceAt = Date.now(); toast(msg); }
}

// Nasconde tutto quando la finestra perde il focus o va in background.
function setShield(on) {
  const show = on && isPrivate() && !!S.key;
  document.body.classList.toggle('shielded', show);
  $('shield').hidden = !show;
}
window.addEventListener('blur', () => setShield(true));
window.addEventListener('focus', () => setShield(false));
document.addEventListener('visibilitychange', () => { if (document.hidden) setShield(true); });
$('shield').addEventListener('pointerdown', () => setShield(false));

// Doppio Esc = blocco immediato (in qualsiasi modalità).
let lastEsc = 0;
document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Escape' || !S.key) return;
  const now = Date.now();
  if (now - lastEsc < 600) { lastEsc = 0; lock(); }
  else lastEsc = now;
}, true);
$('btn-sync').addEventListener('click', () => {
  if (!S.meta.driveLinked) return openSettings();
  sync({ interactive: true });
});

// =====================================================================
// Soggetti e categorie
// =====================================================================
const NONE = '__none';          // "Senza soggetto" / "Senza categoria"
const ALL = null;
S.filter = { subjectId: ALL, categoryId: ALL };

// Soggetto e categoria "effettivi" di una voce (gestisce riferimenti a elementi eliminati).
function placeOf(e) {
  const subj = V.findLive(S.data, 'subjects', e.subjectId);
  const subjectId = subj ? subj.id : NONE;
  const cat = V.findLive(S.data, 'categories', e.categoryId);
  const categoryId = cat && cat.subjectId === subjectId ? cat.id : NONE;
  return { subjectId, categoryId, subj, cat };
}

function subjectName(id) {
  return id === NONE ? 'Senza soggetto' : V.findLive(S.data, 'subjects', id)?.name || 'Senza soggetto';
}
function categoryName(id) {
  return id === NONE ? 'Senza categoria' : V.findLive(S.data, 'categories', id)?.name || 'Senza categoria';
}
function pathText(e) {
  const p = placeOf(e);
  if (p.subjectId === NONE) return p.categoryId === NONE ? '' : categoryName(p.categoryId);
  return p.categoryId === NONE ? subjectName(p.subjectId) : `${subjectName(p.subjectId)} › ${categoryName(p.categoryId)}`;
}

function validateName(coll, subjectId, exceptId) {
  return async (v) => {
    const name = v.trim();
    if (!name) return 'Inserisci un nome';
    const list = coll === 'subjects' ? V.subjectsOf(S.data) : V.categoriesOf(S.data, subjectId);
    if (list.some((x) => x.id !== exceptId && x.name.trim().toLowerCase() === name.toLowerCase())) return 'Esiste già con questo nome';
    return null;
  };
}

async function createSubject() {
  const name = await askInput({ title: 'Nuovo soggetto', msg: 'Es. il tuo nome, un familiare, la tua azienda.', type: 'text', placeholder: 'Nome del soggetto', validate: validateName('subjects') });
  if (name === null) return null;
  const s = V.upsertItem(S.data, 'subjects', { name: name.trim() });
  await afterOrgChange();
  return s;
}

async function createCategory(subjectId) {
  // suggerisce i nomi già usati negli altri soggetti
  const here = new Set(V.categoriesOf(S.data, subjectId).map((c) => c.name.toLowerCase()));
  const suggestions = [...new Set(S.data.categories.filter((c) => !c.deleted && !here.has(c.name.toLowerCase())).map((c) => c.name))].sort();
  const name = await askInput({
    title: 'Nuova categoria', msg: `Categoria per "${subjectName(subjectId)}". Es. Banca, Email, Social, Lavoro.`,
    type: 'text', placeholder: 'Nome della categoria', suggestions, validate: validateName('categories', subjectId),
  });
  if (name === null) return null;
  const c = V.upsertItem(S.data, 'categories', { subjectId, name: name.trim() });
  await afterOrgChange();
  return c;
}

async function renameItem(coll, item) {
  const name = await askInput({
    title: coll === 'subjects' ? 'Rinomina soggetto' : 'Rinomina categoria', type: 'text', value: item.name,
    validate: validateName(coll, item.subjectId, item.id),
  });
  if (name === null || name.trim() === item.name) return;
  V.upsertItem(S.data, coll, { id: item.id, name: name.trim() });
  await afterOrgChange();
}

async function removeItem(coll, item) {
  const u = V.usage(S.data, coll === 'subjects' ? { subjectId: item.id } : { categoryId: item.id });
  if (u.entries || u.categories) {
    const parts = [];
    if (u.categories) parts.push(`${u.categories} categori${u.categories === 1 ? 'a' : 'e'}`);
    if (u.entries) parts.push(`${u.entries} password`);
    return toast(`Impossibile eliminare "${item.name}": contiene ${parts.join(' e ')}. Spostale o eliminale prima.`, 4500);
  }
  const what = coll === 'subjects' ? 'il soggetto' : 'la categoria';
  if (!(await confirmBox('Eliminare?', `Vuoi eliminare ${what} "${item.name}"?`, 'Elimina'))) return;
  V.deleteItem(S.data, coll, item.id);
  if (S.filter.subjectId === item.id) S.filter = { subjectId: ALL, categoryId: ALL };
  if (S.filter.categoryId === item.id) S.filter.categoryId = ALL;
  await afterOrgChange();
}

async function afterOrgChange() {
  await persistLocal();
  renderList();
  if ($('dlg-manage').open) renderManage();
  scheduleSync();
}

// ---- Pannello di gestione ----
function openManage() {
  renderManage();
  openDialog($('dlg-manage'));
}
function renderManage() {
  const subjects = V.subjectsOf(S.data);
  $('m-empty').hidden = subjects.length > 0;
  const actions = (coll, item) => [
    el('button', { class: 'icon-btn', type: 'button', title: 'Rinomina', ariaLabel: `Rinomina ${item.name}`, textContent: '✎', onclick: () => renameItem(coll, item) }),
    el('button', { class: 'icon-btn', type: 'button', title: 'Elimina', ariaLabel: `Elimina ${item.name}`, textContent: '🗑', onclick: () => removeItem(coll, item) }),
  ];
  $('m-tree').replaceChildren(...subjects.map((s) => {
    const cats = V.categoriesOf(S.data, s.id);
    return el('li', { class: 'tree-subject' },
      el('div', { class: 'tree-row' },
        el('span', { class: 'tree-name strong', textContent: s.name }),
        el('span', { class: 'muted small', textContent: `${V.usage(S.data, { subjectId: s.id }).entries} pwd` }),
        ...actions('subjects', s)),
      el('ul', { class: 'tree-cats' },
        ...cats.map((c) => el('li', { class: 'tree-row' },
          el('span', { class: 'tree-name', textContent: c.name }),
          el('span', { class: 'muted small', textContent: `${V.usage(S.data, { categoryId: c.id }).entries} pwd` }),
          ...actions('categories', c))),
        el('li', {}, el('button', { class: 'link-btn', type: 'button', textContent: '+ Categoria', onclick: () => createCategory(s.id) }))));
  }));
}
$('btn-manage').addEventListener('click', openManage);
$('s-manage').addEventListener('click', () => { $('dlg-settings').close(); openManage(); });
$('m-add-subject').addEventListener('click', () => createSubject());

// ---- Filtri a chip ----
function chip(label, active, onclick, extraClass = '') {
  return el('button', { class: `fchip ${active ? 'active' : ''} ${extraClass}`, type: 'button', role: 'tab', ariaSelected: String(active), textContent: label, onclick });
}

function renderFilters() {
  const f = S.filter;
  const entries = V.liveEntries(S.data);
  const orphanSubj = entries.some((e) => placeOf(e).subjectId === NONE);
  const subjects = V.subjectsOf(S.data);
  if (f.subjectId && f.subjectId !== NONE && !subjects.some((s) => s.id === f.subjectId)) S.filter = { subjectId: ALL, categoryId: ALL };
  if (f.subjectId === NONE && !orphanSubj) S.filter = { subjectId: ALL, categoryId: ALL };

  const setSubj = (id) => { $('search').value = ''; S.filter = { subjectId: id, categoryId: ALL }; renderList(); };
  $('subj-chips').replaceChildren(
    chip('Tutti', S.filter.subjectId === ALL, () => setSubj(ALL)),
    ...subjects.map((s) => chip(s.name, S.filter.subjectId === s.id, () => setSubj(s.id))),
    ...(orphanSubj && subjects.length ? [chip('Senza soggetto', S.filter.subjectId === NONE, () => setSubj(NONE), 'ghost')] : []),
    chip('+ Soggetto', false, async () => { const s = await createSubject(); if (s) setSubj(s.id); }, 'add'),
  );

  const sid = S.filter.subjectId;
  const showCats = sid && sid !== NONE;
  $('cat-chips').hidden = !showCats;
  if (!showCats) return;
  const cats = V.categoriesOf(S.data, sid);
  if (S.filter.categoryId && S.filter.categoryId !== NONE && !cats.some((c) => c.id === S.filter.categoryId)) S.filter.categoryId = ALL;
  const orphanCat = entries.some((e) => { const p = placeOf(e); return p.subjectId === sid && p.categoryId === NONE; });
  const setCat = (id) => { $('search').value = ''; S.filter.categoryId = id; renderList(); };
  $('cat-chips').replaceChildren(
    chip('Tutte', S.filter.categoryId === ALL, () => setCat(ALL)),
    ...cats.map((c) => chip(c.name, S.filter.categoryId === c.id, () => setCat(c.id))),
    ...(orphanCat && cats.length ? [chip('Senza categoria', S.filter.categoryId === NONE, () => setCat(NONE), 'ghost')] : []),
    chip('+ Categoria', false, async () => { const c = await createCategory(sid); if (c) setCat(c.id); }, 'add'),
  );
}

// =====================================================================
// Carte di credito
// =====================================================================
const isCard = (e) => e?.kind === 'card';
const digitsOf = (s) => String(s || '').replace(/\D/g, '');
const last4 = (num) => digitsOf(num).slice(-4);
const fmtCardNumber = (num) => (/^[\d\s-]+$/.test(num || '') ? digitsOf(num).replace(/(\d{4})(?=\d)/g, '$1 ') : num || '');
function cardBrand(num) {
  const n = digitsOf(num);
  if (/^4/.test(n)) return 'Visa';
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(n)) return 'Mastercard';
  if (/^3[47]/.test(n)) return 'Amex';
  if (/^(50|5[6-9]|6[37])/.test(n)) return 'Maestro';
  return 'Carta';
}
// "1227", "12/2027", "12-27" -> "12/27"; altrimenti il testo così com'è
function fmtExpiry(v) {
  const m = String(v || '').trim().match(/^(\d{1,2})\s*[/.\-]?\s*(?:20)?(\d{2})$/);
  if (!m || +m[1] < 1 || +m[1] > 12) return String(v || '').trim();
  return `${m[1].padStart(2, '0')}/${m[2]}`;
}
function isExpired(exp) {
  const m = fmtExpiry(exp).match(/^(\d{2})\/(\d{2})$/);
  if (!m) return false;
  const now = new Date();
  const y = 2000 + +m[2];
  return y < now.getFullYear() || (y === now.getFullYear() && +m[1] < now.getMonth() + 1);
}
const cardsOf = (e) => e?.cards || [];
// "Visa •••• 1111 · 09/30" (o il nome dato alla carta al posto del circuito)
function cardSummary(c) {
  const parts = [`${c.label || cardBrand(c.number)}${last4(c.number) ? ` •••• ${last4(c.number)}` : ''}`];
  if (c.expiry) parts.push(fmtExpiry(c.expiry));
  return parts.join(' · ');
}

// =====================================================================
// Ricerca: cerca in tutte le voci (ignora i filtri) e in quasi tutti i campi.
// Le parole devono esserci tutte; spazi, trattini e punti non contano
// (es. "4111 1111" trova "4111-1111-..." e un IBAN scritto con o senza spazi).
// Password, CVC e PIN non vengono mai cercati.
// =====================================================================
const norm = (s) => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const compact = (s) => s.replace(/[\s.\-/_]/g, '');
function searchText(e, p) {
  return norm([
    e.title, e.username, e.url, e.notes,
    ...cardsOf(e).flatMap((c) => [c.label, c.holder, c.number, c.expiry, `carta ${cardBrand(c.number)}`]),
    p.subjectId !== NONE ? subjectName(p.subjectId) : '',
    p.categoryId !== NONE ? categoryName(p.categoryId) : '',
    ...(e.attachments || []).map((a) => a.name),
  ].filter(Boolean).join('\u0001'));
}
function matchesSearch(e, p, q) {
  const hay = searchText(e, p);
  const hayC = compact(hay);
  const words = norm(q).split(/\s+/).filter(Boolean);
  if (words.every((w) => hay.includes(w) || (compact(w) && hayC.includes(compact(w))))) return true;
  const qc = compact(norm(q));
  return qc.length >= 3 && hayC.includes(qc);
}

// =====================================================================
// Elenco voci
// =====================================================================
function renderList() {
  if (!S.data) return;
  renderFilters();
  const q = $('search').value.trim();
  // con una ricerca in corso si cerca ovunque, non solo nel soggetto/categoria selezionati
  const f = q ? { subjectId: ALL, categoryId: ALL } : S.filter;
  document.querySelector('.filters').classList.toggle('searching', !!q);
  const byTitle = (a, b) => (a.title || '').localeCompare(b.title || '', 'it', { sensitivity: 'base' });
  // Ordinamento scelto (salvato sul dispositivo): per nome, raggruppato; per data di creazione, elenco unico.
  const sortBy = ['name', 'newest', 'oldest'].includes(S.meta?.sortBy) ? S.meta.sortBy : 'name';
  $('sort').value = sortBy;
  const byName = sortBy === 'name';
  const created = (e) => e.createdAt || e.updatedAt || 0;

  const items = V.liveEntries(S.data)
    .map((e) => ({ e, p: placeOf(e) }))
    .filter(({ p }) => f.subjectId === ALL || p.subjectId === f.subjectId)
    .filter(({ p }) => f.categoryId === ALL || p.categoryId === f.categoryId)
    .filter(({ e, p }) => !q || matchesSearch(e, p, q));

  // Raggruppa: con "Tutti" per soggetto › categoria, con un soggetto per categoria.
  const groupKey = ({ p }) => (!byName || f.categoryId !== ALL ? '' : f.subjectId === ALL ? `${p.subjectId}|${p.categoryId}` : p.categoryId);
  const groupLabel = ({ p }) => {
    if (f.subjectId === ALL) {
      if (p.subjectId === NONE) return p.categoryId === NONE ? 'Senza soggetto' : categoryName(p.categoryId);
      return p.categoryId === NONE ? subjectName(p.subjectId) : `${subjectName(p.subjectId)} › ${categoryName(p.categoryId)}`;
    }
    return categoryName(p.categoryId);
  };
  const sortKey = (x) => {
    const sn = x.p.subjectId === NONE ? '￿' : subjectName(x.p.subjectId).toLowerCase();
    const cn = x.p.categoryId === NONE ? '￿' : categoryName(x.p.categoryId).toLowerCase();
    return f.subjectId === ALL ? `${sn}\u0000${cn}` : cn;
  };
  if (byName) items.sort((a, b) => (f.categoryId === ALL ? sortKey(a).localeCompare(sortKey(b), 'it') : 0) || byTitle(a.e, b.e));
  else items.sort((a, b) => (sortBy === 'newest' ? created(b.e) - created(a.e) : created(a.e) - created(b.e)) || byTitle(a.e, b.e));

  // senza intestazioni di gruppo (ordine per data) la posizione si mostra su ogni voce
  const itemPath = ({ e, p }) => {
    if (byName || f.categoryId !== ALL) return '';
    if (f.subjectId === ALL) return pathText(e);
    return p.categoryId === NONE ? '' : categoryName(p.categoryId);
  };
  const nodes = [];
  let lastGroup;
  // intestazioni solo se aiutano: più gruppi, oppure un unico gruppo con un nome vero
  const groups = new Set(items.map(groupKey));
  const multipleGroups = groups.size > 1 || (items.length > 0 && ![NONE, `${NONE}|${NONE}`].includes([...groups][0]));
  for (const it of items) {
    const g = groupKey(it);
    if (g && g !== lastGroup && multipleGroups) nodes.push(el('li', { class: 'group', textContent: groupLabel(it) }));
    lastGroup = g;
    const e = it.e;
    nodes.push(el('li', { class: 'item' },
      el('button', { class: 'item-main', type: 'button', onclick: () => openDetail(e.id) },
        el('span', { class: 'avatar', textContent: isCard(e) ? '💳' : (e.title || '?').trim().charAt(0).toUpperCase() }),
        el('span', { class: 'item-text' },
          el('span', { class: 'item-title', textContent: (e.title || '(senza nome)') + (!isCard(e) && cardsOf(e).length ? ' 💳' : '') + ((e.attachments || []).length ? ' 📎' : '') }),
          el('span', { class: 'item-sub', textContent: isCard(e) ? (isPrivate() ? MASK : cardsOf(e).map(cardSummary).join(' + ')) : e.username ? (isPrivate() ? MASK : e.username) : '' }),
          ...(itemPath(it) ? [el('span', { class: 'item-path', textContent: itemPath(it) })] : []))),
      ...(safeUrl(e.url) ? [el('a', {
        class: 'icon-btn', href: safeUrl(e.url), target: '_blank', rel: 'noopener noreferrer',
        title: 'Apri link', ariaLabel: `Apri link di ${e.title}`, textContent: '↗',
      })] : []),
      ...(e.username ? [el('button', {
        class: 'icon-btn', type: 'button', title: 'Copia utente', ariaLabel: `Copia utente di ${e.title}`, textContent: '👤',
        onclick: () => copy(e.username, 'Utente'),
      })] : []),
      ...(isCard(e) ? (cardsOf(e)[0]?.number ? [el('button', {
        class: 'icon-btn', type: 'button', title: 'Copia numero carta', ariaLabel: `Copia numero carta di ${e.title}`, textContent: '💳',
        onclick: () => copy(digitsOf(cardsOf(e)[0].number) || cardsOf(e)[0].number, 'Numero carta'),
      })] : []) : !e.password ? [] : [el('button', {
        class: 'icon-btn', type: 'button', title: 'Copia password', ariaLabel: `Copia password di ${e.title}`, textContent: '🔑',
        onclick: () => copy(e.password, 'Password'),
      })])));
  }
  $('list').replaceChildren(...nodes);

  const total = V.liveEntries(S.data).length;
  const trashed = V.trashedEntries(S.data).length;
  $('trash-count').textContent = String(trashed);
  $('btn-trash').hidden = trashed === 0;
  if ($('dlg-trash').open) renderTrash();
  $('empty').hidden = items.length > 0;
  $('empty').textContent = !total
    ? 'Nessuna password salvata. Tocca + per aggiungerne una.'
    : q ? 'Nessun risultato.' : 'Nessuna password in questa sezione. Tocca + per aggiungerne una.';
}
$('search').addEventListener('input', renderList);
$('sort').addEventListener('change', async () => {
  S.meta = await store.patchMeta({ sortBy: $('sort').value });
  renderList();
});

// =====================================================================
// Dettaglio
// =====================================================================
let currentId = null;

function findEntry(id) {
  return S.data.entries.find((e) => e.id === id && !e.deleted && !e.trashedAt);
}

function openDetail(id) {
  const e = findEntry(id);
  if (!e) return;
  currentId = id;
  $('d-title').textContent = e.title;
  $('d-path').textContent = pathText(e);
  $('d-path').hidden = !pathText(e);
  $('d-user-row').hidden = !e.username;
  $('d-pwd').dataset.shown = '';
  $('d-pwd-row').hidden = !e.password;
  $('d-cards-row').hidden = !cardsOf(e).length;
  const url = safeUrl(e.url);
  $('d-url').textContent = e.url || '';
  if (url) { $('d-url').href = url; $('d-open').href = url; } else { $('d-url').removeAttribute('href'); $('d-open').removeAttribute('href'); }
  $('d-open').hidden = !url;
  $('d-url-row').hidden = !e.url;
  $('d-notes-row').hidden = !e.notes;
  const atts = e.attachments || [];
  $('d-att-row').hidden = !atts.length;
  $('d-att-list').replaceChildren(...atts.map((a) => attRow(a, [
    el('button', { class: 'btn small-btn', type: 'button', textContent: 'Apri', onclick: () => openAttachment(a, 'open') }),
    el('button', { class: 'icon-btn', type: 'button', title: 'Scarica', ariaLabel: `Scarica ${a.name}`, textContent: '⬇', onclick: () => openAttachment(a, 'download') }),
  ])));
  $('d-updated').textContent = `${e.createdAt ? `Creato: ${fmtDate(e.createdAt)} · ` : ''}Modificato: ${fmtDate(e.updatedAt)}`;
  maskDetail();
  openDialog($('dlg-detail'));
}

// Campi del dettaglio: la password è sempre coperta finché non si tocca 👁,
// utente e note solo in modalità riservata.
const plainText = (v) => (isPrivate() ? MASK : v || '');

// Ricopre i campi del dettaglio e ridisegna le carte.
function maskDetail() {
  const e = currentId && S.data && findEntry(currentId);
  if (!e) return;
  $('d-user').textContent = plainText(e.username);
  $('d-notes').textContent = plainText(e.notes);
  $('d-pwd').textContent = MASK;
  $('d-pwd').dataset.shown = '';
  renderDetailCards(e);
}

// Modalità riservata: il valore si vede solo finché si tiene premuto.
// reveal() dà il testo in chiaro, masked() quello coperto.
function holdToReveal(trigger, target, reveal, masked) {
  trigger.addEventListener('pointerdown', (ev) => {
    if (!isPrivate()) return;
    ev.preventDefault();
    const txt = reveal();
    if (txt == null) return;
    target.textContent = txt;
    target.classList.add('peeking');
    const hide = () => {
      target.classList.remove('peeking');
      target.textContent = masked();
      target.dataset.shown = '';
      window.removeEventListener('pointerup', hide);
      window.removeEventListener('pointercancel', hide);
      window.removeEventListener('blur', hide);
    };
    window.addEventListener('pointerup', hide);
    window.addEventListener('pointercancel', hide);
    window.addEventListener('blur', hide);
  });
}
// 👁: un tocco mostra/nasconde (fuori dalla modalità riservata), tenere premuto in modalità riservata.
function bindReveal(btn, target, reveal, masked) {
  holdToReveal(btn, target, reveal, masked);
  holdToReveal(target, target, reveal, masked);
  btn.addEventListener('click', () => {
    if (isPrivate()) return toastOnce('Tieni premuto per vedere');
    const txt = reveal();
    if (txt == null) return;
    if (target.dataset.shown) { target.textContent = masked(); target.dataset.shown = ''; }
    else { target.textContent = txt; target.dataset.shown = '1'; }
  });
}
const entryField = (f) => () => findEntry(currentId)?.[f];
bindReveal($('d-reveal'), $('d-pwd'), entryField('password'), () => MASK);
holdToReveal($('d-user'), $('d-user'), entryField('username'), () => plainText(findEntry(currentId)?.username));
holdToReveal($('d-notes'), $('d-notes'), entryField('notes'), () => plainText(findEntry(currentId)?.notes));

$('dlg-detail').addEventListener('click', (ev) => {
  const b = ev.target.closest('[data-copy]');
  if (!b) return;
  const e = findEntry(currentId);
  const f = b.dataset.copy;
  copy(e[f], { username: 'Utente', password: 'Password', url: 'Link' }[f]);
});
$('dlg-detail').addEventListener('close', () => { $('d-pwd').textContent = MASK; $('d-pwd').dataset.shown = ''; $('d-cards').replaceChildren(); });

// Carte nel dettaglio: numero coperto (si vedono le ultime 4 cifre), CVC e PIN coperti.
function renderDetailCards(e) {
  const blocks = cardsOf(e).map((c) => {
    const rows = [];
    const row = (label, valNode, ...btns) => rows.push(el('div', { class: 'field' }, el('span', { class: 'lbl', textContent: label }), valNode, ...btns));
    const copyBtn = (what, value) => el('button', { class: 'icon-btn', type: 'button', ariaLabel: `Copia ${what.toLowerCase()}`, title: `Copia ${what.toLowerCase()}`, textContent: '⧉', onclick: () => copy(value, what) });
    const plain = (label, value, mono = false) => {
      const v = el('span', { class: `val sec${mono ? ' mono' : ''}`, textContent: plainText(value) });
      holdToReveal(v, v, () => value, () => plainText(value));
      return v;
    };
    const secret = (label, value, masked) => {
      const v = el('span', { class: 'val mono sec', textContent: masked() });
      const btn = el('button', { class: 'icon-btn sec', type: 'button', ariaLabel: `Mostra ${label}`, textContent: '👁' });
      bindReveal(btn, v, () => value, masked);
      row(label, v, btn, copyBtn(label, label === 'Numero' ? digitsOf(c.number) || c.number : value));
    };
    if (c.holder) row('Titolare', plain('Titolare', c.holder), copyBtn('Titolare', c.holder));
    if (c.number) secret('Numero', fmtCardNumber(c.number), () => (!isPrivate() && last4(c.number) ? `•••• ${last4(c.number)}` : MASK));
    if (c.expiry) row('Scadenza', plain('Scadenza', fmtExpiry(c.expiry), true), copyBtn('Scadenza', fmtExpiry(c.expiry)));
    if (c.cvc) secret('CVC', c.cvc, () => MASK);
    if (c.pin) secret('PIN', c.pin, () => MASK);
    // Tendina: chiusa si vede solo il riepilogo, toccando si apre con i dati.
    const title = el('summary', { class: 'card-title' }, `💳 ${isPrivate() ? (c.label || 'Carta') : cardSummary(c)}`,
      ...(isExpired(c.expiry) ? [el('span', { class: 'muted', textContent: ' · scaduta' })] : []));
    return el('details', { class: 'card-block' }, title, el('div', { class: 'card-body' }, ...rows));
  });
  $('d-cards').replaceChildren(...blocks);
}

$('d-edit').addEventListener('click', () => { $('dlg-detail').close(); openEdit(currentId); });

// =====================================================================
// Modifica / nuova voce
// =====================================================================
const NEW = '__new';

function fillSubjectSelect(sel, selected) {
  sel.replaceChildren(
    el('option', { value: '', textContent: '— Nessuno —' }),
    ...V.subjectsOf(S.data).map((s) => el('option', { value: s.id, textContent: s.name })),
    el('option', { value: NEW, textContent: '+ Nuovo soggetto…' }),
  );
  sel.value = selected && V.findLive(S.data, 'subjects', selected) ? selected : '';
}

function fillCategorySelect(sel, subjectId, selected) {
  if (!subjectId) {
    sel.replaceChildren(el('option', { value: '', textContent: '— Scegli prima un soggetto —' }));
    sel.disabled = true;
    return;
  }
  sel.disabled = false;
  const cats = V.categoriesOf(S.data, subjectId);
  sel.replaceChildren(
    el('option', { value: '', textContent: '— Nessuna —' }),
    ...cats.map((c) => el('option', { value: c.id, textContent: c.name })),
    el('option', { value: NEW, textContent: '+ Nuova categoria…' }),
  );
  sel.value = selected && cats.some((c) => c.id === selected) ? selected : '';
}

// Coppia di menu Soggetto/Categoria (con "+ Nuovo…"), usata in Modifica e in Sposta.
function placePicker(subjSel, catSel, onChange = () => {}) {
  let lastS = '';
  let lastC = '';
  subjSel.addEventListener('change', async () => {
    if (subjSel.value === NEW) {
      const s = await createSubject();
      fillSubjectSelect(subjSel, s ? s.id : lastS);
    }
    if (subjSel.value !== lastS) fillCategorySelect(catSel, subjSel.value, null);
    lastS = subjSel.value;
    lastC = catSel.value;
    onChange();
  });
  catSel.addEventListener('change', async () => {
    if (catSel.value === NEW) {
      const c = await createCategory(subjSel.value);
      fillCategorySelect(catSel, subjSel.value, c ? c.id : lastC);
    }
    lastC = catSel.value;
    onChange();
  });
  return {
    set(subjectId, categoryId) {
      fillSubjectSelect(subjSel, subjectId);
      fillCategorySelect(catSel, subjSel.value, categoryId);
      lastS = subjSel.value;
      lastC = catSel.value;
      onChange();
    },
    value() {
      const sv = subjSel.value;
      const cv = catSel.value;
      return { subjectId: sv && sv !== NEW ? sv : null, categoryId: sv && cv && cv !== NEW ? cv : null };
    },
  };
}
const realId = (x) => (x && x !== NONE ? x : null);
const samePlace = (a, b) => a.subjectId === b.subjectId && a.categoryId === b.categoryId;
// posizione attuale di una voce, nel formato di placePicker().value()
function currentPlace(e) {
  const p = placeOf(e);
  return { subjectId: realId(p.subjectId), categoryId: realId(p.categoryId) };
}
function placeLabel({ subjectId, categoryId }) {
  if (!subjectId) return 'Senza soggetto';
  return categoryId ? `${subjectName(subjectId)} › ${categoryName(categoryId)}` : subjectName(subjectId);
}

const editPlace = placePicker($('e-subject'), $('e-category'));

// ---- Sposta in un altro soggetto / categoria (conferma tenendo premuto) ----
const movePlace = placePicker($('mv-subject'), $('mv-category'), () => {
  const e = findEntry(currentId);
  $('mv-ok').disabled = !e || samePlace(movePlace.value(), currentPlace(e));
});
function openMove() {
  const e = findEntry(currentId);
  if (!e) return;
  $('mv-name').textContent = e.title;
  $('mv-from').textContent = placeLabel(currentPlace(e));
  movePlace.set(currentPlace(e).subjectId, currentPlace(e).categoryId);
  $('dlg-detail').close();
  openDialog($('dlg-move'));
}
const moveStop = bindHold($('mv-ok'), async () => {
  const e = findEntry(currentId);
  const to = movePlace.value();
  if (!e || samePlace(to, currentPlace(e))) return;
  V.upsertEntry(S.data, { id: e.id, ...to });
  await persistLocal();
  $('dlg-move').close();
  renderList();
  scheduleSync();
  toast(`Spostata in ${placeLabel(to)}`);
});
$('dlg-move').addEventListener('close', moveStop);
$('d-move').addEventListener('click', openMove);

function openEdit(id) {
  const e = id ? findEntry(id) : null;
  currentId = e ? id : null;
  $('e-heading').textContent = e ? 'Modifica voce' : 'Nuova voce';
  // per una nuova voce propone il soggetto/categoria selezionati nei filtri
  if (e) editPlace.set(currentPlace(e).subjectId, currentPlace(e).categoryId);
  else editPlace.set(realId(S.filter.subjectId), realId(S.filter.categoryId));
  $('e-title').value = e?.title || '';
  $('e-user').value = e?.username || '';
  $('e-pwd').value = e?.password || '';
  $('e-pwd').type = 'password';
  $('e-cards').replaceChildren(...cardsOf(e).map((c) => cardEditor(c)));
  $('e-kind').value = isCard(e) ? 'card' : 'login';
  applyEditKind();
  $('e-url').value = e?.url || '';
  $('e-notes').value = e?.notes || '';
  $('e-delete').hidden = !e;
  editAttachments = [...(e?.attachments || [])];
  renderEditAttachments();
  editSnapshot = editState();
  openDialog($('dlg-edit'));
  $('e-title').focus();
}

$('btn-add').addEventListener('click', () => openEdit(null));

// Tipo di voce: password/account (con eventuali carte collegate, es. il conto in banca)
// oppure solo carta, senza utente e password.
function applyEditKind() {
  const card = $('e-kind').value === 'card';
  $('e-login-fields').hidden = card;
  $('e-title').placeholder = card ? 'es. Visa Intesa, Bancomat Poste…' : 'es. Banca, Gmail…';
  if (card && !$('e-cards').children.length) $('e-cards').append(cardEditor({}, true));
}
$('e-kind').addEventListener('change', applyEditKind);

// Riquadro di modifica di una carta (titolare, numero, scadenza, CVC, PIN).
function cardEditor(c, open = false) {
  const input = (cls, props) => el('input', { class: cls, autocomplete: 'off', spellcheck: false, ...props });
  const label = input('c-label', { maxLength: 100, placeholder: 'Nome carta (es. Visa, Bancomat) — facoltativo', value: c.label || '' });
  const holder = input('c-holder', { maxLength: 200, placeholder: 'Nome come sulla carta', autocapitalize: 'characters', value: c.holder || '' });
  const num = input('c-num', { maxLength: 40, inputMode: 'numeric', placeholder: '1234 5678 9012 3456', value: fmtCardNumber(c.number) });
  const exp = input('c-exp', { maxLength: 7, inputMode: 'numeric', placeholder: 'MM/AA', value: c.expiry || '' });
  const cvc = input('c-cvc', { type: 'password', maxLength: 4, inputMode: 'numeric', value: c.cvc || '' });
  const pin = input('c-pin', { type: 'password', maxLength: 12, inputMode: 'numeric', value: c.pin || '' });
  num.addEventListener('blur', () => { num.value = fmtCardNumber(num.value.trim()); });
  exp.addEventListener('blur', () => { exp.value = fmtExpiry(exp.value); });
  const reveal = el('button', { class: 'btn small-btn sec align-start', type: 'button', textContent: '👁 Mostra CVC e PIN' });
  bindFormReveal(reveal, [cvc, pin]);
  // Intestazione a tendina: tocca per aprire/chiudere i campi della carta.
  const sumText = el('span', { class: 'card-edit-sum' });
  const updateSum = () => {
    const n = digitsOf(num.value);
    sumText.textContent = `${label.value.trim() || (n ? cardBrand(n) : 'Nuova carta')}${last4(n) ? ` •••• ${last4(n)}` : ''}${exp.value.trim() ? ` · ${fmtExpiry(exp.value.trim())}` : ''}`;
  };
  [label, num, exp].forEach((i) => i.addEventListener('input', updateSum));
  updateSum();
  const toggle = el('button', { class: 'card-edit-toggle', type: 'button' }, el('span', { class: 'chev', textContent: '▸' }), el('span', { textContent: '💳' }), sumText);
  const body = el('div', { class: 'card-edit-body' },
    el('label', {}, 'Nome carta', label),
    el('label', {}, 'Titolare', holder),
    el('label', {}, 'Numero carta', el('span', { class: 'input-row' }, num,
      el('button', { class: 'icon-btn', type: 'button', title: 'Copia numero carta', ariaLabel: 'Copia numero carta', textContent: '⧉',
        onclick: () => copy(digitsOf(num.value) || num.value, 'Numero carta') }))),
    el('div', { class: 'three-col' }, el('label', {}, 'Scadenza', exp), el('label', {}, 'CVC', cvc), el('label', {}, 'PIN', pin)),
    reveal);
  const setOpen = (o) => { body.hidden = !o; box.classList.toggle('open', o); toggle.setAttribute('aria-expanded', String(o)); };
  toggle.addEventListener('click', () => setOpen(body.hidden));
  const box = el('fieldset', { class: 'card-edit', dataset: { id: c.id || V.newId() } },
    el('div', { class: 'card-edit-head' }, toggle,
      el('button', { class: 'icon-btn', type: 'button', title: 'Rimuovi carta', ariaLabel: 'Rimuovi carta', textContent: '✕',
        onclick: async () => {
          const what = label.value.trim() || (last4(num.value) ? `•••• ${last4(num.value)}` : 'questa carta');
          if (!(await confirmBox('Rimuovere la carta?', `"${what}" verrà tolta da questa voce quando premi Salva.`, 'Rimuovi'))) return;
          box.remove();
        } })),
    body);
  setOpen(open);
  return box;
}
// Carte come sono ora nel modulo (le carte lasciate vuote non si salvano).
function editCards() {
  return [...$('e-cards').querySelectorAll('.card-edit')].map((b) => {
    const v = (cls) => b.querySelector(cls).value.trim();
    return { id: b.dataset.id, label: v('.c-label'), holder: v('.c-holder'), number: fmtCardNumber(v('.c-num')), expiry: fmtExpiry(v('.c-exp')), cvc: v('.c-cvc'), pin: v('.c-pin') };
  }).filter((c) => c.label || c.holder || c.number || c.expiry || c.cvc || c.pin);
}
$('e-add-card').addEventListener('click', () => {
  const box = cardEditor({}, true);
  $('e-cards').append(box);
  box.querySelector('.c-holder').focus();
});

function renderEditAttachments() {
  $('e-att-list').replaceChildren(...editAttachments.map((a) => attRow(a, [
    el('button', { class: 'icon-btn', type: 'button', title: 'Rimuovi allegato', ariaLabel: `Rimuovi ${a.name}`, textContent: '✕',
      onclick: async () => {
        if (!(await confirmBox('Rimuovere l\'allegato?', `"${a.name}" verrà eliminato da questa password, su tutti i dispositivi, quando premi Salva.`, 'Rimuovi'))) return;
        editAttachments = editAttachments.filter((x) => x.id !== a.id);
        renderEditAttachments();
      } }),
  ])));
}

// Chiudendo la modifica (✕, Annulla, Esc) con cambiamenti non salvati si chiede conferma.
// Il blocco automatico invece chiude sempre senza chiedere (closeAllDialogs).
let editSnapshot = '';
function editState() {
  return JSON.stringify([...['e-subject', 'e-category', 'e-kind', 'e-title', 'e-user', 'e-pwd', 'e-url', 'e-notes'].map((id) => $(id).value), editCards(), editAttachments.map((a) => a.id)]);
}
async function closeEditSafely() {
  if (editState() !== editSnapshot
    && !(await confirmBox('Annullare le modifiche?', 'Le modifiche non salvate a questa password andranno perse.', 'Annulla modifiche'))) return;
  $('dlg-edit').close();
}
$('dlg-edit').addEventListener('cancel', (ev) => { ev.preventDefault(); closeEditSafely(); });
// Le foto vengono ridotte prima di cifrarle: lato lungo max 1600 px (documenti ancora leggibili),
// JPEG qualità 0,8. Una foto da 2-5 MB diventa di solito 200-400 kB. Si perdono anche i metadati
// EXIF (posizione GPS, modello del telefono). Se il risultato non è più piccolo si tiene l'originale.
const IMG_MAX_SIDE = 1600;
const IMG_QUALITY = 0.8;
const IMG_SHRINK_FROM = 300 * 1024;
const MAX_IMG_INPUT_BYTES = 50 * 1024 * 1024;

async function shrinkImage(file) {
  if (!/^image\/(jpeg|png|webp|heic|heif|bmp)$/i.test(file.type) || file.size < IMG_SHRINK_FROM) return file;
  let bmp;
  try {
    bmp = await createImageBitmap(file, { imageOrientation: 'from-image' });
  } catch {
    return file; // formato non decodificabile da questo browser (es. HEIC su Chrome)
  }
  try {
    const scale = Math.min(1, IMG_MAX_SIDE / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = el('canvas', { width: w, height: h });
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#fff'; // eventuali trasparenze (PNG) su sfondo bianco
    ctx.fillRect(0, 0, w, h);
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(bmp, 0, 0, w, h);
    const out = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', IMG_QUALITY));
    canvas.width = canvas.height = 0;
    if (!out || out.size >= file.size) return file;
    const name = file.name.replace(/\.[^.]*$/, '') + '.jpg';
    return new File([out], name, { type: 'image/jpeg', lastModified: file.lastModified });
  } finally {
    bmp.close?.();
  }
}

$('e-attach').addEventListener('click', () => $('e-att-file').click());
$('e-att-file').addEventListener('change', async (ev) => {
  const files = [...ev.target.files];
  ev.target.value = '';
  for (const orig of files) {
    const isImg = orig.type.startsWith('image/');
    if (orig.size > (isImg ? MAX_IMG_INPUT_BYTES : MAX_ATT_BYTES)) { toast(`"${orig.name}" è troppo grande`, 3500); continue; }
    try {
      const f = isImg ? await shrinkImage(orig) : orig;
      if (f.size > MAX_ATT_BYTES) { toast(`"${orig.name}" supera 10 MB`, 3500); continue; }
      if (f !== orig) toast(`Foto ridotta: ${fmtSize(orig.size)} → ${fmtSize(f.size)}`, 2500);
      const key = await C.newAttachmentKey();
      const data = await C.encryptBytes(key, new Uint8Array(await f.arrayBuffer()));
      const id = V.newId();
      await store.putAtt(id, data);
      editAttachments.push({ id, name: f.name, type: f.type || 'application/octet-stream', size: f.size, key, addedAt: Date.now() });
      renderEditAttachments();
    } catch (err) {
      toast(`Impossibile allegare "${f.name}": ${err.message}`, 4000);
    }
  }
});
// 👁 nel modulo: un tocco mostra/nasconde; in modalità riservata i campi personali
// del modulo sono visibili solo finché si tiene premuto.
function bindFormReveal(btn, inputs) {
  btn.addEventListener('click', () => {
    if (isPrivate()) return toastOnce('Tieni premuto per vedere');
    const show = inputs[0].type === 'password';
    for (const i of inputs) i.type = show ? 'text' : 'password';
  });
  btn.addEventListener('pointerdown', (ev) => {
    if (!isPrivate()) return;
    ev.preventDefault();
    document.body.classList.add('peek');
    for (const i of inputs) i.type = 'text';
    const hide = () => {
      document.body.classList.remove('peek');
      for (const i of inputs) i.type = 'password';
      for (const t of ['pointerup', 'pointercancel', 'blur']) window.removeEventListener(t, hide);
    };
    for (const t of ['pointerup', 'pointercancel', 'blur']) window.addEventListener(t, hide);
  });
}
bindFormReveal($('e-reveal'), [$('e-pwd')]);
$('e-gen').addEventListener('click', () => {
  const len = Math.min(64, Math.max(8, Number($('g-len').value) || 20));
  $('e-pwd').value = C.generatePassword(len, { lower: true, upper: true, digits: true, symbols: $('g-sym').checked });
  if (isPrivate()) toast('Password generata (nascosta)');
  else $('e-pwd').type = 'text';
});

$('form-edit').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const place = editPlace.value();
  const old = currentId ? findEntry(currentId) : null;
  if (old && !samePlace(place, currentPlace(old))
    && !(await holdBox('Spostare la password?', `"${old.title}" passerà da ${placeLabel(currentPlace(old))} a ${placeLabel(place)}.`, 'Tieni premuto per spostare'))) return;
  const card = $('e-kind').value === 'card';
  const cards = editCards();
  if (card && !cards.length) return toast('Inserisci i dati della carta');
  if (card && ($('e-user').value.trim() || $('e-pwd').value)
    && !(await confirmBox('Solo carta?', 'Con il tipo "Solo carta" utente e password di questa voce verranno cancellati. Per tenerli insieme alle carte scegli il tipo "Password / account".', 'Cancella utente e password'))) return;
  const entry = {
    ...place,
    kind: card ? 'card' : 'login',
    title: $('e-title').value.trim(),
    // "solo carta": niente utente e password
    username: card ? '' : $('e-user').value.trim(),
    password: card ? '' : $('e-pwd').value,
    cards,
    url: $('e-url').value.trim(),
    notes: $('e-notes').value,
    attachments: editAttachments,
  };
  const before = currentId ? findEntry(currentId)?.attachments || [] : [];
  if (currentId) entry.id = currentId;
  V.upsertEntry(S.data, entry);
  await queueAttDelete(before.filter((a) => !editAttachments.some((b) => b.id === a.id)).map((a) => a.id));
  editAttachments = [];
  await persistLocal();
  $('dlg-edit').close();
  renderList();
  scheduleSync();
  toast('Salvato');
});

$('e-delete').addEventListener('click', async () => {
  const e = findEntry(currentId);
  if (!e || !(await confirmBox('Spostare nel cestino?', `"${e.title}" verrà spostata nel cestino su tutti i dispositivi. Potrai ripristinarla dal cestino.`, 'Sposta nel cestino'))) return;
  V.trashEntry(S.data, currentId);
  await persistLocal();
  $('dlg-edit').close();
  renderList();
  scheduleSync();
  toast('Spostata nel cestino');
});

$('e-copy-user').addEventListener('click', () => copy($('e-user').value, 'Utente'));
$('e-copy-pwd').addEventListener('click', () => copy($('e-pwd').value, 'Password'));

// =====================================================================
// Cestino
// =====================================================================
function openTrash() {
  renderTrash();
  openDialog($('dlg-trash'));
}
function renderTrash() {
  const items = V.trashedEntries(S.data);
  $('t-empty').hidden = items.length > 0;
  $('t-empty-btn').disabled = items.length === 0;
  $('t-list').replaceChildren(...items.map((e) => el('li', { class: 'tree-subject' },
    el('div', { class: 'tree-row' },
      el('span', { class: 'tree-name' },
        el('span', { class: 'strong', textContent: e.title || '(senza nome)' }),
        el('br'),
        el('span', { class: 'muted small', textContent: [pathText(e), `eliminata il ${fmtDate(e.trashedAt)}`].filter(Boolean).join(' · ') })),
      el('button', { class: 'btn small-btn', type: 'button', textContent: 'Ripristina', onclick: () => restoreFromTrash(e.id) }),
      el('button', { class: 'icon-btn', type: 'button', title: 'Elimina definitivamente', ariaLabel: `Elimina definitivamente ${e.title}`, textContent: '✕', onclick: () => deleteForever(e) })))));
}
async function restoreFromTrash(id) {
  V.restoreEntry(S.data, id);
  await persistLocal();
  renderList();
  scheduleSync();
  toast('Password ripristinata');
}
async function deleteForever(e) {
  if (!(await confirmBox('Eliminare definitivamente?', `"${e.title}" verrà eliminata per sempre da tutti i dispositivi. Non si potrà recuperare.`, 'Elimina per sempre'))) return;
  V.deleteEntry(S.data, e.id);
  await queueAttDelete((e.attachments || []).map((a) => a.id));
  await persistLocal();
  renderList();
  scheduleSync();
  toast('Eliminata definitivamente');
}
const EMPTY_WORD = 'SVUOTA';
$('t-empty-btn').addEventListener('click', async () => {
  const n = V.trashedEntries(S.data).length;
  if (!n) return;
  const ok = await askInput({
    title: 'Svuotare il cestino?',
    msg: `${n === 1 ? 'La password nel cestino verrà eliminata' : `Le ${n} password nel cestino verranno eliminate`} per sempre da tutti i dispositivi e non si potranno più recuperare. Per confermare scrivi ${EMPTY_WORD}.`,
    type: 'text',
    placeholder: EMPTY_WORD,
    validate: async (v) => (v.trim().toUpperCase() === EMPTY_WORD ? null : `Scrivi ${EMPTY_WORD} per confermare`),
  });
  if (ok === null) return;
  const attIds = V.trashedEntries(S.data).flatMap((e) => (e.attachments || []).map((a) => a.id));
  const removed = V.emptyTrash(S.data);
  await queueAttDelete(attIds);
  await persistLocal();
  renderList();
  scheduleSync();
  toast(`Cestino svuotato: ${removed} password eliminate definitivamente`);
});
$('btn-trash').addEventListener('click', openTrash);
$('s-trash').addEventListener('click', () => { $('dlg-settings').close(); openTrash(); });

// =====================================================================
// Impostazioni
// =====================================================================
function renderSettingsDrive() {
  const linked = S.meta.driveLinked && drive.isConfigured();
  let txt;
  if (!drive.isConfigured()) txt = 'Client ID Google non configurato in js/config.js.';
  else if (!linked) txt = 'Non collegato. I dati restano solo su questo dispositivo.';
  else txt = `Collegato${drive.accountEmail() ? ` a ${drive.accountEmail()}` : ''} · ultima sincronizzazione: ${fmtDate(S.meta.lastSync)}${S.meta.dirty ? ' · modifiche in attesa' : ''}`;
  $('s-drive-status').textContent = txt;
  $('s-drive-connect').hidden = linked || !drive.isConfigured();
  $('s-sync-now').hidden = !linked;
  $('s-drive-disconnect').hidden = !linked;
}

async function renderSettingsBio() {
  const available = await bio.isAvailable();
  $('s-bio-box').hidden = !available && !bioRec;
  $('s-bio-on').hidden = !!bioRec;
  $('s-bio-off').hidden = !bioRec;
  $('s-bio-status').textContent = bioRec
    ? 'Attivo su questo dispositivo. La password principale resta valida: tienila comunque a portata, serve sugli altri dispositivi e se cambi telefono.'
    : 'Sblocca l\'app con impronta digitale o riconoscimento del volto invece di scrivere la password principale. Vale solo per questo dispositivo.';
}

async function saveBio(rec) {
  bioRec = rec;
  await store.set('bio', rec);
}
async function disableBio() {
  bioRec = null;
  await store.del('bio');
}

// Dopo un cambio della password principale: ricollega la passkey alla nuova password.
async function offerBioUpdate(newPwd) {
  if (!bioRec) return;
  const pending = { credId: bioRec.credId, salt: bioRec.salt };
  await disableBio(); // la password salvata non è più valida in ogni caso
  if (!(await confirmBox('Aggiornare impronta o volto?', 'La password principale è cambiata. Conferma con impronta o volto per continuare a usarli per sbloccare l\'app.', 'Conferma'))) {
    return toast('Sblocco con impronta disattivato: puoi riattivarlo nelle Impostazioni', 4000);
  }
  try {
    await saveBio(await bio.seal(pending, newPwd));
    toast('Sblocco con impronta aggiornato');
  } catch (e) {
    toast(e instanceof bio.BioCancelledError ? 'Sblocco con impronta disattivato: puoi riattivarlo nelle Impostazioni' : e.message, 4000);
  }
}

$('s-bio-on').addEventListener('click', async () => {
  // si verifica la password attuale: è quella che verrà protetta dalla passkey
  let verified = null;
  const pw = await askPassword('Attiva impronta o volto', 'Inserisci la password principale. Verrà cifrata su questo dispositivo con una chiave che si apre solo con la tua impronta o il tuo volto.', async (v) => {
    try { await C.unseal(await C.deriveKey(v, S.kdf), await store.get('vault')); verified = v; return null; } catch (e) { if (e instanceof C.WrongPasswordError) return 'Password errata'; throw e; }
  });
  if (pw === null || verified === null) return;
  // un tocco dedicato: alcuni browser (Safari) chiedono l'impronta solo dentro un gesto dell'utente
  if (!(await confirmBox('Attiva impronta o volto', 'Ora il telefono ti chiederà impronta o volto per creare la chiave di sblocco di CryptoPwd.', 'Continua'))) return;
  try {
    const r = await bio.begin(verified);
    if (r.done) {
      await saveBio(r.record);
    } else {
      if (!(await confirmBox('Ancora un passaggio', 'Conferma di nuovo con impronta o volto per completare l\'attivazione.', 'Conferma'))) return;
      await saveBio(await bio.seal(r.pending, verified));
    }
    toast('Sblocco con impronta o volto attivato');
  } catch (e) {
    if (!(e instanceof bio.BioCancelledError)) toast(e.message, 5000);
  } finally {
    verified = null;
    renderSettingsBio();
  }
});

$('s-bio-off').addEventListener('click', async () => {
  if (!(await confirmBox('Disattivare impronta o volto?', 'Per sbloccare servirà di nuovo la password principale. La passkey "CryptoPwd" resta nel gestore delle passkey del telefono: se vuoi puoi eliminarla da lì.', 'Disattiva'))) return;
  await disableBio();
  renderSettingsBio();
  toast('Sblocco con impronta o volto disattivato');
});

function openSettings() {
  renderSettingsDrive();
  renderSettingsBio();
  $('s-autolock').value = String(Number(S.meta.autolockMin) || DEFAULT_AUTOLOCK_MIN);
  // versione installata = nome della cache del service worker (es. cryptopwd-v13)
  $('s-version').textContent = '';
  if (window.caches) caches.keys().then((k) => { const v = k.filter((n) => /^cryptopwd-v\d+$/.test(n)).sort((a, b) => a.slice(11) - b.slice(11)).pop(); if (v) $('s-version').textContent = `Versione app: ${v.replace('cryptopwd-', '')}`; }).catch(() => {});
  openDialog($('dlg-settings'));
}
$('btn-settings').addEventListener('click', openSettings);

$('s-autolock').addEventListener('change', async () => {
  S.meta = await store.patchMeta({ autolockMin: Number($('s-autolock').value) });
});

$('s-drive-connect').addEventListener('click', async () => {
  try {
    await drive.authorize();
    S.meta = await store.patchMeta({ driveLinked: true });
    renderSettingsDrive();
    await sync({ interactive: true });
    if (S.syncState === 'ok') toast('Google Drive collegato');
  } catch (e) {
    toast(e.message, 4000);
  }
});
$('s-sync-now').addEventListener('click', () => sync({ interactive: true }));
$('s-drive-disconnect').addEventListener('click', async () => {
  if (!(await confirmBox('Scollegare Google Drive?', 'Il vault su Drive non verrà cancellato, ma questo dispositivo smetterà di sincronizzarsi.', 'Scollega'))) return;
  drive.signOut();
  S.meta = await store.patchMeta({ driveLinked: false, fileId: null, remoteModified: null });
  refreshSyncIdle();
});

$('s-change-pwd').addEventListener('click', () => {
  $('form-chpwd').reset();
  $('c-error').hidden = true;
  $('c-meter').style.width = '0';
  openDialog($('dlg-chpwd'));
});
$('form-chpwd').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const err = (m) => { $('c-error').textContent = m; $('c-error').hidden = false; };
  const [oldP, newP, newP2] = [$('c-old').value, $('c-new').value, $('c-new2').value];
  if (newP !== newP2) return err('Le nuove password non coincidono');
  if (newP.length < 10) return err('Usa almeno 10 caratteri');
  const btn = ev.submitter;
  if (btn) btn.disabled = true;
  try {
    const kOld = await C.deriveKey(oldP, S.kdf);
    await C.unseal(kOld, await store.get('vault')); // verifica password attuale
    S.kdf = C.newKdf();
    S.key = await C.deriveKey(newP, S.kdf);
    S.data.keyChangedAt = Date.now();
    await persistLocal();
    $('dlg-chpwd').close();
    toast('Password principale cambiata');
    if (bioRec) await offerBioUpdate(newP);
    // su Drive c'è ancora il vault con la vecchia password: serve per unirlo
    sync({ force: true, interactive: true, password: oldP });
  } catch (e) {
    err(e instanceof C.WrongPasswordError ? 'Password attuale errata' : e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
});

$('s-export').addEventListener('click', async () => {
  const blob = await store.get('vault');
  const attachments = {};
  let missing = 0;
  for (const id of V.referencedAttachments(S.data).keys()) {
    const rec = await store.getAtt(id);
    if (rec) attachments[id] = C.toB64(rec.data); else missing++;
  }
  if (missing) toast(`${missing} allegati non sono ancora su questo dispositivo e non saranno nel backup`, 4000);
  const a = el('a', {
    href: URL.createObjectURL(new Blob([JSON.stringify({ ...blob, attachments })], { type: 'application/json' })),
    download: `cryptopwd-backup-${new Date().toISOString().slice(0, 10)}.json`,
  });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  toast('Backup cifrato esportato');
});

$('s-import').addEventListener('click', () => $('s-import-file').click());
$('s-import-file').addEventListener('change', async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = '';
  if (!file) return;
  try {
    const text = await file.text();
    let incoming;
    if (/\.csv$/i.test(file.name) || file.type === 'text/csv') {
      // le voci importate finiscono nel soggetto/categoria selezionati nei filtri
      const real = (x) => (x && x !== NONE ? x : null);
      incoming = { entries: parseCsvEntries(text).map((e) => ({ ...e, subjectId: real(S.filter.subjectId), categoryId: real(S.filter.subjectId) && real(S.filter.categoryId) })) };
    } else {
      const blob = JSON.parse(text);
      for (const [id, b64] of Object.entries(blob.attachments || {})) {
        if (!(await store.getAtt(id))) await store.putAtt(id, C.fromB64(b64));
      }
      if (C.sameKdf(blob.kdf, S.kdf)) {
        incoming = await C.unseal(S.key, blob);
      } else {
        const pw = await askPassword('Password del backup', 'Inserisci la password principale con cui è stato creato il backup.', async (v) => {
          try { incoming = (await C.openWithPassword(v, blob)).data; return null; } catch (e) { if (e instanceof C.WrongPasswordError) return 'Password errata'; throw e; }
        });
        if (pw === null) return;
      }
    }
    const before = V.liveEntries(S.data).length;
    S.data = { ...V.merge(S.data, incoming), keyChangedAt: S.data.keyChangedAt };
    await persistLocal();
    renderList();
    scheduleSync();
    toast(`Importazione completata: ${V.liveEntries(S.data).length - before} nuove voci`, 3500);
  } catch (e) {
    toast(`Importazione fallita: ${e.message}`, 4000);
  }
});

$('s-wipe').addEventListener('click', async () => {
  const msg = S.meta.dirty
    ? 'ATTENZIONE: ci sono modifiche non ancora sincronizzate su Drive che andranno perse. Continuare?'
    : 'La copia locale verrà cancellata. Potrai ripristinarla da Google Drive.';
  if (!(await confirmBox('Cancellare i dati locali?', msg, 'Cancella'))) return;
  drive.signOut();
  await store.clear();
  location.reload();
});

// =====================================================================
// Avvio
// =====================================================================
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch((e) => console.warn('SW non registrato', e));
}
boot().catch((e) => {
  console.error(e);
  toast(`Errore di avvio: ${e.message}`, 6000);
});
