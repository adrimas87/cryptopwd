// Sblocco con impronta digitale / riconoscimento del volto (WebAuthn + estensione PRF).
//
// All'attivazione si crea una passkey sul dispositivo. L'estensione PRF fa sì che, solo dopo
// la verifica biometrica, l'autenticatore restituisca un segreto di 32 byte, sempre uguale per
// quella passkey e quel "salt". Da quel segreto (HKDF) si ricava una chiave AES-256-GCM che
// cifra la password principale. Sul dispositivo resta solo { credId, salt, iv, ct }: senza
// impronta/volto (o PIN del telefono) la password non si può decifrare.
// Se il browser non supporta PRF l'attivazione viene rifiutata: niente ripieghi meno sicuri.

import { toB64, fromB64 } from './crypto.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const AAD = enc.encode('cryptopwd-bio-v1');
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

export class BioUnsupportedError extends Error {
  constructor(msg = 'Questo browser o dispositivo non supporta lo sblocco biometrico sicuro (estensione PRF). Aggiorna Chrome o iOS.') {
    super(msg); this.name = 'BioUnsupportedError';
  }
}
export class BioCancelledError extends Error {
  constructor() { super('Verifica biometrica annullata'); this.name = 'BioCancelledError'; }
}

export async function isAvailable() {
  try {
    return !!(window.isSecureContext && window.PublicKeyCredential
      && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch {
    return false;
  }
}

function mapError(e) {
  if (e?.name === 'NotAllowedError' || e?.name === 'AbortError') return new BioCancelledError();
  if (e?.name === 'NotSupportedError') return new BioUnsupportedError();
  return e;
}

async function wrapKey(prfOutput) {
  const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('cryptopwd-bio-wrap-v1') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Verifica biometrica: restituisce la chiave di cifratura legata alla passkey.
async function keyFromAssertion(credId, salt) {
  let a;
  try {
    a = await navigator.credentials.get({
      publicKey: {
        challenge: rnd(32),
        allowCredentials: [{ type: 'public-key', id: credId }],
        userVerification: 'required',
        timeout: 60_000,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (e) {
    throw mapError(e);
  }
  const out = a?.getClientExtensionResults?.().prf?.results?.first;
  if (!out) throw new BioUnsupportedError();
  return wrapKey(out);
}

async function sealPassword(key, password) {
  const iv = rnd(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, enc.encode(password));
  return { iv: toB64(iv), ct: toB64(ct) };
}

// Passo 1: crea la passkey. Se l'autenticatore restituisce già il segreto PRF
// l'attivazione è completa; altrimenti serve il passo 2 (finish) con un altro tocco.
export async function begin(password) {
  const salt = rnd(32);
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'CryptoPwd' },
        user: { id: rnd(16), name: 'CryptoPwd', displayName: 'CryptoPwd · sblocco rapido' },
        challenge: rnd(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
        timeout: 60_000,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (e) {
    throw mapError(e);
  }
  const prf = cred.getClientExtensionResults?.().prf;
  if (!prf || prf.enabled === false) throw new BioUnsupportedError();
  const credId = new Uint8Array(cred.rawId);
  const pending = { credId: toB64(credId), salt: toB64(salt) };
  const out = prf.results?.first;
  if (!out) return { done: false, pending };
  return { done: true, record: { ...pending, ...(await sealPassword(await wrapKey(out), password)) } };
}

// Passo 2 (o aggiornamento dopo un cambio password): una verifica biometrica sulla passkey esistente.
export async function seal(pending, password) {
  const key = await keyFromAssertion(fromB64(pending.credId), fromB64(pending.salt));
  return { credId: pending.credId, salt: pending.salt, ...(await sealPassword(key, password)) };
}

// Sblocco: verifica biometrica -> password principale.
export async function unlock(record) {
  const key = await keyFromAssertion(fromB64(record.credId), fromB64(record.salt));
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(record.iv), additionalData: AAD }, key, fromB64(record.ct)
    );
    return dec.decode(pt);
  } catch {
    throw new Error('Dati dello sblocco biometrico non validi: riattivalo nelle Impostazioni');
  }
}
