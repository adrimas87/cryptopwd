// Cifratura lato client: PBKDF2-SHA256 -> AES-256-GCM (WebCrypto).
// La password principale e i dati in chiaro non lasciano mai il dispositivo.

const enc = new TextEncoder();
const dec = new TextDecoder();
const AAD = enc.encode('cryptopwd-vault-v1');

export const KDF_ITERATIONS = 600000; // raccomandazione OWASP 2023+ per PBKDF2-SHA256

export function toB64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromB64(str) {
  const s = atob(str);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

export function newKdf() {
  return { name: 'PBKDF2-SHA256', salt: toB64(crypto.getRandomValues(new Uint8Array(16))), iterations: KDF_ITERATIONS };
}

export function sameKdf(a, b) {
  return !!a && !!b && a.salt === b.salt && a.iterations === b.iterations && a.name === b.name;
}

export async function deriveKey(password, kdf) {
  if (kdf.name !== 'PBKDF2-SHA256') throw new Error('KDF non supportata');
  const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: fromB64(kdf.salt), iterations: kdf.iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Restituisce il "blob" cifrato serializzabile (cio' che va su disco e su Drive).
export async function seal(key, kdf, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: AAD },
    key,
    enc.encode(JSON.stringify(data))
  );
  return { format: 'cryptopwd', version: 1, kdf, iv: toB64(iv), data: toB64(ct) };
}

export class WrongPasswordError extends Error {
  constructor() { super('Password errata'); this.name = 'WrongPasswordError'; }
}

export async function unseal(key, blob) {
  if (!blob || blob.format !== 'cryptopwd' || blob.version !== 1) throw new Error('Formato vault non valido');
  let pt;
  try {
    pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(blob.iv), additionalData: AAD },
      key,
      fromB64(blob.data)
    );
  } catch {
    throw new WrongPasswordError();
  }
  return JSON.parse(dec.decode(pt));
}

// Apre un blob a partire dalla password: { key, kdf, data }
export async function openWithPassword(password, blob) {
  const key = await deriveKey(password, blob.kdf);
  const data = await unseal(key, blob);
  return { key, kdf: blob.kdf, data };
}

// Generatore di password con campionamento a rifiuto (nessun bias).
export function generatePassword(length = 20, opts = { lower: true, upper: true, digits: true, symbols: true }) {
  const sets = [];
  if (opts.lower) sets.push('abcdefghijkmnopqrstuvwxyz');
  if (opts.upper) sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if (opts.digits) sets.push('23456789');
  if (opts.symbols) sets.push('!@#$%^&*()-_=+[]{};:,.?/');
  if (!sets.length) sets.push('abcdefghijkmnopqrstuvwxyz');
  const all = sets.join('');
  const pick = (alphabet) => {
    const limit = 256 - (256 % alphabet.length);
    const buf = new Uint8Array(1);
    for (;;) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) return alphabet[buf[0] % alphabet.length];
    }
  };
  for (;;) {
    let out = '';
    for (let i = 0; i < length; i++) out += pick(all);
    // garantisce almeno un carattere per ogni insieme selezionato
    if (length < sets.length || sets.every((s) => [...out].some((c) => s.includes(c)))) return out;
  }
}
