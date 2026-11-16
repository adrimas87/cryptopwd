// Importazione CSV da altri gestori di password (Chrome, Firefox, Bitwarden, ...).
import { newId } from './vault.js';

export function parseCsv(text) {
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim()));
}

export function parseCsvEntries(text) {
  const rows = parseCsv(text.replace(/^﻿/, ''));
  if (rows.length < 2) throw new Error('CSV vuoto');
  const head = rows[0].map((h) => h.trim().toLowerCase());
  const col = (...names) => head.findIndex((h) => names.includes(h));
  const iT = col('name', 'title', 'nome'), iU = col('username', 'login_username', 'user', 'email', 'utente');
  const iP = col('password', 'login_password'), iL = col('url', 'login_uri', 'website', 'sito');
  const iN = col('note', 'notes', 'extra', 'comments');
  if (iP < 0) throw new Error('colonna "password" non trovata nel CSV');
  const now = Date.now();
  return rows.slice(1).map((r) => ({
    id: newId(),
    title: (r[iT] || '').trim() || hostOf(r[iL]) || '(senza nome)',
    username: (r[iU] || '').trim(),
    password: r[iP] || '',
    url: (r[iL] || '').trim(),
    notes: iN >= 0 ? r[iN] || '' : '',
    createdAt: now,
    updatedAt: now,
  }));
}
function hostOf(u) {
  try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return ''; }
}
