// Modello dati del vault (in chiaro, solo in memoria) e unione tra copie.
//
// data = {
//   subjects:   [ { id, name, createdAt, updatedAt, deleted? } ],
//   categories: [ { id, subjectId, name, createdAt, updatedAt, deleted? } ],   // ogni soggetto ha più categorie
//   entries:    [ { id, subjectId, categoryId, title, username, password, url, notes, createdAt, updatedAt, deleted? } ],
//   keyChangedAt
// }
// Gli elementi eliminati restano come "tombstone" (id + updatedAt + deleted) così
// l'eliminazione si propaga agli altri dispositivi.

export const COLLECTIONS = ['subjects', 'categories', 'entries'];

export function emptyVault() {
  return { subjects: [], categories: [], entries: [] };
}

// Compatibilità con vault creati prima di soggetti/categorie.
export function normalize(data) {
  for (const c of COLLECTIONS) if (!Array.isArray(data[c])) data[c] = [];
  return data;
}

export function newId() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

const alive = (arr) => arr.filter((x) => !x.deleted);
const byName = (a, b) => (a.name || '').localeCompare(b.name || '', 'it', { sensitivity: 'base' });

// voci attive (escluse quelle nel cestino)
export const liveEntries = (data) => alive(data.entries).filter((e) => !e.trashedAt);
// voci nel cestino, dalla più recente
export const trashedEntries = (data) => alive(data.entries).filter((e) => e.trashedAt).sort((a, b) => b.trashedAt - a.trashedAt);
export const subjectsOf = (data) => alive(data.subjects).sort(byName);
export const categoriesOf = (data, subjectId) => alive(data.categories).filter((c) => c.subjectId === subjectId).sort(byName);
export const findLive = (data, coll, id) => (id ? data[coll].find((x) => x.id === id && !x.deleted) : undefined);

export function upsertItem(data, coll, item) {
  const now = Date.now();
  const i = item.id ? data[coll].findIndex((e) => e.id === item.id) : -1;
  if (i >= 0) {
    data[coll][i] = { ...data[coll][i], ...item, updatedAt: now };
    return data[coll][i];
  }
  const created = { ...item, id: item.id || newId(), createdAt: now, updatedAt: now };
  data[coll].push(created);
  return created;
}

export function deleteItem(data, coll, id) {
  const i = data[coll].findIndex((e) => e.id === id);
  if (i >= 0) data[coll][i] = { id, deleted: true, updatedAt: Date.now() };
}

export const upsertEntry = (data, entry) => upsertItem(data, 'entries', entry);

// Cestino: la voce conserva tutti i dati e si può ripristinare.
export function trashEntry(data, id) {
  const e = data.entries.find((x) => x.id === id && !x.deleted);
  if (e) upsertItem(data, 'entries', { id, trashedAt: Date.now() });
}
export function restoreEntry(data, id) {
  const i = data.entries.findIndex((x) => x.id === id && !x.deleted);
  if (i < 0) return;
  const { trashedAt, ...rest } = data.entries[i];
  data.entries[i] = { ...rest, updatedAt: Date.now() };
}
// Eliminazione definitiva (dal cestino): resta solo il "tombstone".
export const deleteEntry = (data, id) => deleteItem(data, 'entries', id);
export function emptyTrash(data) {
  const ids = trashedEntries(data).map((e) => e.id);
  for (const id of ids) deleteItem(data, 'entries', id);
  return ids.length;
}

// Allegati ancora in uso (voci attive e nel cestino): Map id -> metadati
export function referencedAttachments(data) {
  const m = new Map();
  for (const e of alive(data.entries)) for (const a of e.attachments || []) m.set(a.id, a);
  return m;
}

// Quante voci/categorie vive dipendono da un soggetto o da una categoria.
export function usage(data, { subjectId, categoryId }) {
  if (categoryId) return { entries: liveEntries(data).filter((e) => e.categoryId === categoryId).length, categories: 0 };
  return {
    entries: liveEntries(data).filter((e) => e.subjectId === subjectId).length,
    categories: categoriesOf(data, subjectId).length,
  };
}

function mergeList(a = [], b = []) {
  const map = new Map();
  for (const e of [...a, ...b]) {
    const cur = map.get(e.id);
    if (!cur || (e.updatedAt || 0) > (cur.updatedAt || 0)) map.set(e.id, e);
  }
  return [...map.values()].sort((x, y) => x.id.localeCompare(y.id));
}

// Unione elemento per elemento: vince la versione modificata più di recente.
export function merge(a, b) {
  const out = {};
  for (const c of COLLECTIONS) out[c] = mergeList(a?.[c], b?.[c]);
  // quando è stata cambiata l'ultima volta la password principale (serve a scegliere la chiave più recente)
  out.keyChangedAt = Math.max(a?.keyChangedAt || 0, b?.keyChangedAt || 0);
  return out;
}

// Confronto stabile per capire se due versioni sono identiche.
export function fingerprint(data) {
  return JSON.stringify(
    COLLECTIONS.map((c) => [...(data?.[c] || [])].sort((x, y) => x.id.localeCompare(y.id)).map((e) => [e.id, e.updatedAt, !!e.deleted]))
  );
}
