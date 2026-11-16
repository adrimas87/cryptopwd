// Archivio locale (IndexedDB). Contiene SOLO il vault cifrato e metadati non sensibili.

const DB_NAME = 'cryptopwd';
const STORE = 'kv';
let dbPromise;

function db() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return dbPromise;
}

async function tx(mode, fn) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(STORE, mode);
    const store = t.objectStore(STORE);
    const req = fn(store);
    t.oncomplete = () => resolve(req?.result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

export const get = (k) => tx('readonly', (s) => s.get(k));
export const set = (k, v) => tx('readwrite', (s) => s.put(v, k));
export const del = (k) => tx('readwrite', (s) => s.delete(k));
export const clear = () => tx('readwrite', (s) => s.clear());

export async function getMeta() {
  return (await get('meta')) || {};
}

export async function patchMeta(patch) {
  const m = await getMeta();
  const next = { ...m, ...patch };
  await set('meta', next);
  return next;
}

// Chiede al browser di non cancellare i dati in caso di poco spazio.
export async function requestPersistence() {
  try {
    if (navigator.storage?.persist && !(await navigator.storage.persisted())) await navigator.storage.persist();
  } catch { /* non critico */ }
}
