// Minimal IndexedDB wrapper. CryptoKey objects are stored via structured clone, staying non-extractable.
// Each put resolves only after the transaction commits (durable write, like a synchronous SQLite commit).
const DB_NAME = "credential-agent";
const STORES = ["keys", "records", "audit", "meta"] as const;
export type StoreName = (typeof STORES)[number];

let dbp: Promise<IDBDatabase> | null = null;

function db(): Promise<IDBDatabase> {
  if (!dbp) {
    dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        for (const s of STORES) if (!req.result.objectStoreNames.contains(s)) req.result.createObjectStore(s);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return dbp;
}

function tx<T>(store: StoreName, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest | void): Promise<T> {
  return db().then(
    (d) =>
      new Promise<T>((resolve, reject) => {
        const t = d.transaction(store, mode, { durability: "strict" } as IDBTransactionOptions);
        const r = fn(t.objectStore(store));
        t.oncomplete = () => resolve((r ? r.result : undefined) as T);
        t.onerror = () => reject(t.error);
        t.onabort = () => reject(t.error);
      }),
  );
}

export const idbGet = <T>(store: StoreName, key: string) => tx<T | undefined>(store, "readonly", (s) => s.get(key));
export const idbPut = (store: StoreName, key: string, value: unknown) => tx<void>(store, "readwrite", (s) => s.put(value, key));
export const idbDelete = (store: StoreName, key: string) => tx<void>(store, "readwrite", (s) => s.delete(key));
export const idbAll = <T>(store: StoreName) => tx<T[]>(store, "readonly", (s) => s.getAll());

export async function idbWipe(): Promise<void> {
  if (dbp) (await dbp).close();
  dbp = null;
  await new Promise<void>((resolve, reject) => {
    const r = indexedDB.deleteDatabase(DB_NAME);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
    r.onblocked = () => resolve();
  });
}
