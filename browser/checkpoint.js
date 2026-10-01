// Extends keyvaluedb-web's col0/Uint8Array layout with one strict CAS transaction.
// keyvaluedb's separate get/write calls cannot fence concurrent browser tabs.
export async function compareCheckpoint(name, expected, next, maximum) {
  expected = expected === undefined ? null : expected;
  if (expected !== null) expected = expected.slice();
  next = next.slice();
  if (next.length === 0 || next.length > maximum) throw new Error('storage');
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(name);
    request.onerror = () => reject(new Error('storage'));
    request.onupgradeneeded = () => request.transaction.abort();
    request.onsuccess = () => resolve(request.result);
  });
  try {
    return await new Promise((resolve, reject) => {
      let conflict = false;
      const tx = db.transaction('col0', 'readwrite', { durability: 'strict' });
      tx.oncomplete = () => resolve(true);
      tx.onabort = () => conflict ? resolve(false) : reject(new Error('storage'));
      if (tx.durability !== 'strict') { tx.abort(); return; }
      const records = tx.objectStore('col0');
      const key = new TextEncoder().encode('checkpoint');
      const read = records.get(key);
      read.onsuccess = () => {
        const prior = read.result;
        const matches = expected === null ? prior === undefined : prior instanceof Uint8Array &&
          prior.length === expected.length && prior.every((v, i) => v === expected[i]);
        if (!matches) { conflict = true; tx.abort(); return; }
        records.put(next, key);
      };
    });
  } finally { db.close(); }
}
