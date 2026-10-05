// Key/store isolation: CAS touches only the exact binary checkpoint key.
// Real Chromium IndexedDB; production browser/checkpoint.js is imported unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright-core';

test('checkpoint CAS isolates exact binary key and col0/col1 neighbours', { timeout: 30000 }, async () => {
  const source = await readFile(new URL('./checkpoint.js', import.meta.url), 'utf8');
  const server = createServer((request, response) => {
    const isModule = request.url === '/checkpoint.js';
    response.setHeader('Content-Type', isModule ? 'text/javascript' : 'text/html');
    response.end(isModule ? source : '<!doctype html><title>Key isolation</title>');
  });
  const stamp = `${process.pid}-${Date.now()}`;
  const present = `cwst-keyiso-present-${stamp}`;
  const absent = `cwst-keyiso-absent-${stamp}`;
  let listening = false;
  let launched = false;
  let browser;
  let page;
  try {
    await new Promise((resolve, reject) => {
      server.on('error', reject);
      server.listen(0, '127.0.0.1', () => {
        listening = true;
        resolve();
      });
    });
    browser = await chromium.launch({
      executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome',
      headless: true,
    });
    launched = true;
    page = await browser.newPage();
    page.setDefaultTimeout(5000);
    page.setDefaultNavigationTimeout(5000);
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.evaluate(async () => {
      globalThis.cas = (await import('/checkpoint.js')).compareCheckpoint;
      const keys = () => {
        const base = new TextEncoder().encode('checkpoint');
        const prefix = base.slice(0, base.length - 1);
        const suffix = new Uint8Array(base.length + 1);
        suffix.set(base);
        suffix[base.length] = 0;
        return { base, prefix, suffix };
      };
      globalThis.seed = (name, withCheckpoint) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('seed timeout')), 5000);
        const wipe = indexedDB.deleteDatabase(name);
        wipe.onblocked = () => reject(new Error('seed blocked'));
        wipe.onerror = () => reject(new Error('seed wipe'));
        wipe.onsuccess = () => {
          const open = indexedDB.open(name, 1);
          open.onblocked = () => { clearTimeout(timer); reject(new Error('seed blocked')); };
          open.onerror = () => { clearTimeout(timer); reject(new Error('seed open')); };
          open.onupgradeneeded = () => {
            open.result.createObjectStore('col0');
            open.result.createObjectStore('col1');
          };
          open.onsuccess = () => {
            const db = open.result;
            const tx = db.transaction(['col0', 'col1'], 'readwrite');
            tx.onabort = () => { clearTimeout(timer); db.close(); reject(new Error('seed abort')); };
            tx.onerror = () => { clearTimeout(timer); db.close(); reject(new Error('seed error')); };
            tx.oncomplete = () => { clearTimeout(timer); db.close(); resolve(); };
            const { base, prefix, suffix } = keys();
            if (withCheckpoint) tx.objectStore('col0').put(new Uint8Array([10, 20]), base);
            tx.objectStore('col0').put(new Uint8Array([1]), 'checkpoint');
            tx.objectStore('col0').put(new Uint8Array([2]), prefix);
            tx.objectStore('col0').put(new Uint8Array([3]), suffix);
            tx.objectStore('col1').put(new Uint8Array([4, 5]), 'other');
          };
        };
      });
      globalThis.snapshot = (name) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('read timeout')), 5000);
        const open = indexedDB.open(name);
        open.onblocked = () => { clearTimeout(timer); reject(new Error('read blocked')); };
        open.onerror = () => { clearTimeout(timer); reject(new Error('read open')); };
        open.onsuccess = () => {
          const db = open.result;
          const tx = db.transaction(['col0', 'col1'], 'readonly');
          tx.onabort = () => { clearTimeout(timer); db.close(); reject(new Error('read abort')); };
          tx.onerror = () => { clearTimeout(timer); db.close(); reject(new Error('read error')); };
          const { base, prefix, suffix } = keys();
          const col0 = tx.objectStore('col0');
          const col1 = tx.objectStore('col1');
          const gets = {
            checkpoint: col0.get(base),
            text: col0.get('checkpoint'),
            prefix: col0.get(prefix),
            suffix: col0.get(suffix),
            other: col1.get('other'),
          };
          tx.oncomplete = () => {
            clearTimeout(timer);
            db.close();
            const out = {};
            for (const [slot, request] of Object.entries(gets)) {
              const value = request.result;
              out[slot] = value === undefined
                ? { missing: true, bytes: null }
                : { missing: false, bytes: Array.from(value), binary: value instanceof Uint8Array };
            }
            resolve(out);
          };
        };
      });
      globalThis.remove = (name) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('delete timeout')), 5000);
        const request = indexedDB.deleteDatabase(name);
        request.onblocked = () => { clearTimeout(timer); reject(new Error('delete blocked')); };
        request.onerror = () => { clearTimeout(timer); reject(new Error('delete error')); };
        request.onsuccess = () => { clearTimeout(timer); resolve(); };
      });
    });
    await page.evaluate(async (name) => { await globalThis.seed(name, true); }, present);
    await page.evaluate(async (name) => { await globalThis.seed(name, false); }, absent);
    const beforePresent = await page.evaluate(async (name) => globalThis.snapshot(name), present);
    assert.equal(beforePresent.checkpoint.binary, true);
    assert.deepEqual(beforePresent.checkpoint.bytes, [10, 20]);
    assert.deepEqual(beforePresent.text.bytes, [1]);
    assert.deepEqual(beforePresent.prefix.bytes, [2]);
    assert.deepEqual(beforePresent.suffix.bytes, [3]);
    assert.deepEqual(beforePresent.other.bytes, [4, 5]);
    const ok = await page.evaluate(async (name) => globalThis.cas(name, new Uint8Array([10, 20]), new Uint8Array([30, 40]), 8), present);
    assert.equal(ok, true);
    const afterSuccess = await page.evaluate(async (name) => globalThis.snapshot(name), present);
    assert.equal(afterSuccess.checkpoint.binary, true);
    assert.deepEqual(afterSuccess.checkpoint.bytes, [30, 40]);
    assert.deepEqual(afterSuccess.text, beforePresent.text);
    assert.deepEqual(afterSuccess.prefix, beforePresent.prefix);
    assert.deepEqual(afterSuccess.suffix, beforePresent.suffix);
    assert.deepEqual(afterSuccess.other, beforePresent.other);
    const stale = await page.evaluate(async (name) => globalThis.cas(name, new Uint8Array([10, 20]), new Uint8Array([50]), 8), present);
    assert.equal(stale, false);
    const afterConflict = await page.evaluate(async (name) => globalThis.snapshot(name), present);
    assert.deepEqual(afterConflict.checkpoint.bytes, [30, 40]);
    assert.deepEqual(afterConflict.text, beforePresent.text);
    assert.deepEqual(afterConflict.prefix, beforePresent.prefix);
    assert.deepEqual(afterConflict.suffix, beforePresent.suffix);
    assert.deepEqual(afterConflict.other, beforePresent.other);
    const beforeAbsent = await page.evaluate(async (name) => globalThis.snapshot(name), absent);
    assert.equal(beforeAbsent.checkpoint.missing, true);
    assert.deepEqual(beforeAbsent.text.bytes, [1]);
    assert.deepEqual(beforeAbsent.other.bytes, [4, 5]);
    const created = await page.evaluate(async (name) => globalThis.cas(name, null, new Uint8Array([60]), 8), absent);
    assert.equal(created, true);
    const afterAbsent = await page.evaluate(async (name) => globalThis.snapshot(name), absent);
    assert.equal(afterAbsent.checkpoint.binary, true);
    assert.deepEqual(afterAbsent.checkpoint.bytes, [60]);
    assert.deepEqual(afterAbsent.text, beforeAbsent.text);
    assert.deepEqual(afterAbsent.prefix, beforeAbsent.prefix);
    assert.deepEqual(afterAbsent.suffix, beforeAbsent.suffix);
    assert.deepEqual(afterAbsent.other, beforeAbsent.other);
  } finally {
    try {
      if (launched && page) {
        await page.evaluate(async (names) => {
          for (const name of names) {
            try { await globalThis.remove(name); } catch { throw new Error('cleanup failed'); }
          }
        }, [present, absent]);
      }
    } finally {
      if (launched) await browser.close();
      if (listening) await new Promise((resolve) => server.close(resolve));
    }
  }
});
