// View-snapshot vectors for the unchanged production browser/checkpoint.js.
// Execute (owner-selected, not run on this workstation):
//   node --test browser/checkpoint-views.test.js
// Real headless-browser IndexedDB only; no instrumentation, no fake IndexedDB.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright-core';

const TEST_MS = 120000;
const GOTO_MS = 30000;
const VECTORS_MS = 60000;

// Rejects when the wrapped work exceeds its budget so outer finally blocks run.
const withDeadline = (work, ms, step) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error(`timeout: ${step}`)), ms);
  if (typeof timer.unref === 'function') timer.unref();
  work.then(
    value => { clearTimeout(timer); resolve(value); },
    error => { clearTimeout(timer); reject(error); },
  );
});

test('browser checkpoint snapshots Uint8Array views before first await', { timeout: TEST_MS }, async () => {
  const source = await readFile(new URL('./checkpoint.js', import.meta.url), 'utf8');
  const server = createServer((request, response) => {
    const isModule = request.url === '/checkpoint.js';
    response.setHeader('Content-Type', isModule ? 'text/javascript' : 'text/html');
    response.end(isModule ? source : '<!doctype html><title>View snapshots</title>');
  });
  try {
    await withDeadline(new Promise(resolve => server.listen(0, '127.0.0.1', resolve)), GOTO_MS, 'listen');
    const address = `http://127.0.0.1:${server.address().port}`;
    const browser = await chromium.launch({
      executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome',
      headless: true,
    });
    try {
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        await page.goto(address, { timeout: GOTO_MS });
        const outcome = await withDeadline(page.evaluate(async () => {
          const { compareCheckpoint } = await import('/checkpoint.js');
          const key = new TextEncoder().encode('checkpoint');
          const name = 'views-snapshot-v1';
          const create = () => new Promise((resolve, reject) => {
            const request = indexedDB.open(name, 1);
            request.onupgradeneeded = () => request.result.createObjectStore('col0');
            request.onerror = () => reject(new Error('create'));
            request.onsuccess = () => { request.result.close(); resolve(); };
          });
          const rawRead = () => new Promise((resolve, reject) => {
            const request = indexedDB.open(name);
            request.onerror = () => reject(new Error('open'));
            request.onsuccess = () => {
              const db = request.result;
              const tx = db.transaction('col0', 'readonly');
              const query = tx.objectStore('col0').get(key);
              let value;
              query.onsuccess = () => { value = query.result; };
              query.onerror = () => reject(new Error('read'));
              tx.oncomplete = () => { db.close(); resolve(value); };
              const fail = () => {
                try { db.close(); } catch { /* already closed */ }
                reject(new Error('read'));
              };
              tx.onerror = fail;
              tx.onabort = fail;
            };
          });
          const remove = () => new Promise((resolve, reject) => {
            const request = indexedDB.deleteDatabase(name);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(new Error('delete'));
            request.onblocked = () => reject(new Error('delete-blocked'));
          });
          const bytes = value => Array.from(value);
          try {
            await create();
            if (await compareCheckpoint(name, null, new Uint8Array([10, 20, 30]), 16) !== true) {
              return { ok: false, step: 'seed' };
            }
            // Positive control: subarray views with sentinel bytes outside the view.
            const expectedBacking = new Uint8Array([0xaa, 10, 20, 30, 0xbb]);
            const expectedView = expectedBacking.subarray(1, 4);
            const nextBacking = new Uint8Array([0xcc, 40, 50, 0xdd]);
            const nextView = nextBacking.subarray(1, 3);
            const pending = compareCheckpoint(name, expectedView, nextView, 16);
            expectedBacking.fill(0xff);
            nextBacking.fill(0xff);
            if (await pending !== true) return { ok: false, step: 'snapshot-commit' };
            const stored = await rawRead();
            if (!(stored instanceof Uint8Array) || bytes(stored).join(',') !== '40,50') {
              return { ok: false, step: 'stored-view', seen: bytes(stored ?? []) };
            }
            // Mismatched view conflicts and leaves the exact predecessor.
            const badBacking = new Uint8Array([0x11, 40, 51, 0x22]);
            const badView = badBacking.subarray(1, 3);
            const thirdBacking = new Uint8Array([0x33, 60, 61, 62, 0x44]);
            const thirdView = thirdBacking.subarray(1, 4);
            const conflict = compareCheckpoint(name, badView, thirdView, 16);
            badBacking.fill(0x7e);
            thirdBacking.fill(0x7f);
            if (await conflict !== false) return { ok: false, step: 'mismatch-commit' };
            const kept = await rawRead();
            if (!(kept instanceof Uint8Array) || bytes(kept).join(',') !== '40,50') {
              return { ok: false, step: 'kept-view', seen: bytes(kept ?? []) };
            }
            return { ok: true };
          } finally {
            await remove();
          }
        }), VECTORS_MS, 'browser vectors');
        assert.deepEqual(outcome, { ok: true });
      } finally {
        await context.close();
      }
    } finally {
      await browser.close();
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
