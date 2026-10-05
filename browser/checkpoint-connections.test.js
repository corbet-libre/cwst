// Real-browser connection-closure vectors: compareCheckpoint must close its
// own IndexedDB connection on every settled path (success, expected-mismatch
// conflict, missing object store). Proof is an actual version upgrade plus
// deletion on the same database reaching success without a blocked event.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright-core';

const GUARD_MS = 5000;
const OWNED = ['conn-closed-ok', 'conn-closed-conflict', 'conn-closed-nostore'];

function withTimeout(promise, label) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: timeout`)), GUARD_MS);
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

test('compareCheckpoint closes its connection on settled paths', { timeout: 30000 }, async () => {
  const source = await readFile(new URL('./checkpoint.js', import.meta.url), 'utf8');
  let server;
  let browser;
  let context;
  let page;
  try {
    server = createServer((request, response) => {
      response.setHeader('Content-Type', request.url === '/checkpoint.js' ? 'text/javascript' : 'text/html');
      response.end(request.url === '/checkpoint.js' ? source : '<!doctype html><title>Connection vectors</title>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true });
    context = await browser.newContext();
    page = await context.newPage();
    const url = `http://127.0.0.1:${server.address().port}`;
    await withTimeout(page.goto(url), 'goto');
    await withTimeout(page.evaluate(() => {
      globalThis.withGuard = (install) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('browser guard: timeout')), 4000);
        const ok = (value) => { clearTimeout(timer); resolve(value); };
        const fail = (error) => { clearTimeout(timer); reject(error); };
        try { install(ok, fail); } catch (error) { fail(error); }
      });
      globalThis.createWithStore = (name) => globalThis.withGuard((resolve, reject) => {
        const request = indexedDB.open(name, 1);
        request.onupgradeneeded = () => request.result.createObjectStore('col0');
        request.onblocked = () => reject(new Error('setup blocked'));
        request.onerror = () => reject(new Error('create failed'));
        request.onsuccess = () => { request.result.close(); resolve(true); };
      });
      globalThis.createBare = (name) => globalThis.withGuard((resolve, reject) => {
        const request = indexedDB.open(name, 1);
        request.onblocked = () => reject(new Error('setup blocked'));
        request.onerror = () => reject(new Error('create failed'));
        request.onsuccess = () => { request.result.close(); resolve(true); };
      });
      globalThis.upgradeCloseAndDelete = (name) => globalThis.withGuard((resolve, reject) => {
        let finished = false;
        const request = indexedDB.open(name, 2);
        request.onblocked = () => {
          if (finished) return;
          finished = true;
          reject(new Error('upgrade blocked'));
        };
        request.onerror = () => {
          if (finished) return;
          finished = true;
          reject(new Error('upgrade failed'));
        };
        request.onsuccess = () => {
          // A late upgrade success after an onblocked rejection still owns a
          // handle, so close it before leaving; the race already rejected.
          if (finished) { try { request.result.close(); } catch {} return; }
          finished = true;
          const db = request.result;
          db.close();
          const deletion = indexedDB.deleteDatabase(name);
          deletion.onblocked = () => reject(new Error('delete blocked'));
          deletion.onerror = () => reject(new Error('delete failed'));
          deletion.onsuccess = () => resolve(true);
        };
      });
      // Best-effort hygiene for the three owned databases only. Never rejects:
      // a blocked or failed delete here must not mask the oracle assertion
      // above. Context shutdown below is the fallback if evaluation hangs.
      globalThis.bestEffortDelete = (name) => new Promise((resolve) => {
        let timer;
        try {
          const deletion = indexedDB.deleteDatabase(name);
          timer = setTimeout(() => resolve(false), 2000);
          deletion.onblocked = () => { clearTimeout(timer); resolve(false); };
          deletion.onerror = () => { clearTimeout(timer); resolve(false); };
          deletion.onsuccess = () => { clearTimeout(timer); resolve(true); };
        } catch { if (timer !== undefined) clearTimeout(timer); resolve(false); }
      });
      globalThis.cleanupOwned = async (names) => {
        for (const name of names) await globalThis.bestEffortDelete(name);
        return true;
      };
    }), 'install helpers');
    await withTimeout(page.evaluate(async () => {
      globalThis.cas = (await import('/checkpoint.js')).compareCheckpoint;
    }), 'import cas');
    assert.equal(await withTimeout(page.evaluate(async () => {
      await globalThis.createWithStore('conn-closed-ok');
      return globalThis.cas('conn-closed-ok', null, new Uint8Array([1, 2]), 4);
    }), 'success cas'), true);
    assert.equal(await withTimeout(page.evaluate(() => globalThis.upgradeCloseAndDelete('conn-closed-ok')), 'success upgrade'), true);
    assert.equal(await withTimeout(page.evaluate(async () => {
      await globalThis.createWithStore('conn-closed-conflict');
      const seeded = await globalThis.cas('conn-closed-conflict', null, new Uint8Array([7]), 4);
      const conflict = await globalThis.cas('conn-closed-conflict', new Uint8Array([9]), new Uint8Array([8]), 4);
      return seeded === true && conflict === false;
    }), 'conflict cas'), true);
    assert.equal(await withTimeout(page.evaluate(() => globalThis.upgradeCloseAndDelete('conn-closed-conflict')), 'conflict upgrade'), true);
    // checkpoint.js settles the missing-store path via db.transaction('col0',
    // ...) (line 17), which the IndexedDB standard reports as a NotFoundError
    // DOMException when the store is absent. Its own open/bounds/abort paths
    // instead reject with Error('storage'), so only the DOMException name
    // proves this vector and a generic setup failure cannot pass.
    assert.equal(await withTimeout(page.evaluate(async () => {
      await globalThis.createBare('conn-closed-nostore');
      try {
        await globalThis.cas('conn-closed-nostore', null, new Uint8Array([1]), 4);
        return 'no-throw';
      } catch (error) {
        return error && error.name ? String(error.name) : String(error);
      }
    }), 'missing cas'), 'NotFoundError');
    assert.equal(await withTimeout(page.evaluate(() => globalThis.upgradeCloseAndDelete('conn-closed-nostore')), 'missing upgrade'), true);
  } finally {
    // Best-effort removal of exactly the owned databases; never masks the
    // body failure. Context shutdown is the fallback when evaluation hangs.
    if (page && context) {
      await withTimeout(page.evaluate(names => globalThis.cleanupOwned(names), OWNED), 'cleanup').catch(() => {});
    }
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    if (server) await new Promise((resolve) => {
      if (!server.listening) { resolve(); return; }
      server.close(() => resolve());
    }).catch(() => {});
  }
});
