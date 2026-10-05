// Real IndexedDB corrupt value-type vectors against unchanged checkpoint.js.
// Raw IDB setup/read/delete below are external test fixtures only; the CAS
// under test is always the production compareCheckpoint, never reimplemented.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright-core';

const STEP_TIMEOUT = 15000;

// Finite watchdog: a hung goto/evaluate/IDB step rejects instead of hanging
// the owner run, terminating the context so blocked pages cannot linger.
function guarded(work, context, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      context.close().catch(() => {});
      reject(new Error(`timeout: ${label}`));
    }, STEP_TIMEOUT);
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

test('corrupt checkpoint value types refuse CAS and keep originals', { timeout: 120000 }, async () => {
  const source = await readFile(new URL('./checkpoint.js', import.meta.url), 'utf8');
  let server = null;
  let browser = null;
  let context = null;
  try {
    server = createServer((request, response) => {
      const body = request.url === '/checkpoint.js' ? source : '<!doctype html><title>Checkpoint types</title>';
      response.setHeader('Content-Type', request.url === '/checkpoint.js' ? 'text/javascript' : 'text/html');
      response.end(body);
    });
    await new Promise((resolve, reject) => {
      server.on('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true });
    context = await browser.newContext();
    const url = `http://127.0.0.1:${server.address().port}`;
    const page = await context.newPage();
    await guarded(page.goto(url), context, 'goto');
    await guarded(page.evaluate(async () => {
      globalThis.cas = (await import('/checkpoint.js')).compareCheckpoint;
      const keyOf = () => new TextEncoder().encode('checkpoint');
      const finishWith = (dbBox, settled, resolve, reject) => (error, value) => {
        if (settled.done) return;
        settled.done = true;
        clearTimeout(settled.timer);
        if (dbBox.db !== null) { try { dbBox.db.close(); } catch {} dbBox.db = null; }
        if (error) reject(error); else resolve(value);
      };
      globalThis.setup = (name, value) => new Promise((resolve, reject) => {
        const dbBox = { db: null };
        const settled = { done: false, timer: 0 };
        const finish = finishWith(dbBox, settled, resolve, reject);
        settled.timer = setTimeout(() => finish(new Error('setup timeout')), 10000);
        const open = indexedDB.open(name, 1);
        open.onupgradeneeded = () => open.result.createObjectStore('col0');
        open.onerror = () => finish(new Error('setup open'));
        open.onblocked = () => finish(new Error('setup blocked'));
        open.onsuccess = () => {
          dbBox.db = open.result;
          let tx;
          try { tx = dbBox.db.transaction('col0', 'readwrite'); }
          catch { finish(new Error('setup transaction')); return; }
          tx.oncomplete = () => finish(null);
          tx.onerror = () => finish(new Error('setup write'));
          tx.onabort = () => finish(new Error('setup aborted'));
          try { tx.objectStore('col0').put(value, keyOf()); }
          catch { try { tx.abort(); } catch {} }
        };
      });
      globalThis.readRaw = name => new Promise((resolve, reject) => {
        const dbBox = { db: null };
        const settled = { done: false, timer: 0 };
        const finish = finishWith(dbBox, settled, resolve, reject);
        settled.timer = setTimeout(() => finish(new Error('read timeout')), 10000);
        const open = indexedDB.open(name);
        open.onerror = () => finish(new Error('read open'));
        open.onblocked = () => finish(new Error('read blocked'));
        open.onsuccess = () => {
          dbBox.db = open.result;
          let tx;
          try { tx = dbBox.db.transaction('col0', 'readonly'); }
          catch { finish(new Error('read transaction')); return; }
          tx.onerror = () => finish(new Error('read transaction'));
          tx.onabort = () => finish(new Error('read aborted'));
          let get;
          try { get = tx.objectStore('col0').get(keyOf()); }
          catch { finish(new Error('read get')); return; }
          get.onsuccess = () => finish(null, get.result);
          get.onerror = () => finish(new Error('read get'));
        };
      });
      globalThis.wipe = name => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('wipe timeout')), 10000);
        const request = indexedDB.deleteDatabase(name);
        request.onsuccess = () => { clearTimeout(timer); resolve(); };
        request.onerror = () => { clearTimeout(timer); reject(new Error('wipe failed')); };
        request.onblocked = () => { clearTimeout(timer); reject(new Error('wipe blocked')); };
      });
    }), context, 'fixtures');
    const outcomes = await guarded(page.evaluate(async () => {
      const bytes = value => Array.from(new Uint8Array(value.buffer ?? value, value.byteOffset ?? 0, value.byteLength ?? value.length));
      const cases = [
        { name: 'corrupt-ab', make: () => new Uint8Array([1, 2]).buffer, check: v => v instanceof ArrayBuffer && bytes(v).join() === '1,2' },
        { name: 'corrupt-dv', make: () => new DataView(new Uint8Array([1, 2]).buffer), check: v => v instanceof DataView && bytes(v).join() === '1,2' },
        { name: 'corrupt-i8', make: () => new Int8Array([1, 2]), check: v => v instanceof Int8Array && !(v instanceof Uint8Array) && [...v].join() === '1,2' },
        { name: 'corrupt-u16', make: () => new Uint16Array([0x0101]), check: v => v instanceof Uint16Array && !(v instanceof Uint8Array) && v.length === 1 && v[0] === 0x0101 },
        { name: 'corrupt-arr', make: () => [1, 2], check: v => Array.isArray(v) && v.join() === '1,2' },
        { name: 'corrupt-obj', make: () => ({ 0: 1, 1: 2 }), check: v => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof ArrayBuffer) && !(v instanceof DataView) && !ArrayBuffer.isView(v) && v[0] === 1 && v[1] === 2 },
      ];
      const run = async (name, seed, expectedBytes, accept, check) => {
        let done = false;
        let kept = false;
        try {
          await wipe(name);
          await setup(name, seed());
          done = (await cas(name, expectedBytes(), new Uint8Array([3, 4]), 4)) === accept;
          kept = check(await readRaw(name));
        } catch { done = false; kept = false; }
        let cleaned = false;
        try { await wipe(name); cleaned = true; } catch { cleaned = false; }
        return [done, kept, cleaned];
      };
      const ok = [];
      for (const { name, make, check } of cases) {
        const expected = name === 'corrupt-u16' ? () => new Uint8Array([1, 1]) : () => new Uint8Array([1, 2]);
        ok.push(...await run(name, make, expected, false, check));
      }
      const positive = raw => raw instanceof Uint8Array && [...raw].join() === '3,4';
      ok.push(...await run('positive-u8', () => new Uint8Array([1, 2]), () => new Uint8Array([9, 1, 2, 9]).subarray(1, 3), true, positive));
      return ok;
    }), context, 'cases');
    assert.deepEqual(outcomes, Array(outcomes.length).fill(true));
    assert.equal(outcomes.length, 21);
  } finally {
    await context?.close().catch(() => {});
    await browser?.close().catch(() => {});
    if (server !== null) await new Promise(resolve => server.close(resolve));
  }
});
