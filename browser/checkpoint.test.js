// Real IndexedDB transaction vectors. Instrumentation is test-only; production JS is unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright-core';
import instrument from 'istanbul-lib-instrument';
import coverage from 'istanbul-lib-coverage';

test('actual browser CAS, corruption, tab races and strict durability', async () => {
  const source = await readFile(new URL('./checkpoint.js', import.meta.url), 'utf8');
  const instrumenter = instrument.createInstrumenter({ esModules: true });
  const module = instrumenter.instrumentSync(source, 'browser/checkpoint.js');
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', request.url === '/checkpoint.js' ? 'text/javascript' : 'text/html');
    response.end(request.url === '/checkpoint.js' ? module : '<!doctype html><title>Storage vectors</title>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true });
  const context = await browser.newContext();
  const url = `http://127.0.0.1:${server.address().port}`;
  const pages = [await context.newPage(), await context.newPage()];
  try {
    await Promise.all(pages.map(page => page.goto(url)));
    for (const page of pages) {
      await page.evaluate(async () => {
        globalThis.cas = (await import('/checkpoint.js')).compareCheckpoint;
        globalThis.create = name => new Promise((resolve, reject) => {
          const request = indexedDB.open(name, 1);
          request.onupgradeneeded = () => request.result.createObjectStore('col0');
          request.onerror = reject;
          request.onsuccess = () => { request.result.close(); resolve(); };
        });
        globalThis.put = (name, value) => new Promise((resolve, reject) => {
          const request = indexedDB.open(name);
          request.onerror = reject;
          request.onsuccess = () => {
            const db = request.result;
            const tx = db.transaction('col0', 'readwrite');
            tx.objectStore('col0').put(value, new TextEncoder().encode('checkpoint'));
            tx.oncomplete = () => { db.close(); resolve(); };
            tx.onabort = () => { db.close(); reject(new Error('test transaction')); };
          };
        });
      });
    }
    const page = pages[0];
    assert.deepEqual(await page.evaluate(async () => {
      const results = [];
      for (const next of [new Uint8Array(), new Uint8Array(5)]) {
        try { await cas('bounds', null, next, 4); results.push(false); }
        catch { results.push(true); }
      }
      try { await cas('not-created', null, new Uint8Array([1]), 4); results.push(false); }
      catch { results.push(true); }
      await create('store');
      results.push(await cas('store', undefined, new Uint8Array([1, 2]), 4));
      results.push(!await cas('store', null, new Uint8Array([3]), 4));
      results.push(!await cas('store', new Uint8Array([1]), new Uint8Array([3]), 4));
      results.push(!await cas('store', new Uint8Array([1, 9]), new Uint8Array([3]), 4));
      results.push(await cas('store', new Uint8Array([1, 2]), new Uint8Array([3]), 4));
      await put('store', 'corrupt upstream type');
      results.push(!await cas('store', new Uint8Array([3]), new Uint8Array([4]), 4));
      await create('race');
      results.push(await cas('race', null, new Uint8Array([1]), 4));
      return results;
    }), Array(10).fill(true));
    const results = await Promise.all(pages.map((page, i) => page.evaluate(async i => {
      return cas('race', new Uint8Array([1]), new Uint8Array([i + 2]), 4);
    }, i)));
    assert.equal(results.filter(Boolean).length, 1);
    // Fault injection changes the platform durability dialect, not the transaction engine.
    // The real default-durability transaction must be aborted before any write is attempted.
    assert.equal(await page.evaluate(async () => {
      const original = IDBDatabase.prototype.transaction;
      IDBDatabase.prototype.transaction = function (stores, mode) {
        return original.call(this, stores, mode);
      };
      try {
        await cas('race', null, new Uint8Array([9]), 4);
        return false;
      } catch { return true; }
      finally { IDBDatabase.prototype.transaction = original; }
    }), true);
    const measured = coverage.createCoverageMap({});
    for (const page of pages) measured.merge(await page.evaluate(() => globalThis.__coverage__));
    await writeFile('browser-coverage.json', JSON.stringify(measured.toJSON()));
    const summary = measured.getCoverageSummary().toJSON();
    await writeFile('browser-coverage-summary.json', JSON.stringify(summary, null, 2));
    for (const kind of ['lines', 'branches', 'functions', 'statements']) {
      assert.ok(summary[kind].total > 0, `${kind}: empty measurement`);
      assert.equal(summary[kind].covered, summary[kind].total, `${kind}: ${JSON.stringify(summary[kind])}`);
    }
  } finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
});
