// End-to-end check of `shieldcheck serve` in a real browser.
// Usage: node e2e/ui.mjs  (needs the `playwright` package resolvable, e.g. NODE_PATH=.../node_modules,
// and a shieldcheck binary built at ./shieldcheck). Uses ports 4115 (UI) and 4116 (fixture site).
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import http from 'node:http';
import assert from 'node:assert/strict';

const { chromium } = createRequire(import.meta.url)('playwright'); // CJS resolution honours NODE_PATH

const site = http.createServer((_, res) => {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end('<!doctype html><html lang="en"><head><title>fixture</title></head><body>hi</body></html>');
}).listen(4116, '127.0.0.1');
const ui = spawn('./shieldcheck', ['serve', '--port', '4115', '--allow-private'], { stdio: 'inherit' });
const stop = () => { ui.kill(); site.close(); };
try {
  await new Promise(r => setTimeout(r, 700));
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('console', m => m.type() === 'error' && errors.push(m.text()));
  const t0 = Date.now();
  await page.goto('http://127.0.0.1:4115/');
  const load = Date.now() - t0;
  assert.equal(await page.locator('h1').count(), 1, 'one h1');
  assert.ok(await page.getAttribute('html', 'lang'), 'html lang');
  await page.fill('#url', 'http://127.0.0.1:4116/');
  await page.keyboard.press('Enter');
  await page.waitForURL(/\/scan\?/);
  assert.match(await page.textContent('h1'), /127\.0\.0\.1:4116/);
  const unnamed = await page.$$eval('a,button,input', els => els.filter(e => !(e.getAttribute('aria-label') || e.textContent.trim() || (e.labels && e.labels.length) || e.title)).length);
  assert.equal(unnamed, 0, 'every control has a name');
  assert.deepEqual(errors, [], 'no console errors');
  console.log(`ok: load ${load} ms, result shown`);
  await browser.close();
} finally { stop(); }
