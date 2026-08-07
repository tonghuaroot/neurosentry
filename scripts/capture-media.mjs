// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0
//
// capture-media.mjs — automated product media for the docs.
// Drives the live console with Playwright: captures high-DPI screenshots of the
// key views and records a video of the guided tour. Re-run whenever the product
// changes so the docs stay current.
//
//   NS_BASE=http://<host>:8080 \
//   NS_EMAIL=admin@neurosentry.local NS_PASS=... NS_TENANT=default \
//   node scripts/capture-media.mjs
//
// Then convert the recorded video with scripts/media-to-gif.sh.

import { chromium } from 'playwright';
import { mkdir, rename, readdir } from 'node:fs/promises';
import path from 'node:path';

const BASE   = process.env.NS_BASE   || 'http://127.0.0.1:8080';
const EMAIL  = process.env.NS_EMAIL  || 'admin@neurosentry.local';
const PASS   = process.env.NS_PASS   || 'NeuroDemo2026!';
const TENANT = process.env.NS_TENANT || 'default';
const OUT    = 'docs/media';
const SHOTS  = path.join(OUT, 'screenshots');
const VIDEO  = path.join(OUT, 'video');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function login() {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant_slug: TENANT, email: EMAIL, password: PASS }),
  });
  if (!res.ok) throw new Error(`login failed: ${res.status}`);
  const { token } = await res.json();
  if (!token) throw new Error('no token in login response');
  return token;
}

// A context pre-authenticated as the admin, with the first-run welcome suppressed.
async function authedContext(browser, token, opts = {}) {
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: opts.video ? 1 : 2,
    recordVideo: opts.video ? { dir: VIDEO, size: { width: 1440, height: 900 } } : undefined,
  });
  await ctx.addInitScript((t) => {
    localStorage.setItem('ns_token', t);
    localStorage.setItem('ns_seen_welcome', '1');
  }, token);
  return ctx;
}

async function gotoApp(page) {
  // The console keeps an SSE stream open, so 'networkidle' never settles — wait
  // for the DOM + a rendered view instead.
  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('.page-title', { timeout: 20000 }).catch(() => {});
  // Wait for the overview KPIs to load (they start as an em-dash placeholder).
  await page
    .waitForFunction(() => {
      const e = document.querySelector('#s-open');
      return e && !['–', '—', ''].includes(e.textContent.trim());
    }, { timeout: 15000 })
    .catch(() => {});
  await wait(1500);
}

// Nav to a view and wait until its data has actually rendered (not the loading
// placeholder), so screenshots show a populated console.
async function settleView(page, view) {
  await page.evaluate((v) => window.nav && window.nav(v), view);
  const ready = {
    overview: '#nstri-hero .nstri-row, #nstri-hero .nstri-empty',
    kb: '.kb-card',
    detections: '#det-body tr',
    gateway: '#mcp-body tr',
    cases: '#cases-list .case, #cases-empty',
    fleet: '#fleet-body tr',
  }[view];
  if (ready) await page.waitForSelector(ready, { timeout: 10000 }).catch(() => {});
  await wait(view === 'overview' ? 2200 : 1800);
}

async function shot(page, name) {
  const file = path.join(SHOTS, `${name}.png`);
  await page.screenshot({ path: file });
  console.log('  ✓', file);
}

async function captureScreenshots(browser, token) {
  const ctx = await authedContext(browser, token);
  const page = await ctx.newPage();
  await gotoApp(page);

  const views = ['overview', 'threats', 'cases', 'detections', 'kb', 'gateway', 'fleet', 'audit'];
  for (const v of views) {
    try {
      await settleView(page, v);
      await shot(page, v);
    } catch (e) { console.log('  ! view', v, e.message); }
  }

  // KB article drawer
  try {
    await page.evaluate(() => window.nav && window.nav('kb'));
    await wait(1000);
    await page.click('.kb-card', { timeout: 5000 });
    await page.waitForSelector('.nsdrw-panel', { timeout: 5000 });
    await wait(700);
    await shot(page, 'kb-article');
    await page.keyboard.press('Escape');
  } catch (e) { console.log('  ! kb-article', e.message); }

  // Cross-layer attack chain (finding drawer)
  try {
    await page.evaluate(() => window.nav && window.nav('overview'));
    await wait(1200);
    await page.click('#nstri-hero .nstri-row', { timeout: 5000 });
    await page.waitForSelector('.nsdrw-panel .nsg-wrap svg', { timeout: 6000 });
    await wait(1400); // let the chain ignite
    await shot(page, 'attack-chain');
    await page.keyboard.press('Escape');
  } catch (e) { console.log('  ! attack-chain', e.message); }

  await ctx.close();
}

async function captureTourVideo(browser, token) {
  const ctx = await authedContext(browser, token, { video: true });
  const page = await ctx.newPage();
  await gotoApp(page);
  await wait(600);
  await page.evaluate(() => window.nsTourStart && window.nsTourStart());

  // Step through the tour, pausing on each step so the video is watchable.
  for (let i = 0; i < 8; i++) {
    await wait(2400);
    const next = await page.$('#nstour-next');
    if (!next) break;
    await next.click().catch(() => {});
  }
  await wait(1500);
  await ctx.close(); // finalizes the video file

  // Give the recorded file a stable name.
  const files = (await readdir(VIDEO)).filter((f) => f.endsWith('.webm'));
  if (files.length) {
    const newest = files.map((f) => path.join(VIDEO, f)).sort().pop();
    await rename(newest, path.join(VIDEO, 'guided-tour.webm')).catch(() => {});
    console.log('  ✓', path.join(VIDEO, 'guided-tour.webm'));
  }
}

async function main() {
  await mkdir(SHOTS, { recursive: true });
  await mkdir(VIDEO, { recursive: true });
  console.log(`Capturing NeuroSentry media from ${BASE}`);
  const token = await login();
  const browser = await chromium.launch();
  try {
    console.log('Screenshots:');
    await captureScreenshots(browser, token);
    console.log('Guided-tour video:');
    await captureTourVideo(browser, token);
  } finally {
    await browser.close();
  }
  console.log('Done. Convert the video with scripts/media-to-gif.sh');
}

main().catch((e) => { console.error(e); process.exit(1); });
