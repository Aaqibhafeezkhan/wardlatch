#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The one network step of the coverage check (docs/COVERAGE-PROTOCOL.md): fetch the sources, read each one whole, and
// write test/support/fixtures/coverage-snapshot.json. The check itself (scripts/coverage/check.mjs, run by
// test/coverage-protocol.test.mjs) reads only that file, so CI needs no network.
//
//   node scripts/coverage/refresh.mjs [--months 6] [--out test/support/fixtures/coverage-snapshot.json]
//
// Sources, each read whole or nothing is written:
//   1. Apple's security releases index, support.apple.com/en-us/100100, and the notes page of every macOS release it
//      lists in the window (parseNotes refuses a page whose CVE numbers are not all placed in an entry);
//   2. CISA's Known Exploited Vulnerabilities feed (its `count` must equal the rows read, as scripts/kev-snapshot.mjs
//      requires), keeping every row added in the window.
// Wardlatch itself never runs this: it is a maintainer's step, like scripts/kev-snapshot.mjs.
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseIndex, parseNotes, macosRelease, CVE_RE } from './apple-notes.mjs';
import { EQUIVALENCE } from './check.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const INDEX = 'https://support.apple.com/en-us/100100';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const VINCE = 'https://kb.cert.org/vuls/api/';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i < 0 ? d : args[i + 1]; };
const months = Number(opt('--months', '6'));
const out = opt('--out', join(ROOT, 'test', 'support', 'fixtures', 'coverage-snapshot.json'));
if (!Number.isInteger(months) || months < 1 || months > 36) { console.error('--months: a whole number from 1 to 36'); process.exit(2); }

const now = new Date();
const sinceDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - months, now.getUTCDate()));
const since = sinceDate.toISOString().slice(0, 10);

// One accept type per request. MEASURED 16 Nov 2026: support.apple.com/en-us/149042 (Tahoe 26.7) answered 404 to
// "text/html,application/json" and 200 to "text/html", so the refresh could not be run at all.
async function get(url, accept = url.startsWith('https://support.apple.com/') ? 'text/html' : 'application/json') {
  const r = await fetch(url, { headers: { 'user-agent': 'wardlatch-coverage-refresh', accept }, redirect: 'follow' });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
}

const index = parseIndex(await get(INDEX));
// the index must reach back past the window, or the window was not read whole
if (index.at(-1).date > since) throw new Error(`the index's oldest row is ${index.at(-1).date}, after the window's start ${since}: not read whole`);
const inWindow = index.filter((r) => r.date >= since && macosRelease(r.name));
const releases = [];
for (const r of inWindow) {
  if (!r.url) { releases.push({ name: r.name, date: r.date, url: '', noCves: true, entries: [] }); continue; }
  const n = parseNotes(await get(r.url));
  if (n.title !== r.name) throw new Error(`${r.url}: the page is titled "${n.title}", the index says "${r.name}"`);
  releases.push({ name: r.name, date: r.date, url: r.url, entries: n.entries.map((e) => ({ component: e.component, impact: e.impact, description: e.description, cves: e.cves })) });
  console.error(`${r.name} (${r.date}): ${n.entries.length} entries, ${n.cves.length} CVEs`);
}

const feed = JSON.parse(await get(KEV));
const rows = feed.vulnerabilities;
if (!Array.isArray(rows) || !rows.length || feed.count !== rows.length) throw new Error(`KEV feed says count ${feed.count} and holds ${Array.isArray(rows) ? rows.length : 'no'} rows: not a whole catalog`);
const kev = rows.filter((v) => v.dateAdded >= since)
  .map((v) => ({ cve: v.cveID, vendorProject: v.vendorProject, product: v.product, dateAdded: v.dateAdded, name: v.vulnerabilityName }))
  .sort((a, b) => (a.dateAdded === b.dateAdded ? a.cve.localeCompare(b.cve) : a.dateAdded < b.dateAdded ? 1 : -1));

// 3. CERT/CC's vulnerability notes (16 Nov 2026, docs/PATTERN-IDENTITY-EQUIVALENCE.md): every monthly listing in the
// window, read whole (each month answers with a list), and for every note in the equivalence class its vulnerability
// rows and its vendors, so that a CVE number printed only in a vendor's addendum (VU#604762's yarn CVE-2026-11313) or
// in a reference is still an item.
const vuMonths = [];
for (let d = new Date(Date.UTC(sinceDate.getUTCFullYear(), sinceDate.getUTCMonth(), 1)); d <= now; d = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1))) vuMonths.push(`${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}`);
const cert = [];
let notesRead = 0;
const cvesIn = (...texts) => [...new Set(texts.flatMap((t) => JSON.stringify(t ?? '').match(CVE_RE) ?? []))].sort();
for (const m of vuMonths) {
  const list = JSON.parse(await get(`${VINCE}${m}/`));
  if (!Array.isArray(list)) throw new Error(`${VINCE}${m}/: not a list of notes: not read whole`);
  notesRead += list.length;
  for (const n of list) {
    if ((n.datefirstpublished ?? n.publicdate ?? '') < since) continue;
    if (!EQUIVALENCE.test(`${n.name}\n${n.overview}`)) continue;
    const vuls = JSON.parse(await get(`${VINCE}${n.idnumber}/vuls/`));
    const vendors = JSON.parse(await get(`${VINCE}${n.idnumber}/vendors/`));
    if (!Array.isArray(vuls) || !Array.isArray(vendors)) throw new Error(`${n.vuid}: its vulnerability rows or vendors are not lists: not read whole`);
    cert.push({ id: n.vuid, name: n.name, published: (n.datefirstpublished ?? '').slice(0, 10), url: `https://kb.cert.org/vuls/id/${n.idnumber}`,
      cves: cvesIn(n.cveids, n.overview, n.public, vuls.map((v) => [v.cve && `CVE-${v.cve}`, v.description]), vendors.map((v) => [v.statement, v.addendum, v.references])), vulsRead: true, vendorsRead: true });
    console.error(`${n.vuid} (${n.datefirstpublished?.slice(0, 10)}): in the equivalence class, ${cert.at(-1).cves.length} CVEs`);
  }
}

const snapshot = {
  read: now.toISOString().slice(0, 19) + 'Z',
  since,
  sources: [
    { id: 'apple-macos', url: INDEX, indexRows: index.length, indexOldest: index.at(-1).date, macosReleasesInWindow: inWindow.length },
    { id: 'cisa-kev', url: KEV, catalogVersion: feed.catalogVersion, dateReleased: feed.dateReleased, count: feed.count, read: rows.length, inWindow: kev.length },
    { id: 'cert-vu', url: VINCE, months: vuMonths, monthsInWindow: vuMonths.length, notesRead, inClass: cert.length },
  ],
  apple: releases,
  kev,
  cert,
};
writeFileSync(out, JSON.stringify(snapshot, null, 1) + '\n');
console.error(`wrote ${out}: ${releases.length} macOS releases since ${since}, ${releases.reduce((n, r) => n + r.entries.length, 0)} entries; ${kev.length} KEV rows (catalog ${feed.catalogVersion})`);
