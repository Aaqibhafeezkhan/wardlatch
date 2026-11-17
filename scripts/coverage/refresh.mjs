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
import { parseIndex, parseNotes, macosRelease } from './apple-notes.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const INDEX = 'https://support.apple.com/en-us/100100';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i < 0 ? d : args[i + 1]; };
const months = Number(opt('--months', '6'));
const out = opt('--out', join(ROOT, 'test', 'support', 'fixtures', 'coverage-snapshot.json'));
if (!Number.isInteger(months) || months < 1 || months > 36) { console.error('--months: a whole number from 1 to 36'); process.exit(2); }

const now = new Date();
const sinceDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - months, now.getUTCDate()));
const since = sinceDate.toISOString().slice(0, 10);

async function get(url) {
  const r = await fetch(url, { headers: { 'user-agent': 'wardlatch-coverage-refresh', accept: 'text/html,application/json' }, redirect: 'follow' });
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
  releases.push({ name: r.name, date: r.date, url: r.url, entries: n.entries.map((e) => ({ component: e.component, impact: e.impact, cves: e.cves })) });
  console.error(`${r.name} (${r.date}): ${n.entries.length} entries, ${n.cves.length} CVEs`);
}

const feed = JSON.parse(await get(KEV));
const rows = feed.vulnerabilities;
if (!Array.isArray(rows) || !rows.length || feed.count !== rows.length) throw new Error(`KEV feed says count ${feed.count} and holds ${Array.isArray(rows) ? rows.length : 'no'} rows: not a whole catalog`);
const kev = rows.filter((v) => v.dateAdded >= since)
  .map((v) => ({ cve: v.cveID, vendorProject: v.vendorProject, product: v.product, dateAdded: v.dateAdded, name: v.vulnerabilityName }))
  .sort((a, b) => (a.dateAdded === b.dateAdded ? a.cve.localeCompare(b.cve) : a.dateAdded < b.dateAdded ? 1 : -1));

const snapshot = {
  read: now.toISOString().slice(0, 19) + 'Z',
  since,
  sources: [
    { id: 'apple-macos', url: INDEX, indexRows: index.length, indexOldest: index.at(-1).date, macosReleasesInWindow: inWindow.length },
    { id: 'cisa-kev', url: KEV, catalogVersion: feed.catalogVersion, dateReleased: feed.dateReleased, count: feed.count, read: rows.length, inWindow: kev.length },
  ],
  apple: releases,
  kev,
};
writeFileSync(out, JSON.stringify(snapshot, null, 1) + '\n');
console.error(`wrote ${out}: ${releases.length} macOS releases since ${since}, ${releases.reduce((n, r) => n + r.entries.length, 0)} entries; ${kev.length} KEV rows (catalog ${feed.catalogVersion})`);
