// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The coverage protocol (docs/COVERAGE-PROTOCOL.md), held by machine. Offline: the sources are the committed snapshot
// test/support/fixtures/coverage-snapshot.json (scripts/coverage/refresh.mjs writes it from the network). Every item in
// a covered class must be named in an incident file or declined with a reason and a review date. Each rule here has a
// control that makes it fail: the 16 Nov 2026 miss itself (CVE-2026-65339, fixed 17 Aug, named nowhere until today)
// is replayed and must come back as a gap.
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, report, items, classesOf, namedCves, incomplete, SNAPSHOT, DECLINED, MAX_AGE_DAYS, SOURCES, RUNS_ON, IDENTITY } from '../scripts/coverage/check.mjs';
import { parseIndex, parseNotes, macosRelease, isoDate, htmlText } from '../scripts/coverage/apple-notes.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SNAP = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
const DEC = JSON.parse(readFileSync(DECLINED, 'utf8'));
const NAMED = namedCves();
const TODAY = new Date().toISOString().slice(0, 10);
const clone = (x) => JSON.parse(JSON.stringify(x));
const run = (o = {}) => check({ snapshot: o.snapshot ?? SNAP, named: o.named ?? NAMED, declined: o.declined ?? DEC, today: o.today ?? TODAY });

test('C1 the committed snapshot, incidents and declined list pass: a complete read of every source, no gap, no expired decline', () => {
  const r = run();
  assert.deepEqual(r.why, [], 'complete');
  assert.deepEqual(r.gaps.map((g) => g.key), [], 'no gaps');
  assert.deepEqual(r.expired.map((e) => e.key), [], `declines past their review date: run the triage (docs/COVERAGE-PROTOCOL.md)`);
  assert.deepEqual(r.badDeclines, []);
  assert.equal(r.ok, true);
  assert.match(report(r), /NO GAPS, from a complete read of: apple-macos, cisa-kev$/);
  // the read is named: every source with its own counts
  assert.deepEqual(r.sources.map((s) => s.id), SOURCES);
  assert.ok(r.inScope > 100 && r.total > r.inScope, `${r.inScope} of ${r.total}`);
});

test('C2 the 16 Nov 2026 miss, replayed: without apple-audio-2026-08, CVE-2026-65339 is a gap and the check fails', () => {
  // the source has it: Apple's notes for Tahoe 26.6.2 and Sequoia 15.8, in the snapshot
  const rel = SNAP.apple.filter((r) => r.entries.some((e) => e.cves.includes('CVE-2026-65339'))).map((r) => r.name);
  assert.deepEqual(rel.sort(), ['macOS Sequoia 15.8', 'macOS Tahoe 26.6.2']);
  assert.deepEqual(classesOf('An app may be able to leak sensitive user information'), ['privacy']);
  assert.deepEqual(NAMED.get('CVE-2026-65339'), ['apple-audio-2026-08']);
  const named = new Map(NAMED); named.delete('CVE-2026-65339');
  const r = run({ named });
  assert.equal(r.ok, false);
  assert.deepEqual(r.gaps.map((g) => g.key), ['CVE-2026-65339']);
  assert.match(report(r), /^GAP CVE-2026-65339 \[identity,privacy\] Audio: An app may be able to leak sensitive user information \(macOS Sequoia 15\.8; macOS Tahoe 26\.6\.2\)$/m);
  assert.match(report(r), /FAIL$/);
});

test('C3 a declined entry removed is a gap; one past its review date, or with no reason, fails', () => {
  const pick = DEC.entries.find((e) => /^CVE-/.test(e.key));
  const r = run({ declined: { entries: DEC.entries.filter((e) => e !== pick) } });
  assert.deepEqual(r.gaps.map((g) => g.key), [pick.key]); assert.equal(r.ok, false);
  const late = run({ declined: { entries: DEC.entries.map((e) => (e === pick ? { ...e, reviewBy: '2026-01-01' } : e)) } });
  assert.deepEqual(late.expired.map((e) => e.key), [pick.key]); assert.equal(late.ok, false);
  assert.match(report(late), new RegExp(`^EXPIRED ${pick.key}: `, 'm'));
  for (const bad of [{ ...pick, reason: '' }, { ...pick, reason: 'ok' }, { ...pick, reason: 'two\nlines of reason here' }, { ...pick, reviewBy: undefined }, { ...pick, reason: 'x'.repeat(241) }]) {
    const b = run({ declined: { entries: DEC.entries.map((e) => (e === pick ? bad : e)) } });
    assert.equal(b.ok, false, JSON.stringify(bad).slice(0, 80)); assert.ok(b.badDeclines.length);
  }
  // declining twice is a mistake too
  assert.equal(run({ declined: { entries: [...DEC.entries, pick] } }).ok, false);
  // every decline is one line with a date, and every one is used
  for (const e of DEC.entries) { assert.ok(e.reason.length >= 12 && e.reason.length <= 240 && !e.reason.includes('\n'), e.key); assert.match(e.reviewBy, /^\d{4}-\d{2}-\d{2}$/, e.key); }
  assert.deepEqual(run().unusedDeclines.map((d) => d.key), []);
});

test('C4 "no gaps" only from a complete read: a missing source, a short read or a stale snapshot is INCOMPLETE and fails', () => {
  const cases = {
    'no KEV source': (s) => { s.sources = s.sources.filter((x) => x.id !== 'cisa-kev'); s.kev = []; },
    'no Apple source': (s) => { s.sources = s.sources.filter((x) => x.id !== 'apple-macos'); s.apple = []; },
    'one Apple release not read': (s) => { s.apple.pop(); },
    'an Apple page read with no entries': (s) => { s.apple.find((r) => r.entries.length).entries = []; },
    'the index read not reaching the window': (s) => { s.sources.find((x) => x.id === 'apple-macos').indexOldest = '2026-10-01'; },
    'KEV read short': (s) => { s.sources.find((x) => x.id === 'cisa-kev').read -= 1; },
    'KEV rows dropped': (s) => { s.kev.pop(); },
  };
  for (const [name, f] of Object.entries(cases)) {
    const s = clone(SNAP); f(s);
    // the declines are emptied too: an incomplete read must fail even when it finds no gap at all
    const r = check({ snapshot: s, named: NAMED, declined: { entries: [] }, today: TODAY });
    assert.equal(r.complete, false, name); assert.equal(r.ok, false, name);
    assert.doesNotMatch(report(r), /NO GAPS/, name); assert.match(report(r), /^INCOMPLETE/m, name);
  }
  // even with nothing in scope at all, an empty read is never "no gaps"
  const empty = check({ snapshot: { sources: [], apple: [], kev: [], read: SNAP.read, since: SNAP.since }, named: NAMED, declined: { entries: [] }, today: TODAY });
  assert.equal(empty.gaps.length, 0); assert.equal(empty.ok, false);
  // the age gate: the day after MAX_AGE_DAYS is incomplete; the day the snapshot was read is not
  const read = Date.parse(SNAP.read);
  const day = (n) => new Date(read + n * 86400000).toISOString().slice(0, 10);
  assert.deepEqual(incomplete(SNAP, day(0)), []);
  assert.match(incomplete(SNAP, day(MAX_AGE_DAYS + 1)).join(' '), /read \d+ days ago/);
});

test('C5 the snapshot is the sources\' own words: Apple entries carry a component, an impact and CVE numbers; KEV rows a date', () => {
  for (const r of SNAP.apple) {
    assert.ok(macosRelease(r.name), r.name); assert.match(r.date, /^\d{4}-\d{2}-\d{2}$/); assert.ok(r.date >= SNAP.since, r.name);
    if (!r.noCves) assert.match(r.url, /^https:\/\/support\.apple\.com\/en-us\/\d+$/, r.name);
    for (const e of r.entries) { assert.ok(e.component && e.impact, r.name); for (const c of e.cves) assert.match(c, /^CVE-\d{4}-\d{4,}$/); }
  }
  for (const k of SNAP.kev) { assert.match(k.cve, /^CVE-\d{4}-\d{4,}$/); assert.ok(k.dateAdded >= SNAP.since, k.cve); }
  // the KEV rows Wardlatch carries in incident files are in the window's rows (the two snapshots agree)
  const kevSnap = JSON.parse(readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'kev-snapshot.json'), 'utf8'));
  assert.equal(kevSnap.catalogVersion, SNAP.sources.find((s) => s.id === 'cisa-kev').catalogVersion);
  // an Apple entry printed without a CVE number is kept, by release, component and place
  assert.ok(items(SNAP).some((i) => /^apple:macOS Sequoia 15\.8:Shortcuts:\d+$/.test(i.key)));
});

// The readers, on planted pages: the completeness gates must be able to say no.
const note = (entries, extra = '') => `<html><body><h1>About the security content of macOS Tahoe 26.6.2</h1><p>Released August 17, 2026</p>${entries.map((e) => `<p>${e.c}</p><p>Available for: macOS Tahoe</p>${e.i === null ? '' : `<p>Impact: ${e.i}</p>`}<p>Description: A logic issue was addressed with improved checks.</p>${e.cves.map((c) => `<p>${c}: someone</p>`).join('')}`).join('')}${extra}<h2>Additional recognition</h2><p>Audio</p><p>We would like to acknowledge someone.</p></body></html>`;
test('C6 the notes reader: a page read whole parses; a CVE outside every entry, or an entry with no impact, throws', () => {
  const ok = parseNotes(note([{ c: 'Audio', i: 'An app may be able to leak sensitive user information', cves: ['CVE-2026-65339'] }, { c: 'Kernel', i: 'An app may be able to gain root privileges', cves: ['CVE-2026-1001', 'CVE-2026-1002'] }]));
  assert.equal(ok.title, 'macOS Tahoe 26.6.2'); assert.equal(ok.released, 'August 17, 2026');
  assert.deepEqual(ok.entries.map((e) => [e.component, e.cves]), [['Audio', ['CVE-2026-65339']], ['Kernel', ['CVE-2026-1001', 'CVE-2026-1002']]]);
  assert.throws(() => parseNotes(note([{ c: 'Audio', i: 'x', cves: ['CVE-2026-65339'] }], '<p>See also CVE-2026-9999 in a sentence.</p>')), /CVE number\(s\) on the page in no entry read: CVE-2026-9999/);
  assert.throws(() => parseNotes(note([{ c: 'Audio', i: null, cves: ['CVE-2026-65339'] }])), /impact missing/);
  assert.throws(() => parseNotes('<p>nothing here</p>'), /no "About the security content of" heading/);
  // an entry Apple prints without a CVE number is kept, not dropped
  assert.deepEqual(parseNotes(note([{ c: 'Shortcuts', i: 'A shortcut may be able to access sensitive user data without permission', cves: [] }])).entries.map((e) => e.cves), [[]]);
});

const row = (name, url, date, noCves = false) => `<tr><td><p>${url ? `<a href="${url}">${name}</a>` : name}</p>${noCves ? '<div><p>This update has no published CVE entries.</p></div>' : ''}</td><td><p>macOS Tahoe</p></td><td><p>${date}</p></td></tr>`;
test('C7 the index reader: rows with a page, rows Apple gives none, and a row it can\'t read throws', () => {
  const html = `<table><tr><th>Name</th><th>For</th><th>Date</th></tr>${row('macOS Tahoe 26.6.2', 'https://support.apple.com/en-us/148281', '17 Aug 2026')}${row('macOS Golden Gate 27.0.1', '', '28 Sep 2026', true)}${row('iOS 26.6.1 and iPadOS 26.6.1', 'https://support.apple.com/en-us/148282', '17 Aug 2026')}</table>`;
  assert.deepEqual(parseIndex(html).map((r) => [r.name, r.date, r.noCves]), [['macOS Tahoe 26.6.2', '2026-08-17', false], ['macOS Golden Gate 27.0.1', '2026-09-28', true], ['iOS 26.6.1 and iPadOS 26.6.1', '2026-08-17', false]]);
  assert.throws(() => parseIndex(`<table>${row('macOS Tahoe 26.6.2', 'https://support.apple.com/en-us/148281', 'soon')}</table>`), /not read whole/);
  assert.throws(() => parseIndex(`<table>${row('macOS Tahoe 26.6.3', '', '1 Dec 2026')}</table>`), /neither a page nor/);
  assert.throws(() => parseIndex('<p>no table</p>'), /no rows/);
  assert.deepEqual(macosRelease('macOS Golden Gate 27'), { line: 'Golden Gate', version: '27' });
  assert.deepEqual(macosRelease('macOS Sequoia 15.8'), { line: 'Sequoia', version: '15.8' });
  for (const n of ['iOS 26.6.1 and iPadOS 26.6.1', 'macOS Sequoia and macOS Tahoe', 'Safari 27', 'macOS Tahoe 26.6 and later']) assert.equal(macosRelease(n), null, n);
  assert.equal(isoDate('6 Aug 2026'), '2026-08-06'); assert.equal(isoDate('Aug 6 2026'), '');
  assert.equal(htmlText('<p>a&amp;b</p><script>x</script><p> c </p>'), 'a&b\nc');
});

test('C8 the classes: each of the owner\'s classes matches Apple\'s own impact lines, and a line outside them matches none', () => {
  const want = {
    'An app may be able to access sensitive user data': ['privacy'],
    'A malicious application may be able to bypass Privacy preferences': ['privacy'],
    'An app may be able to break out of its sandbox': ['sandbox'],
    'An app may bypass Gatekeeper checks': ['code-signing'],
    'An attacker in a privileged network position may be able to impersonate a Kerberos KDC': ['identity', 'trust'],
    'An app may be able to gain root privileges': ['privilege'],
    'Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited': ['exploited'],
    'An app may be able to cause unexpected system termination': [],
    'Processing maliciously crafted web content may lead to an unexpected Safari crash': [],
  };
  for (const [impact, classes] of Object.entries(want)) assert.deepEqual(classesOf(impact), classes, impact);
});

test('C10 every skip says where the flawed code runs: a decline without runsOn, or with another word, fails the check', () => {
  for (const e of DEC.entries) assert.ok(RUNS_ON.includes(e.runsOn), `${e.key}: runsOn ${e.runsOn}`);
  const pick = DEC.entries.find((e) => e.runsOn === 'server');
  for (const bad of [(({ runsOn, ...e }) => e)(pick), { ...pick, runsOn: 'appliance' }, { ...pick, runsOn: '' }]) {
    const r = run({ declined: { entries: DEC.entries.map((e) => (e === pick ? bad : e)) } });
    assert.equal(r.ok, false, JSON.stringify(bad.runsOn)); assert.match(report(r), new RegExp(`^BAD DECLINE ${pick.key}: no runsOn`, 'm'));
  }
  // the PR #37 miss: ScreenConnect's client flaw was declined as a "self-hosted server". It is named now, and every
  // decline worded as a server or an appliance says server; the re-read of 16 Nov 2026 moved the rest
  assert.equal(DEC.entries.find((e) => e.key === 'CVE-2026-84869'), undefined);
  for (const e of DEC.entries.filter((x) => /^(self-hosted server|network appliance)/.test(x.reason))) assert.equal(e.runsOn, 'server', e.key);
  // the re-read's client-side candidates: listed, not added (no incident names them)
  const reread = ['CVE-2026-124194', 'CVE-2026-41091', 'CVE-2026-45498', 'CVE-2026-8398', 'CVE-2026-87886', 'CVE-2026-34926', 'CVE-2026-123039', 'CVE-2026-85102', 'CVE-2025-61624', 'CVE-2025-25249'];
  for (const k of reread) { const e = DEC.entries.find((x) => x.key === k); assert.ok(e?.candidate && e.runsOn !== 'server' && /16 Nov/.test(e.reason), k); assert.equal(NAMED.has(k), false, k); }
});

test('C11 the identity/authority class reads Apple\'s Description line too, and a snapshot without that line is not a complete read', () => {
  const want = [
    ['An app may be able to access protected user data', 'A logic issue was addressed with improved checks.', ['identity', 'privacy']],
    ['An app may be able to cause unexpected app behavior', 'A case-insensitive comparison was replaced with an exact one.', ['identity']],
    ['A remote attacker may be able to cause unexpected app behavior', 'This issue was addressed with improved Unicode normalization.', ['identity']],
    ['A malicious app may be able to forge a request', 'An authentication issue was addressed: requests could be forged.', ['identity']],
    ['An attacker may be able to spoof the sender of a message', 'The issue was addressed with improved validation.', ['identity', 'trust']],
    // the controls: a logic issue with no permission in it, and a type confusion, are not this class
    ['An app may be able to cause unexpected system termination', 'A logic issue was addressed with improved checks.', []],
    ['Processing maliciously crafted web content may lead to memory corruption', 'A type confusion issue was addressed with improved checks.', []],
  ];
  for (const [impact, description, classes] of want) assert.deepEqual(classesOf(impact, description), classes, `${impact} / ${description}`);
  // without the Description, the description-only cases fall out of scope: the instrument can tell the two apart
  assert.deepEqual(classesOf('An app may be able to cause unexpected app behavior'), []);
  // the snapshot carries the line on every entry; strip it from one and the read is INCOMPLETE
  assert.ok(SNAP.apple.every((r) => r.entries.every((e) => typeof e.description === 'string' && e.description)), 'every entry has its Description');
  const s = clone(SNAP); delete s.apple.find((r) => r.entries.length).entries[0].description;
  const r = check({ snapshot: s, named: NAMED, declined: DEC, today: TODAY });
  assert.equal(r.ok, false); assert.match(r.why.join(' '), /1 entries carry no Description line/);
  // a new CVE of the shape, planted in the snapshot, is a gap until it is named or declined
  const p = clone(SNAP); p.apple[0].entries.push({ component: 'Planted', impact: 'An app may be able to cause unexpected app behavior', description: 'A path normalization issue was addressed.', cves: ['CVE-2026-999999'] });
  const g = check({ snapshot: p, named: NAMED, declined: DEC, today: TODAY });
  assert.deepEqual(g.gaps.map((x) => [x.key, x.classes]), [['CVE-2026-999999', ['identity']]]);
  assert.ok(IDENTITY.words && IDENTITY.logic && IDENTITY.authority);
});

test('C9 the command: exit 0 with the sources named on the committed files; exit 1 with GAP lines when the declines are taken away', () => {
  const ok = spawnSync(process.execPath, [join(ROOT, 'scripts', 'coverage', 'check.mjs'), '--today', SNAP.read.slice(0, 10)], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /^ {2}apple-macos: https:\/\/support\.apple\.com\/en-us\/100100 /m);
  assert.match(ok.stdout, /^ {2}cisa-kev: https:\/\/www\.cisa\.gov\/.* rows read; \d+ added in the window\)$/m);
  const d = mkdtempSync(join(tmpdir(), 'wardlatch-coverage-'));
  try {
    const f = join(d, 'declined.json'); writeFileSync(f, JSON.stringify({ entries: [] }));
    const bad = spawnSync(process.execPath, [join(ROOT, 'scripts', 'coverage', 'check.mjs'), '--declined', f, '--today', SNAP.read.slice(0, 10)], { encoding: 'utf8' });
    assert.equal(bad.status, 1);
    assert.equal((bad.stdout.match(/^GAP /gm) ?? []).length, DEC.entries.length);
    assert.match(bad.stdout, /FAIL$/m);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
