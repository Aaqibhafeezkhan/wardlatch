// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// apple-audio-2026-08: CVE-2026-65339, Apple's "Audio" entry ("An app may be able to leak sensitive user
// information"), fixed in macOS Tahoe 26.6.2 (17 Aug 2026) and Sequoia 15.8 (14 Sep 2026), by the CVE record and
// Apple's notes 148281 and 149043 (read 16 Nov 2026). Not in CISA's catalog (2026.11.13). Below the fix on its own line
// is EXPOSED; Sonoma and older, a beta, an unread build, an unread or unplaceable version are UNKNOWN, never SAFE;
// off a Mac the row says iPhones and iPads are not checked. Each rule has a mutant in A5 that this file must catch.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appleCveRow, SYSTEM_VERSION_PLIST } from '../lib/macos.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'apple-audio-2026-08.json'), 'utf8'));
const KEV = JSON.parse(readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'kev-snapshot.json'), 'utf8'));
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-audio-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
// a release build unless a test says otherwise (26.6.2's shape: digits, a capital, digits)
const at = (version, build = '25G84', inc = INC) => appleCveRow(inc, { version, build }, 'darwin');

test('A1 the record is Apple\'s and the CVE record\'s: the CVE, the component, the two releases, not in CISA\'s catalog', () => {
  const a = INC.appleSystem;
  assert.equal(INC.type, 'apple-cve');
  assert.equal(a.cve, 'CVE-2026-65339');
  assert.equal(a.component, 'Audio');
  assert.deepEqual(a.releases, ['26.6.2', '15.8']);
  assert.deepEqual(a.sources, ['https://support.apple.com/en-us/148281', 'https://support.apple.com/en-us/149043']);
  for (const s of ['https://www.cve.org/CVERecord?id=CVE-2026-65339', 'https://support.apple.com/en-us/148281', 'https://support.apple.com/en-us/149043']) assert.ok(INC.sources.includes(s), s);
  // the house rule: no kev rows and no "exploited" unless CISA lists it; the KEV snapshot says it does not
  assert.equal(INC.kev, undefined);
  assert.ok(!KEV.listed[INC.id], 'CISA does not list it');
  assert.deepEqual(KEV.notListed[INC.id], ['CVE-2026-65339']);
  assert.doesNotMatch(JSON.stringify(INC), /exploit/i);
  // the posts' details that Apple's notes don't carry are not claimed as Apple's
  assert.doesNotMatch(a.said, /audiomxd|microphone|orange|indicator|token/i);
});

test('A2 below the fix on its own line is EXPOSED, at or past it SAFE: every boundary of both lines', () => {
  for (const [v, want] of [['26.6.1', '26.6.2'], ['26.6', '26.6.2'], ['26.0', '26.6.2'], ['26.6.1.9', '26.6.2'], ['15.7.9', '15.8'], ['15.0', '15.8'], ['15.7', '15.8']]) {
    const r = at(v);
    assert.equal(r.status, 'EXPOSED', v);
    assert.equal(r.fix, `Update macOS to ${want} or later (System Settings, General, Software Update).`, v);
    assert.match(r.reason, /CVE-2026-65339 under "Audio"/);
    assert.match(r.reason, /doesn't have that update yet/);
  }
  for (const v of ['26.6.2', '26.6.2.1', '26.7', '26.7.3', '15.8', '15.8.0', '15.8.3', '27', '27.0', '27.2.1', '28.0']) {
    const r = at(v);
    assert.equal(r.status, 'SAFE', v);
    assert.deepEqual(r.searched, [SYSTEM_VERSION_PLIST], v);
    assert.match(r.reason, /The flaw is in macOS itself, which is not read here/);
  }
});

test('A3 never a false SAFE: Sonoma and older, a beta, an odd build, an unread build, an unread or unplaceable version are UNKNOWN', () => {
  for (const v of ['14.8.9', '14.0', '13.7.8', '10.15.7']) { const r = at(v); assert.equal(r.status, 'UNKNOWN', v); assert.match(r.reason, /Apple's notes don't say whether this release is affected/, v); }
  // a beta of 26.6.2 carries 26.6.2's number: by the number alone it would be SAFE
  assert.equal(at('26.6.2', '25G5035r').status, 'UNKNOWN');
  assert.match(at('26.6.2', '25G5035r').reason, /is a beta/);
  assert.equal(at('27.3', '26C5035r').status, 'UNKNOWN');
  assert.equal(at('26.6.2', '25G84R').status, 'UNKNOWN', 'a build of no release shape');
  assert.equal(at('26.6.2', '').status, 'UNKNOWN', 'a build that could not be read');
  assert.match(at('26.6.2', '').reason, /build could not be read/);
  for (const v of ['', '20.1', '16.0', '25.9', 'x', '26.x']) assert.equal(at(v).status, 'UNKNOWN', `"${v}"`);
  assert.match(at('').reason, /^the macOS version could not be read/);
  // a beta below the fix is not SAFE either way; it is UNKNOWN (Apple's notes are for releases)
  assert.equal(at('26.6.1', '25G5020a').status, 'UNKNOWN');
  assert.equal(appleCveRow({ ...INC, appleSystem: undefined }, { version: '26.6.1', build: '25G84' }, 'darwin'), null);
});

test('A4 off a Mac: SAFE that there is no macOS, and it says iPhones and iPads are not checked', () => {
  for (const os of ['linux', 'win32']) {
    const r = appleCveRow(INC, { version: '', build: '' }, os);
    assert.equal(r.status, 'SAFE', os);
    assert.match(r.reason, /not a Mac/);
    assert.match(r.reason, /does not check iPhones, iPads/);
    assert.match(r.reason, /iOS and iPadOS 26\.6\.1 and 18\.7\.11/);
  }
  assert.match(INC.notCovered, /^iPhones, iPads/);
});

// A5: the planted mutations. Each is a change a careless edit could make; each must turn a test above red. The suite
// here re-runs A2/A3's assertions against the mutant and requires at least one to fail (and the original to pass).
const verdicts = (row) => {
  const out = [];
  const chk = (v, b, want) => out.push((row(v, b)?.status ?? 'none') === want);
  for (const v of ['26.6.1', '15.7.9']) chk(v, '25G84', 'EXPOSED');
  for (const v of ['26.6.2', '15.8', '27.2.1']) chk(v, '25G84', 'SAFE');
  for (const v of ['14.8.9', '', '20.1']) chk(v, '25G84', 'UNKNOWN');
  chk('26.6.2', '25G5035r', 'UNKNOWN'); chk('26.6.2', '', 'UNKNOWN');
  return out.every(Boolean);
};
test('A5 mutation proof: each planted mistake makes the verdict table fail; the true code passes it', () => {
  assert.ok(verdicts((v, b) => at(v, b)), 'the true code passes');
  const mutants = {
    'fix one release too late on Tahoe (26.6.3)': (v, b) => at(v, b, { ...INC, appleSystem: { ...INC.appleSystem, releases: ['26.6.3', '15.8'] } }),
    'Sequoia fix dropped (15 judged as older than every line)': (v, b) => at(v, b, { ...INC, appleSystem: { ...INC.appleSystem, releases: ['26.6.2'] } }),
    'fix one release too early on Sequoia (15.7.9)': (v, b) => at(v, b, { ...INC, appleSystem: { ...INC.appleSystem, releases: ['26.6.2', '15.7.9'] } }),
    'the unread-build rule removed': (v, b) => appleCveRow(INC, { version: v, build: b || '25G84' }, 'darwin'),
    'the beta label not passed (bare number judged)': (v, b) => appleCveRow(INC, { version: v, build: b && /[a-z]$/.test(b) ? '25G84' : b }, 'darwin'),
    'Sonoma called SAFE (a 14 line added at 14.0)': (v, b) => at(v, b, { ...INC, appleSystem: { ...INC.appleSystem, releases: ['26.6.2', '15.8', '14.0'] } }),
  };
  for (const [name, m] of Object.entries(mutants)) assert.equal(verdicts(m), false, `mutant survived: ${name}`);
});

// The command, on a Mac, with this test's own SystemVersion.plist (a preload maps the path), as test/macos-0.1.18 does
const plist = (v, build) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n${build === null ? '' : `  <key>ProductBuildVersion</key>\n  <string>${build}</string>\n`}  <key>ProductName</key>\n  <string>macOS</string>\n  <key>ProductVersion</key>\n  <string>${v}</string>\n</dict>\n</plist>\n`;
const cli = (v, build = '25G84', args = []) => {
  const f = join(fresh('plist'), 'SystemVersion.plist'); writeFileSync(f, plist(v, build));
  const pre = join(fresh('pre'), 'map.cjs');
  writeFileSync(pre, `const fs = require('node:fs'); const P = ${JSON.stringify(SYSTEM_VERSION_PLIST)}, V = ${JSON.stringify(f)};
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'openSync', 'existsSync']) { const o = fs[k]; fs[k] = (p, ...a) => o(String(p) === P ? V : p, ...a); }
require('node:module').syncBuiltinESMExports();\n`);
  const { NODE_OPTIONS, ...rest } = process.env;
  return spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), '--require', pre, BIN, '--incident', INC.id, ...args], { encoding: 'utf8', env: { ...rest, HOME: fresh('home'), PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
};
test('A6 the command on a Mac: EXPOSED exit 1 with the fix, SAFE exit 0, Sonoma and a beta exit 2, iPhones named', { skip: process.platform !== 'darwin' && 'macOS only: the version is read on a Mac' }, () => {
  const e = cli('26.6.1');
  assert.equal(e.status, 1, e.stdout + e.stderr);
  assert.match(e.stdout, /^EXPOSED +macOS Audio \(CVE-2026-65339\) +macOS 26\.6\.1 +\/System\/Library\/CoreServices\/SystemVersion\.plist$/m);
  assert.match(e.stdout, /fix: Update macOS to 26\.6\.2 or later/);
  assert.match(e.stdout, /not covered: iPhones, iPads/);
  assert.doesNotMatch(e.stdout, /CISA KEV/);
  const q = cli('15.7.9', '24G84', ['--json']);
  assert.equal(q.status, 1);
  assert.deepEqual(JSON.parse(q.stdout).results.map((x) => [x.kind, x.status, x.version]), [['macos', 'EXPOSED', '15.7.9']]);
  const s = cli('26.7.3', '25H31', ['--json']);
  assert.equal(s.status, 0, s.stdout); assert.deepEqual(JSON.parse(s.stdout).results.map((x) => x.status), ['SAFE']);
  for (const [v, b] of [['14.8.9', '23J84'], ['26.6.2', '25G5035r'], ['26.6.2', null]]) {
    const u = cli(v, b);
    assert.equal(u.status, 2, `${v} ${b}: ${u.stdout}`);
    assert.match(u.stdout, /^UNKNOWN +macOS Audio/m);
  }
});
