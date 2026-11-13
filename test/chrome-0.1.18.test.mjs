// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: chrome-2026-11, corrected and widened.
//   - The bug: 0.1.16 judged every Chrome against 157.0.8103.50 alone, so a Chrome on the Extended Stable channel at
//     156.0.8078.96, which Google's Extended Stable post of 9 Nov 2026 lists as fixing CVE-2026-125350, read EXPOSED.
//     The Mac files now take Google's two fixes, one per line; Linux has no Extended Stable package and keeps 157's.
//   - Brave 1.99.56 (Chromium 157.0.8103.50, 10 Nov) and Vivaldi 8.3.4191.35 ("8.3 minor update 2", 10 Nov, which
//     Vivaldi says includes the fix) are read from their Info.plist, each against its own number.
//   - Microsoft Edge for Mac: Microsoft named no fixed desktop version (its notes, read 13 Nov 2026), so any Edge read is
//     REVIEW, never SAFE and never EXPOSED on a guess.
// No Brave, Vivaldi or Edge was installed on the Mac this was written on: their plists here are written to the version
// formats the vendors publish (Brave's carries Chromium's major in front, from brave-core's build scripts).
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVersionFiles } from '../lib/installs.mjs';
import { judgeVersion } from '../lib/binaries.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'chrome-2026-11.json'), 'utf8'));
const V = INC.versionFiles;
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-chrome18-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };
const APPS = { chrome: 'Google Chrome', brave: 'Brave Browser', vivaldi: 'Vivaldi', edge: 'Microsoft Edge' };
const plist = (v, build = '1') => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>CFBundleExecutable</key>\n\t<string>x</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string>${v}</string>\n\t<key>CFBundleVersion</key>\n\t<string>${build}</string>\n</dict>\n</plist>\n`;
const app = (root, which, text) => { const f = join(root, 'Applications', `${APPS[which]}.app`, 'Contents', 'Info.plist'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return f; };
// the system-wide places of one product only
const ruleOf = (product, files = V.files) => ({ ...V, files: files.filter((f) => f.path.startsWith('/Applications/') && (f.product ?? 'Google Chrome') === product) });
const one = (which, product, v, rule = ruleOf(product)) => { const root = fresh(`${which}-${v}-${Math.random()}`); app(root, which, plist(v)); const rows = checkVersionFiles(rule, { root }); assert.equal(rows.length, 1, JSON.stringify(rows)); return rows[0]; };
const cli = (home, args = []) => {
  const { NODE_OPTIONS, ...rest } = process.env;
  return spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'chrome-2026-11', ...args], { encoding: 'utf8', env: { ...rest, HOME: home, PATH: fresh(`p-${Math.random()}`), WARDLATCH_TEST_OWN_DIR: dir } });
};

test('X1 the bug: a fixed Extended Stable Chrome (156.0.8078.96, 9 Nov) is no longer EXPOSED; below it, and 157 below .50, still are', () => {
  for (const [v, want, why] of [['156.0.8078.96', 'REVIEW'], ['156.0.8078.100', 'REVIEW'], ['156.0.8078.95', 'EXPOSED', 'fixed in 156.0.8078.96'], ['156.0.8075.120', 'EXPOSED', 'fixed in 156.0.8078.96'],
    ['157.0.8103.49', 'EXPOSED', 'fixed in 157.0.8103.50'], ['157.0.8103.50', 'REVIEW'], ['157.0.8103.51', 'REVIEW'], ['157.0.8103.79', 'REVIEW'], ['158.0.8127.36', 'REVIEW'],
    ['155.0.7950.1', 'EXPOSED', /no fix for the 155\.0 line/]]) {
    const r = one('chrome', 'Google Chrome', v);
    assert.equal(r.status, want, `${v}: ${JSON.stringify(r)}`);
    if (why) assert.match(r.reason, why instanceof RegExp ? why : new RegExp(`^${why.replace(/\./g, '\\.')}$`), v);
    if (want === 'REVIEW') assert.match(r.reason, /Wardlatch can't see which version is running/);
  }
  // the regression's control: the 0.1.16 rule (157.0.8103.50 for every Chrome) reads the fixed Extended Stable as EXPOSED
  const old = { ...ruleOf('Google Chrome'), fixedIn: undefined, minVersion: '157.0.8103.50' };
  assert.equal(one('chrome', 'Google Chrome', '156.0.8078.96', old).status, 'EXPOSED', 'the control: the old rule reproduces the bug');
  assert.equal(judgeVersion('156.0.8078.96', V).status, 'SAFE', 'the shared rule takes the Extended Stable fix (the file makes it REVIEW)');
});

test('X2 Linux has no Extended Stable package: dpkg\'s google-chrome-stable keeps 157.0.8103.50 as its one fix', () => {
  const dpkg = V.files.find((f) => f.path === '/var/lib/dpkg/status');
  assert.deepEqual(dpkg.rule, { minVersion: '157.0.8103.50' });
  const root = fresh('dpkg'); const f = join(root, 'var', 'lib', 'dpkg', 'status'); mkdirSync(dirname(f), { recursive: true });
  writeFileSync(f, 'Package: google-chrome-stable\nStatus: install ok installed\nArchitecture: amd64\nVersion: 156.0.8078.96-1\n\n');
  const rows = checkVersionFiles({ ...V, files: [dpkg] }, { root });
  assert.deepEqual(rows.map((r) => [r.status, r.reason]), [['EXPOSED', 'fixed in 157.0.8103.50']]);
});

test('X3 Brave: judged as Brave numbers it, with Chromium\'s major in front or not; 1.99.56 is the fix', () => {
  for (const [v, want, ver] of [['157.1.99.56', 'REVIEW', '1.99.56'], ['1.99.56', 'REVIEW', '1.99.56'], ['158.1.100.2', 'REVIEW', '1.100.2'],
    ['157.1.99.55', 'EXPOSED', '1.99.55'], ['156.1.98.120', 'EXPOSED', '1.98.120'], ['1.98.120', 'EXPOSED', '1.98.120']]) {
    const r = one('brave', 'Brave', v);
    assert.deepEqual([r.status, r.version, r.product], [want, ver, 'Brave'], v);
    if (want === 'EXPOSED') assert.equal(r.reason, 'fixed in 1.99.56');
    if (want === 'REVIEW') assert.match(r.reason, /Brave built on Chromium 157\.0\.8103\.50/);
    assert.match(r.fix, /^Update Brave to 1\.99\.56/); assert.match(r.reviewFix, /^Restart Brave/);
  }
  // a number in a shape Brave doesn't use is not guessed at: UNKNOWN
  for (const v of ['2.0.1', '157.2.0.1', '1.99']) assert.equal(one('brave', 'Brave', v).status, 'UNKNOWN', v);
  // the control for the prefix: read whole, 157.1.99.55 compares above 1.99.56 and a vulnerable Brave would read SAFE
  assert.equal(judgeVersion('157.1.99.55', { minVersion: '1.99.56' }).status, 'SAFE');
  // and judged against Chrome's numbers instead of its own, a fixed Brave would read EXPOSED
  assert.equal(judgeVersion('1.99.56', V).status, 'EXPOSED');
});

test('X4 Vivaldi: 8.3.4191.35 ("8.3 minor update 2") is the fix', () => {
  for (const [v, want] of [['8.3.4191.30', 'EXPOSED'], ['8.3.4191.34', 'EXPOSED'], ['8.2.4100.10', 'EXPOSED'], ['8.3.4191.35', 'REVIEW'], ['8.3.4191.40', 'REVIEW'], ['8.4.4250.3', 'REVIEW']]) {
    const r = one('vivaldi', 'Vivaldi', v);
    assert.deepEqual([r.status, r.product], [want, 'Vivaldi'], v);
    if (want === 'EXPOSED') assert.equal(r.reason, 'fixed in 8.3.4191.35');
  }
  // the control: against Chrome's numbers every Vivaldi would read EXPOSED
  assert.equal(judgeVersion('8.3.4191.35', V).status, 'EXPOSED');
});

test('X5 Microsoft Edge for Mac: REVIEW whatever its version, never SAFE and never EXPOSED; unread is UNKNOWN', () => {
  for (const v of ['150.0.3000.1', '157.0.4341.42', '157.0.4341.60', '170.0.1.1']) {
    const r = one('edge', 'Microsoft Edge', v);
    assert.deepEqual([r.status, r.product, r.version], ['REVIEW', 'Microsoft Edge', v], v);
    assert.match(r.reason, /^Microsoft has not named a fixed Edge for Mac/);
    assert.match(r.reviewFix, /microsoft-edge-relnotes-security/);
  }
  const root = fresh('edge-nokey'); app(root, 'edge', plist('157.0.4341.42').replace('CFBundleShortVersionString', 'CFBundleOther'));
  assert.deepEqual(checkVersionFiles(ruleOf('Microsoft Edge'), { root }).map((r) => [r.status, r.product]), [['UNKNOWN', 'Microsoft Edge']]);
  const locked = fresh('edge-locked'); chmodSync(app(locked, 'edge', plist('157.0.4341.42')), 0);
  assert.deepEqual(checkVersionFiles(ruleOf('Microsoft Edge'), { root: locked }).map((r) => r.status), ['UNKNOWN']);
  // the control: without reviewAlways, Edge's own numbers judged as Chrome's give a verdict nobody published
  const strip = ruleOf('Microsoft Edge', V.files.map(({ reviewAlways, ...f }) => f));
  assert.equal(one('edge', 'Microsoft Edge', '157.0.4341.42', strip).status, 'EXPOSED');
  assert.equal(one('edge', 'Microsoft Edge', '158.0.1.1', strip).status, 'SAFE');
});

test('X6 every other browser in Chrome\'s file carries its own rule (or reviewAlways), fix and review advice, so none is judged as Chrome', () => {
  const others = V.files.filter((f) => f.product);
  assert.deepEqual([...new Set(others.map((f) => f.product))].sort(), ['Brave', 'Microsoft Edge', 'Vivaldi']);
  for (const f of others) {
    assert.ok(f.rule || f.reviewAlways, `${f.path}: a rule of its own`);
    assert.ok(f.reviewFix, `${f.path}: review advice of its own`);
    if (!f.reviewAlways) assert.ok(f.fix && f.reviewWhenFixed, `${f.path}: fix and reviewWhenFixed`);
    if (f.reviewAlways) assert.ok(!f.rule && !f.reviewWhenFixed, `${f.path}: nothing that could make it SAFE or EXPOSED`);
  }
  for (const p of ['/Applications/', '~/Applications/']) for (const a of Object.values(APPS)) assert.ok(V.files.some((f) => f.path === `${p}${a}.app/Contents/Info.plist`), `${p}${a}`);
});

test('X7 the command: Brave EXPOSED with Brave\'s fix (exit 1), Edge REVIEW with Edge\'s advice, a fixed Extended Stable Chrome REVIEW', () => {
  const home = fresh('cli-mix');
  app(home, 'brave', plist('157.1.99.55')); app(home, 'edge', plist('157.0.4341.42')); app(home, 'chrome', plist('156.0.8078.96')); app(home, 'vivaldi', plist('8.3.4191.35'));
  const t = cli(home);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.match(t.stdout, /^EXPOSED +Brave \(Mac app\) 1\.99\.55 +~\/Applications\/Brave Browser\.app\/Contents\/Info\.plist$/m);
  assert.match(t.stdout, /fix: Update Brave to 1\.99\.56 or later/);
  assert.match(t.stdout, /^REVIEW +Microsoft Edge \(Mac app\) 157\.0\.4341\.42 +~\/Applications\/Microsoft Edge\.app/m);
  assert.match(t.stdout, /check: Keep Edge updated/);
  assert.match(t.stdout, /^REVIEW +Google Chrome \(Mac app\) 156\.0\.8078\.96 /m);
  assert.match(t.stdout, /^REVIEW +Vivaldi \(Mac app\) 8\.3\.4191\.35 /m);
  assert.doesNotMatch(t.stdout, /^SAFE /m);
  const j = JSON.parse(cli(home, ['--json']).stdout);
  const by = Object.fromEntries(j.results.map((r) => [r.product ?? 'Google Chrome', r]));
  assert.deepEqual(Object.keys(by).sort(), ['Brave', 'Google Chrome', 'Microsoft Edge', 'Vivaldi']);
  assert.equal(by.Brave.status, 'EXPOSED'); assert.match(by.Brave.fix, /^Update Brave/);
  assert.equal(by['Microsoft Edge'].status, 'REVIEW'); assert.match(by['Microsoft Edge'].fix, /^Keep Edge updated/);
  assert.equal(by['Google Chrome'].status, 'REVIEW'); assert.equal(by['Google Chrome'].fix, INC.reviewFix);
  assert.equal(by.Vivaldi.fix, 'Restart Vivaldi, so the version that runs is the one installed.');
  // no row carries a reviewFix field of its own: it became the row's fix
  assert.ok(j.results.every((r) => !('reviewFix' in r)));
  // the clean twin: none of the four anywhere it reads is one receipted all-clear that names all four
  const none = cli(fresh('cli-none'), ['--json']);
  assert.equal(none.status, 0, none.stdout);
  const rows = JSON.parse(none.stdout).results;
  assert.equal(rows.length, 1); assert.equal(rows[0].status, 'SAFE');
  assert.match(rows[0].reason, /^no Google Chrome, Brave, Vivaldi or Microsoft Edge found/);
});
