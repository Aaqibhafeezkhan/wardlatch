// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: macos-2026-11. This Mac's macOS, read from SystemVersion.plist (no program run), against Apple's latest
// security release for its line (Apple's index, read 13 Nov 2026: 27.2.1, 26.7.3, 15.8.3 on 9 Nov; Sonoma's last 14.8.9
// on 6 Aug) and the fixes for the three Apple flaws in CISA's catalog: CVE-2026-86950 (26.7.1, 15.8.1; no Sonoma fix
// named), CVE-2026-65400 (27, 26.6.1, 15.7.9, 14.8.9) and CVE-2024-27834 (14.5). Below one of those fixes is EXPOSED;
// past them but below the line's latest is REVIEW; any Sonoma, and anything older, is REVIEW (Apple ships them nothing
// and does not say they are affected); at or past the latest is SAFE.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, realpathSync, utimesSync } from 'node:fs';
import { CLOCK_FILES } from '../lib/clock.mjs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { macosUpdateRow, productVersion, productBuild, isBetaBuild, isReleaseBuild, appleVersionLabel, appleFixState, appleSystemRow, SYSTEM_VERSION_PLIST } from '../lib/macos.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'macos-2026-11.json'), 'utf8'));
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-macos18-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
const plist = (v, build = '26B131') => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n${build === null ? '' : `  <key>ProductBuildVersion</key>\n  <string>${build}</string>\n`}  <key>ProductName</key>\n  <string>macOS</string>\n  <key>ProductVersion</key>\n  <string>${v}</string>\n</dict>\n</plist>\n`;
// a release build unless a test says otherwise (27.2.1's is 26B131)
// a fixed "today", three days after the list was read (13 Nov 2026), so these verdicts don't turn REVIEW as the real date
// passes the staleness limit (test/no-stale-safe.test.mjs holds that rule)
const FRESH = { today: { now: Date.parse('2026-11-16T12:00:00Z'), from: 'the test' } };
const at = (v, build = '26B131') => macosUpdateRow(INC, v, 'darwin', build, FRESH);

test('M1 the table is Apple\'s and the CVE records\': each line\'s latest release, each exploited flaw\'s fix, the frozen line', () => {
  const by = Object.fromEntries(INC.macosLines.map((l) => [l.major, l]));
  assert.deepEqual(INC.macosLines.map((l) => [l.major, l.latest, l.latestDate]), [[27, '27.2.1', '9 Nov 2026'], [26, '26.7.3', '9 Nov 2026'], [15, '15.8.3', '9 Nov 2026'], [14, '14.8.9', '6 Aug 2026']]);
  assert.deepEqual(by[26].kev, [{ cve: 'CVE-2026-86950', fixed: '26.7.1' }, { cve: 'CVE-2026-65400', fixed: '26.6.1' }]);
  assert.deepEqual(by[15].kev, [{ cve: 'CVE-2026-86950', fixed: '15.8.1' }, { cve: 'CVE-2026-65400', fixed: '15.7.9' }]);
  assert.deepEqual(by[14].kev, [{ cve: 'CVE-2024-27834', fixed: '14.5' }, { cve: 'CVE-2026-65400', fixed: '14.8.9' }]);
  assert.deepEqual(by[27].kev, [{ cve: 'CVE-2026-65400', fixed: '27.0' }]);
  assert.ok(by[14].frozen && !by[26].frozen && !by[15].frozen && !by[27].frozen);
  assert.equal(INC.advisory, 'https://support.apple.com/en-us/100100');
  // every CVE it judges on is one CISA lists (test/kev.test.mjs holds the rows to the catalog)
  assert.deepEqual(INC.kev.map((k) => k.cve).sort(), ['CVE-2024-27834', 'CVE-2026-65400', 'CVE-2026-86950']);
});

test('M2 every verdict, at and around each boundary', () => {
  const table = [
    ['27.2.1', 'SAFE'], ['27.3', 'SAFE'], ['27.2', 'REVIEW'], ['27.0', 'REVIEW'],
    ['26.7.3', 'SAFE'], ['26.7.2', 'REVIEW'], ['26.7.1', 'REVIEW'], ['26.7', 'EXPOSED'], ['26.7.0', 'EXPOSED'], ['26.6.1', 'EXPOSED'], ['26.5', 'EXPOSED'],
    ['15.8.3', 'SAFE'], ['15.8.2', 'REVIEW'], ['15.8.1', 'REVIEW'], ['15.8', 'EXPOSED'], ['15.8.0', 'EXPOSED'], ['15.7.9', 'EXPOSED'], ['15.0', 'EXPOSED'],
    ['14.8.9', 'REVIEW'], ['14.8.8', 'EXPOSED'], ['14.5', 'EXPOSED'], ['14.4', 'EXPOSED'],
    ['13.7', 'REVIEW'], ['12.7.6', 'REVIEW'], ['10.15.7', 'REVIEW'],
    ['28.0', 'SAFE'], ['16.0', 'UNKNOWN'], ['20.1', 'UNKNOWN'], ['', 'UNKNOWN'], ['garbage', 'UNKNOWN'],
  ];
  for (const [v, want] of table) assert.equal(at(v).status, want, `${v}: ${JSON.stringify(at(v))}`);
});

test('M3 what each line says: the CVE and its fix, the release to move to, Sonoma\'s frozen line, and a SAFE that names what it read', () => {
  const e = at('26.7.0');
  assert.equal(e.reason, `macOS 26.7.0 (build 26B131), read from ${SYSTEM_VERSION_PLIST}: lacks Apple's fix for CVE-2026-86950 (fixed in 26.7.1), which CISA lists as exploited`);
  assert.equal(e.fix, 'Update macOS to 26.7.3 or later: System Settings, General, Software Update.');
  assert.match(at('26.5').reason, /CVE-2026-86950 \(fixed in 26\.7\.1\) and CVE-2026-65400 \(fixed in 26\.6\.1\)/);
  assert.match(at('14.4').reason, /CVE-2024-27834 \(fixed in 14\.5\) and CVE-2026-65400 \(fixed in 14\.8\.9\)/);
  assert.match(at('14.4').fix, /^Apple ships no more updates for macOS Sonoma: update to 14\.8\.9, its last/);
  const r = at('26.7.1');
  assert.match(r.reason, /has the fixes for the flaws CISA lists as exploited, but not 26\.7\.3, Apple's latest security release for macOS Tahoe 26 \(9 Nov 2026\)/);
  const s = at('14.8.9');
  assert.match(s.reason, /Apple has published no security update for macOS Sonoma 14 since 14\.8\.9 on 6 Aug 2026/);
  assert.match(s.reason, /It does not say Sonoma is affected, so this is not judged EXPOSED/);
  assert.match(at('13.7').reason, /no fix for macOS 13 or older/);
  const ok = at('27.2.1');
  assert.deepEqual(ok.searched, [SYSTEM_VERSION_PLIST, 'version 27.2.1', 'build 26B131']);
  // off a Mac: nothing to check, said so, with the platform as its receipt
  const lin = macosUpdateRow(INC, '', 'linux');
  assert.equal(lin.status, 'SAFE'); assert.match(lin.reason, /^not a Mac \(linux\)/);
  // nothing claims exploitation for a CVE CISA doesn't list
  for (const v of ['27.2', '26.7.2', '14.8.9', '13.7']) assert.doesNotMatch(at(v).reason, /lacks/);
});

test('M4 each rule, removed, changes the answer: the KEV fixes, the latest release, the frozen line', () => {
  const lines = (f) => ({ ...INC, macosLines: INC.macosLines.map(f) });
  // without the KEV fixes, a Tahoe that lacks the exploited flaw's fix reads only REVIEW
  assert.equal(macosUpdateRow(lines((l) => ({ ...l, kev: [] })), '26.7.0', 'darwin', '25G100').status, 'REVIEW');
  // without the latest release (latest = the KEV fix), 26.7.1 reads SAFE
  assert.equal(macosUpdateRow(lines((l) => (l.major === 26 ? { ...l, latest: '26.7.1' } : l)), '26.7.1', 'darwin', '25H100', FRESH).status, 'SAFE');
  // without `frozen`, Sonoma's last release reads SAFE, the answer this check exists to refuse
  assert.equal(macosUpdateRow(lines(({ frozen, ...l }) => ({ ...l, latestSays: 'x' })), '14.8.9', 'darwin', '23J100', FRESH).status, 'SAFE');
  // as shipped
  assert.deepEqual(['26.7.0', '26.7.1', '14.8.9'].map((v) => at(v).status), ['EXPOSED', 'REVIEW', 'REVIEW']);
});

test('M4b a beta is never SAFE (an independent review\'s B2): 27.3 beta 1 (26C5035r, 3 Nov) is REVIEW, and so is a build that can\'t be read', () => {
  assert.ok(isBetaBuild('26C5035r') && isBetaBuild('25A5279m') && !isBetaBuild('26B131') && !isBetaBuild('') && !isBetaBuild('26C5035R'));
  const b = at('27.3', '26C5035r');
  assert.equal(b.status, 'REVIEW');
  assert.match(b.reason, /^macOS 27\.3 \(build 26C5035r\), read from .*: a beta\. Apple's security notes cover its releases, and whether this beta carries the fixes of 27\.2\.1 is not stated$/);
  assert.match(b.fix, /^Install the release/);
  assert.doesNotMatch(b.reason, /at or past/);
  // a beta of a newer major, and a version past the latest with no build key
  assert.equal(at('28.0', '27A5218g').status, 'REVIEW');
  assert.equal(at('27.3', '').status, 'REVIEW'); assert.match(at('27.3', '').reason, /its build could not be read/);
  assert.equal(macosUpdateRow(INC, '27.2.1', 'darwin').status, 'REVIEW', 'no build given is no build read');
  // a beta below a KEV fix is still EXPOSED; a release build of 27.2.1 is SAFE
  assert.equal(at('26.7', '25H5020a').status, 'EXPOSED');
  assert.equal(at('27.2.1', '26B131').status, 'SAFE');
  assert.equal(at('27.3', '26C70').status, 'SAFE', 'a release build of 27.3, when it comes, is past 27.2.1');
  // the control: judged without the build, as before this fix, 27.3 beta 1 read SAFE
  assert.equal(macosUpdateRow(INC, '27.3', 'darwin', '26C70', FRESH).status, 'SAFE');
});

test('M4c the older eMudhra and Brotli judgements (appleFixState): a beta is labelled with its build and can\'t be placed, so it is never "fixed"', () => {
  assert.equal(appleVersionLabel({ version: '27.3', build: '26C5035r' }), '27.3 (beta build 26C5035r)');
  assert.equal(appleVersionLabel({ version: '27.2.1', build: '26B131' }), '27.2.1');
  assert.equal(appleFixState('27.3', ['27.2.1', '26.7.3', '15.8.3']), 'fixed', 'the control: the bare number reads fixed');
  assert.equal(appleFixState(appleVersionLabel({ version: '27.3', build: '26C5035r' }), ['27.2.1', '26.7.3', '15.8.3']), 'unknown');
  const brotli = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'brotli-2026-10.json'), 'utf8'));
  const row = appleSystemRow(brotli, '27.3 (beta build 26C5035r)');
  assert.equal(row.status, 'UNKNOWN'); assert.match(row.reason, /is a beta: .*Apple's notes don't say whether a beta carries the fix$/);
  assert.equal(appleSystemRow(brotli, '27.3').status, 'SAFE', 'the control: by its number alone the beta read SAFE');
});

test('M4d a build Apple doesn\'t give a release fails closed to REVIEW (the re-review\'s R1), and a beta at a KEV fix\'s number gets the beta wording (R2)', () => {
  for (const b of ['26C5035R', '24J', 'A1', '26b131', '26B131x1', '26C 5035']) {
    assert.ok(!isReleaseBuild(b), b);
    const r = at('27.3', b);
    assert.equal(r.status, 'REVIEW', b);
    assert.doesNotMatch(r.reason, /at or past/, b);
    assert.match(appleVersionLabel({ version: '27.3', build: b }), /^27\.3 \((beta )?build /, b);
  }
  assert.ok(isReleaseBuild('26B131') && isReleaseBuild('25H100'));
  assert.match(at('27.3', '26C5035R').reason, /not in the form Apple gives a release/);
  // R2: a beta whose number is a KEV fix's is not told it "has the fixes"
  for (const [v, b] of [['27.0', '26A5288k'], ['26.7.1', '25H5001c']]) {
    const r = at(v, b);
    assert.equal(r.status, 'REVIEW', v); assert.match(r.reason, /: a beta\./, v); assert.doesNotMatch(r.reason, /has the fixes/, v);
  }
  // a release build there keeps its wording
  assert.match(at('26.7.1', '25H100').reason, /has the fixes for the flaws CISA lists as exploited/);
});

test('M5 the version is read from the plist\'s ProductVersion, as the command reads it', () => {
  assert.equal(productVersion(plist('26.7.1')), '26.7.1');
  assert.equal(productVersion(plist('26.7.1').replace('ProductVersion', 'ProductOther')), '');
  assert.equal(productBuild(plist('27.3', '26C5035r')), '26C5035r');
  assert.equal(productBuild(plist('27.3', null)), '');
});

// The command, on a Mac: SystemVersion.plist is this test's own (a preload maps the path), as in brotli-0.1.16's B4
const cli = (v, args = [], build, incidents = ['macos-2026-11'], NOW = FRESH.today.now) => {
  const f = join(fresh('plist'), 'SystemVersion.plist'); writeFileSync(f, v === null ? '<plist/>' : plist(v, build));
  // the run's "today" is pinned three days after the list was read (13 Nov 2026): the clock, the plist's time, and the
  // other files lib/clock.mjs reads, which are hidden, so the real date can't turn these SAFEs into REVIEWs
  utimesSync(f, NOW / 1000, NOW / 1000);
  const hide = CLOCK_FILES.darwin.filter((p) => p !== SYSTEM_VERSION_PLIST);
  const pre = join(fresh('pre'), 'map.cjs');
  writeFileSync(pre, `const fs = require('node:fs'); const P = ${JSON.stringify(SYSTEM_VERSION_PLIST)}, V = ${JSON.stringify(f)}, H = new Set(${JSON.stringify(hide)});
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'openSync', 'existsSync']) { const o = fs[k]; fs[k] = (p, ...a) => o(String(p) === P ? V : H.has(String(p)) ? V + '.hidden' : p, ...a); }
Date.now = () => ${NOW};
require('node:module').syncBuiltinESMExports();\n`);
  const { NODE_OPTIONS, ...rest } = process.env;
  return spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), '--require', pre, BIN, ...incidents.flatMap((i) => ['--incident', i]), ...args], { encoding: 'utf8', env: { ...rest, HOME: fresh('home'), PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
};

test('M6 the command on a Mac: EXPOSED exit 1 with the CISA lines and the fix, REVIEW exit 0, SAFE exit 0, unread exit 2', { skip: process.platform !== 'darwin' && 'macOS only: the version is read on a Mac' }, () => {
  const e = cli('26.7.0');
  assert.equal(e.status, 1, e.stdout + e.stderr);
  assert.match(e.stdout, /^EXPOSED +macOS 26\.7\.0 +\/System\/Library\/CoreServices\/SystemVersion\.plist$/m);
  assert.match(e.stdout, /^CISA KEV: Apple Multiple Products CVE-2026-86950 is known to be exploited · added 29 Sep 2026/m);
  assert.match(e.stdout, /fix: Update macOS to 26\.7\.3 or later/);
  const j = JSON.parse(cli('26.7.0', ['--json']).stdout);
  assert.deepEqual(j.results.map((x) => [x.kind, x.status, x.version]), [['macos', 'EXPOSED', '26.7.0']]);
  assert.deepEqual(j.incidents[0].kev.map((k) => k.cve), ['CVE-2024-27834', 'CVE-2026-65400', 'CVE-2026-86950']);
  const r = cli('14.8.9');
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^REVIEW +macOS 14\.8\.9 /m); assert.match(r.stdout, /check: Apple ships no more updates for macOS Sonoma/);
  const beta = cli('27.3', ['--json'], '26C5035r');
  assert.equal(beta.status, 0, beta.stdout); assert.deepEqual(JSON.parse(beta.stdout).results.map((x) => [x.status, x.build]), [['REVIEW', '26C5035r']]);
  const s = cli('27.2.1', ['--json']);
  assert.equal(s.status, 0); assert.deepEqual(JSON.parse(s.stdout).results.map((x) => x.status), ['SAFE']);
  // fix/no-stale-safe: the same Mac 31 days after the list was read is REVIEW, through the command, with the reason
  const old = cli('27.2.1', [], undefined, undefined, Date.parse('2026-12-14T12:00:00Z'));
  assert.equal(old.status, 0, old.stdout); assert.match(old.stdout, /^REVIEW +macOS 27\.2\.1 /m);
  assert.match(old.stdout, /Wardlatch's list of Apple releases is 31 days old/); assert.match(old.stdout, /check: Open System Settings, General, Software Update/);
  // a build Apple doesn't give a release, through the command
  const odd = cli('27.3', ['--json'], '26C5035R');
  assert.deepEqual(JSON.parse(odd.stdout).results.map((x) => x.status), ['REVIEW']);
  const u = cli(null);
  assert.equal(u.status, 2, u.stdout); assert.match(u.stdout, /^UNKNOWN +macOS +\/System/m);
});

// The re-review's N17: the command must hand the Brotli check the beta's label, not its bare number. Reverted, macOS's
// own Brotli row on 27.3 beta 1 reads SAFE "fixed" by its number. One run, both incidents, a beta plist, and its twin
// with a release build as the control that the test can tell the two apart.
const VM_VARS = ['VOLTA_HOME', 'MISE_DATA_DIR', 'MISE_INSTALLS_DIR', 'MISE_SYSTEM_DATA_DIR', 'MISE_SYSTEM_INSTALLS_DIR', 'MISE_SHARED_INSTALL_DIRS', 'XDG_DATA_HOME', 'RTX_DATA_DIR', 'PROTO_HOME', 'ASDF_DATA_DIR', 'NODENV_ROOT'];
test('M7 the command on a beta: macOS\'s own Brotli row is UNKNOWN and the macOS row REVIEW; on a release build both are SAFE', { skip: process.platform !== 'darwin' && 'macOS only: the version is read on a Mac' }, () => {
  const both = (build) => {
    const saved = Object.fromEntries(VM_VARS.map((k) => [k, process.env[k]]));
    for (const k of VM_VARS) process.env[k] = '';
    try { return cli('27.3', ['--json', '--paths', fresh('root')], build, ['brotli-2026-10', 'macos-2026-11']); } finally { for (const k of VM_VARS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } }
  };
  const rows = (r) => { const j = JSON.parse(r.stdout); return { brotli: j.results.find((x) => x.incident === 'brotli-2026-10' && x.what === 'macOS'), macos: j.results.find((x) => x.incident === 'macos-2026-11') }; };
  const beta = rows(both('26C5035r'));
  assert.equal(beta.brotli?.status, 'UNKNOWN', JSON.stringify(beta.brotli));
  assert.match(beta.brotli.reason, /27\.3 \(beta build 26C5035r\).*is a beta/);
  assert.equal(beta.macos.status, 'REVIEW'); assert.match(beta.macos.reason, /: a beta\./);
  // the control: a release build of the same number is SAFE in both, so the beta's rows are the beta's doing
  const rel = rows(both('26C70'));
  assert.deepEqual([rel.brotli?.status, rel.macos.status], ['SAFE', 'SAFE']);
});
