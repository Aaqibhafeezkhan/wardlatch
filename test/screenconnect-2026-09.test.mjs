// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// ConnectWise ScreenConnect, CVE-2026-84869 (screenconnect-2026-09). ConnectWise's bulletin and CVE record of 8 Sep 2026:
// the ScreenConnect CLIENT before 26.6.5 can let files be transferred and run in a remote session without the host's
// confirmation; servers are not affected; the fix is 26.6.5, and clients must be reinstalled or updated. CISA lists it
// (added 11 Sep 2026, due 14 Sep). PR #37's coverage list declined it as a "self-hosted server": the flaw runs on the
// client, which is software on the machine Wardlatch checks. The check reads the Info.plist of the apps; it never starts
// one. No ScreenConnect was installed on the Mac this was written on: the bundles here are written to Apple's format.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVersionFiles } from '../lib/installs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'screenconnect-2026-09.json'), 'utf8'));
const DECLINED = JSON.parse(readFileSync(join(ROOT, 'scripts', 'coverage', 'declined.json'), 'utf8'));
// the system-wide places only: ~/Applications is read through HOME, in the command's test below
const RULE = { ...INC.versionFiles, files: INC.versionFiles.files.filter((f) => !f.path.startsWith('~')) };
const ROGUE = '7a4d7d66502d4260';
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-screenconnect-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
// the build number (CFBundleVersion) beside the version, so the pattern has to find the right key
const plist = (v) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>CFBundleIdentifier</key>\n\t<string>com.screenconnect.client</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string>${v}</string>\n\t<key>CFBundleVersion</key>\n\t<string>9445</string>\n</dict>\n</plist>\n`;
const bundle = (root, rel, text) => { const f = join(root, rel, 'Contents', 'Info.plist'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return f; };
const HOST = 'Applications/ScreenConnect Client (0123456789abcdef).app';
const AGENT = 'opt/connectwisecontrol-0123456789abcdef.app';
const judge = (root) => checkVersionFiles(RULE, { root });

test('SC1 the facts are the sources\': the client, not the server; 26.6.5; KEV 11 Sep 2026; and "exploited" only from that row', () => {
  assert.equal(INC.advisory, 'https://www.connectwise.com/company/trust/security-bulletins/2026-09-08-screenconnect-bulletin');
  assert.deepEqual(INC.kev, [{ cve: 'CVE-2026-84869', vendorProject: 'ConnectWise', product: 'ScreenConnect', dateAdded: '2026-09-11', dueDate: '2026-09-14' }]);
  assert.equal(INC.versionFiles.minVersion, '26.6.5');
  assert.match(INC.summary, /says ScreenConnect servers are not affected\. So upgrading a server does not fix a client/);
  assert.match(INC.versionFiles.fix, /upgrading the server alone does not fix this machine/);
  assert.ok(INC.sources.some((s) => { const u = new URL(s); return u.protocol === 'https:' && u.host === 'www.huntress.com' && u.pathname === '/blog/rogue-screenconnect-installations'; }));
  // the Windows indicators are listed as not checked, by name
  for (const n of ['1.vbs', 'WindowsServiceHost.vbs', 'runner.ps1', 'svcdrv64.sys', 'Run key']) assert.ok(INC.notCovered.includes(n), n);
  // no longer declined: it is named, and the coverage check would call a decline of it stale
  assert.equal(DECLINED.entries.find((e) => e.key === 'CVE-2026-84869'), undefined);
});

test('SC2 the host client and the access agent: below 26.6.5 EXPOSED, at or past it REVIEW (no real bundle read yet), never SAFE', () => {
  for (const rel of [HOST, 'Applications/ConnectWise Control Client.app', AGENT, 'Applications/connectwisecontrol-0123456789abcdef.app']) {
    for (const [v, want] of [['26.6.4', 'EXPOSED'], ['25.2.4', 'EXPOSED'], ['19.0', 'EXPOSED'], ['26.6.4.9440', 'EXPOSED'], ['26.6.5', 'REVIEW'], ['26.6.5.9445', 'REVIEW'], ['27.1', 'REVIEW']]) {
      const root = fresh('v'); bundle(root, rel, plist(v));
      const rows = judge(root);
      assert.deepEqual(rows.map((r) => [r.status, r.version]), [[want, v]], `${rel} ${v}: ${JSON.stringify(rows)}`);
      if (want === 'REVIEW') assert.match(rows[0].reason, /no real ScreenConnect bundle has been read by this check yet/);
    }
  }
});

test('SC3 unreadable is UNKNOWN: no key, a version not in ScreenConnect\'s form, a file that can\'t be opened, a Linux agent folder', () => {
  const ok = fresh('ok'); bundle(ok, HOST, plist('26.6.4'));
  assert.equal(judge(ok)[0].status, 'EXPOSED', 'the control');
  const nokey = fresh('nokey'); bundle(nokey, HOST, plist('26.6.4').replace('CFBundleShortVersionString', 'CFBundleOther'));
  assert.deepEqual(judge(nokey).map((r) => r.status), ['UNKNOWN']);
  // "1.0" is not a ScreenConnect version: not read as one (it would be a false EXPOSED; 99.0 a false REVIEW)
  for (const v of ['1.0', '99.0', '6.4']) { const r = fresh('form'); bundle(r, HOST, plist(v)); assert.deepEqual(judge(r).map((x) => x.status), ['UNKNOWN'], v); }
  const locked = fresh('locked'); chmodSync(bundle(locked, HOST, plist('26.6.5')), 0);
  assert.deepEqual(judge(locked).map((r) => r.status), ['UNKNOWN']);
  const linux = fresh('linux'); mkdirSync(join(linux, 'opt', 'screenconnect-0123456789abcdef'), { recursive: true });
  assert.deepEqual(judge(linux).map((r) => [r.status, r.reason]), [['UNKNOWN', INC.versionFiles.files.at(-1).whenFound.reason]]);
  // not installed: nothing here (the command's all-clear names where it looked)
  assert.deepEqual(judge(fresh('none')), []);
});

test('SC4 Huntress\'s attacker instance, by name: an agent app or folder named for it is EXPOSED, whatever its version', () => {
  for (const rel of [`Applications/connectwisecontrol-${ROGUE}.app`, `opt/connectwisecontrol-${ROGUE}.app`]) {
    const root = fresh('rogue'); bundle(root, rel, plist('26.6.5'));
    const rows = judge(root);
    assert.ok(rows.some((r) => r.status === 'EXPOSED' && /Huntress's report names as the attacker's/.test(r.reason)), `${rel}: ${JSON.stringify(rows)}`);
  }
  const folder = fresh('rogue-dir'); mkdirSync(join(folder, 'opt', `screenconnect-${ROGUE}`), { recursive: true });
  assert.deepEqual(judge(folder).map((r) => r.status), ['EXPOSED'], 'one row: the generic agent-folder rule does not add an UNKNOWN for the same folder');
  // the control: another instance's agent at a fixed version is no indicator
  const other = fresh('other'); bundle(other, AGENT, plist('26.6.5'));
  assert.ok(judge(other).every((r) => r.status !== 'EXPOSED'));
});

const cli = (home, args = []) => {
  const { NODE_OPTIONS, ...rest } = process.env;
  return spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'screenconnect-2026-09', ...args], { encoding: 'utf8', env: { ...rest, HOME: home, PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
};
test('SC5 the command: an old host client in ~/Applications is EXPOSED, exit 1, with CISA\'s line and the client fix; none installed is the safe line only', () => {
  const home = fresh('cli'); bundle(home, 'Applications/ScreenConnect Client (0123456789abcdef).app', plist('26.6.4'));
  const t = cli(home);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.match(t.stdout, /^EXPOSED +ScreenConnect \(host client\) 26\.6\.4 +~\/Applications\/ScreenConnect Client \(0123456789abcdef\)\.app\/Contents\/Info\.plist$/m);
  assert.match(t.stdout, /^CISA KEV: ConnectWise ScreenConnect CVE-2026-84869 is known to be exploited · added 11 Sep 2026/m);
  assert.match(t.stdout, /fix: Update ScreenConnect on this machine to 26\.6\.5 or later/);
  const none = cli(fresh('cli-none'), ['--json']);
  assert.equal(none.status, 0, none.stdout + none.stderr);
  const rows = JSON.parse(none.stdout).results;
  assert.deepEqual(rows.map((r) => r.status), ['SAFE']); assert.match(rows[0].reason, /^no ScreenConnect client found in the places this check reads/);
});
